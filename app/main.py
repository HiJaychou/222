import os,sys,io,time,secrets,hmac,re
from urllib.parse import quote
from pathlib import Path
from datetime import datetime
from fastapi import FastAPI,Request,Form
from fastapi.responses import RedirectResponse,JSONResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeSerializer,BadSignature
import qrcode
from .db import init_db,create_admin,verify_admin,connect,log_action
from . import system_ops,protocol_installer
BASE_DIR=Path(__file__).resolve().parent
SECRET_FILE=Path('/etc/freedom-vpn/web/session.secret'); SECRET_FILE.parent.mkdir(parents=True,exist_ok=True)
if not SECRET_FILE.exists(): SECRET_FILE.write_text(os.urandom(32).hex())
serializer=URLSafeSerializer(SECRET_FILE.read_text().strip(),salt='iwantrun-vpn-web')
app=FastAPI(title='iwantrun VPN Web Manager'); templates=Jinja2Templates(directory=str(BASE_DIR/'templates')); app.mount('/static',StaticFiles(directory=str(BASE_DIR/'static')),name='static')
SESSION_MAX_AGE=86400
LOGIN_WINDOW=600
LOGIN_MAX_FAILURES=8
_login_failures={}
USERNAME_RE=re.compile(r'^[A-Za-z0-9_]{1,32}$')
def current_session(request):
    c=request.cookies.get('ivpn_session')
    if not c: return None
    try: data=serializer.loads(c)
    except BadSignature: return None
    if int(time.time())-int(data.get('iat',0))>SESSION_MAX_AGE: return None
    return data
def current_user(request):
    data=current_session(request)
    return data.get('username') if data else None
def require_login(request): return RedirectResponse('/login',302) if not current_user(request) else None
def csrf_token(request):
    data=current_session(request) or {}
    return data.get('csrf','')
def csrf_ok(request,token):
    expected=csrf_token(request)
    return bool(expected and token and hmac.compare_digest(expected,token))
def csrf_redirect(request,token,path='/'):
    return None if csrf_ok(request,token) else RedirectResponse(path,302)
def login_blocked(ip):
    now=time.time()
    failures=[t for t in _login_failures.get(ip,[]) if now-t<LOGIN_WINDOW]
    _login_failures[ip]=failures
    return len(failures)>=LOGIN_MAX_FAILURES
def record_login_failure(ip):
    now=time.time()
    failures=[t for t in _login_failures.get(ip,[]) if now-t<LOGIN_WINDOW]
    failures.append(now)
    _login_failures[ip]=failures
def clear_login_failures(ip): _login_failures.pop(ip,None)
def protocol_rows(): con=connect(); rows=con.execute('SELECT * FROM protocols ORDER BY id').fetchall(); con.close(); return [dict(r) for r in rows]
def redirect_with_message(path,msg='',error=''):
    params=[]
    if msg: params.append('msg='+quote(msg))
    if error: params.append('error='+quote(error))
    return RedirectResponse(path+('?'+'&'.join(params) if params else ''),302)
@app.on_event('startup')
def startup(): init_db()
@app.get('/login')
def login_page(request:Request): return templates.TemplateResponse('login.html',{'request':request,'error':''})
@app.post('/login')
def login(request:Request,username:str=Form(...),password:str=Form(...)):
    ip=request.client.host if request.client else ''
    if login_blocked(ip):
        return templates.TemplateResponse('login.html',{'request':request,'error':'登录失败次数过多，请 10 分钟后再试'})
    ok=verify_admin(username,password); con=connect(); con.execute('INSERT INTO login_logs(username,ip,success,message,created_at) VALUES (?,?,?,?,?)',(username,ip,1 if ok else 0,'login',datetime.now().strftime('%Y-%m-%d %H:%M:%S'))); con.commit(); con.close()
    if not ok:
        record_login_failure(ip)
        return templates.TemplateResponse('login.html',{'request':request,'error':'账号或密码错误'})
    clear_login_failures(ip)
    resp=RedirectResponse('/',302); resp.set_cookie('ivpn_session',serializer.dumps({'username':username,'csrf':secrets.token_urlsafe(32),'iat':int(time.time())}),httponly=True,samesite='lax',max_age=SESSION_MAX_AGE,secure=request.url.scheme=='https'); return resp
@app.get('/logout')
def logout(): resp=RedirectResponse('/login',302); resp.delete_cookie('ivpn_session'); return resp
@app.get('/api/dashboard')
def api_dashboard(request:Request):
    if not current_user(request): return JSONResponse({'error':'unauthorized'},401)
    return {'stats':system_ops.system_stats(),'net':system_ops.network_stats(),'singbox_version':system_ops.singbox_version(),'open_ports':system_ops.list_open_ports(),'protocols':[{**p,'runtime_status':system_ops.service_status(p['service_name'])} for p in protocol_rows()]}
@app.get('/')
def dashboard(request:Request):
    auth=require_login(request)
    if auth: return auth
    protocols=protocol_rows(); return templates.TemplateResponse('dashboard.html',{'request':request,'active':'home','csrf_token':csrf_token(request),'stats':system_ops.system_stats(),'net':system_ops.network_stats(),'protocols':protocols,'installed':[p for p in protocols if p['installed']],'singbox_version':system_ops.singbox_version(),'open_ports':system_ops.list_open_ports()})
@app.get('/protocols')
def protocols_page(request:Request):
    auth=require_login(request)
    if auth: return auth
    protocols=protocol_rows(); links={p['protocol_key']:protocol_installer.protocol_links(p['protocol_key']) if p['installed'] else [] for p in protocols}
    status={p['protocol_key']:system_ops.service_status(p['service_name']) for p in protocols}
    return templates.TemplateResponse('protocols.html',{'request':request,'active':'protocols','csrf_token':csrf_token(request),'protocols':protocols,'links':links,'status':status,'msg':request.query_params.get('msg',''),'error':request.query_params.get('error',''),'singbox_version':system_ops.singbox_version(),'service_status':system_ops.service_status})
@app.post('/protocols/{protocol_key}/{action}')
def protocol_action(request:Request,protocol_key:str,action:str,csrf_token_value:str=Form(...,alias='csrf_token'),username:str=Form('',alias='username'),password:str=Form('',alias='password')):
    auth=require_login(request)
    if auth: return auth
    bad_csrf=csrf_redirect(request,csrf_token_value,'/protocols')
    if bad_csrf: return bad_csrf
    con=connect(); p=con.execute('SELECT * FROM protocols WHERE protocol_key=?',(protocol_key,)).fetchone(); con.close()
    if not p: return redirect_with_message('/protocols',error='协议不存在')
    try:
        if action=='install':
            protocol_installer.install_protocol(protocol_key,username,password)
            return redirect_with_message('/protocols',msg=f"{p['protocol_name']} 安装成功，已生成用户 {username}")
        elif action=='toggle':
            current=system_ops.service_status(p['service_name'])
            cmd='stop' if current=='运行中' else 'start'
            code,out,err=system_ops.run_cmd(['systemctl',cmd,p['service_name']],20)
            ok=code==0
            log_action(cmd,p['service_name'],'ok' if ok else 'error',out or err)
            if not ok: return redirect_with_message('/protocols',error=f"{p['protocol_name']} {'关闭' if cmd=='stop' else '开启'}失败：{err or out}")
            return redirect_with_message('/protocols',msg=f"{p['protocol_name']} 已{'关闭' if cmd=='stop' else '开启'}")
        elif action=='restart':
            code,out,err=system_ops.run_cmd(['systemctl','restart',p['service_name']],20)
            ok=code==0
            log_action(action,p['service_name'],'ok' if ok else 'error',out or err)
            if not ok: return redirect_with_message('/protocols',error=f"{p['protocol_name']} 重启失败：{err or out}")
            return redirect_with_message('/protocols',msg=f"{p['protocol_name']} 重启成功")
    except Exception as e:
        log_action(action,protocol_key,'error',str(e))
        return redirect_with_message('/protocols',error=f"{p['protocol_name']} 操作失败：{e}")
    return redirect_with_message('/protocols',error='未知操作')
@app.get('/protocols/{protocol_key}/qr/{username}')
def qr(request:Request,protocol_key:str,username:str):
    auth=require_login(request)
    if auth: return auth
    for item in protocol_installer.protocol_links(protocol_key):
        if item['name']==username:
            img=qrcode.make(item['link']); buf=io.BytesIO(); img.save(buf,format='PNG'); buf.seek(0); return StreamingResponse(buf,media_type='image/png')
    return JSONResponse({'error':'not found'},404)
@app.get('/users')
def users_page(request:Request):
    auth=require_login(request)
    if auth: return auth
    con=connect(); users=con.execute('SELECT * FROM users ORDER BY id DESC').fetchall(); protocols=con.execute('SELECT * FROM protocols ORDER BY id').fetchall(); con.close(); return templates.TemplateResponse('users.html',{'request':request,'active':'users','csrf_token':csrf_token(request),'users':users,'protocols':protocols})
@app.post('/users/add')
def users_add(request:Request,username:str=Form(...),protocol_key:str=Form(...),password:str=Form('',alias='password'),csrf_token_value:str=Form(...,alias='csrf_token')):
    auth=require_login(request)
    if auth: return auth
    bad_csrf=csrf_redirect(request,csrf_token_value,'/users')
    if bad_csrf: return bad_csrf
    if not USERNAME_RE.match(username):
        log_action('add user',f'{protocol_key}:{username}','error','invalid username')
        return RedirectResponse('/users',302)
    try: protocol_installer.add_user_to_protocol(protocol_key,username,password); log_action('add user',f'{protocol_key}:{username}')
    except Exception as e: log_action('add user',f'{protocol_key}:{username}','error',str(e))
    return RedirectResponse('/users',302)
@app.post('/users/{user_id}/delete')
def users_delete(request:Request,user_id:int,csrf_token_value:str=Form(...,alias='csrf_token')):
    auth=require_login(request)
    if auth: return auth
    bad_csrf=csrf_redirect(request,csrf_token_value,'/users')
    if bad_csrf: return bad_csrf
    con=connect(); u=con.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone(); con.close()
    if u:
        try: protocol_installer.delete_user_from_protocol(u['protocol_key'],u['username']); log_action('delete user',f"{u['protocol_key']}:{u['username']}")
        except Exception as e: log_action('delete user',str(user_id),'error',str(e))
    return RedirectResponse('/users',302)
@app.get('/firewall')
def firewall_page(request:Request):
    auth=require_login(request)
    if auth: return auth
    return templates.TemplateResponse('firewall.html',{'request':request,'active':'firewall','csrf_token':csrf_token(request),'ports':system_ops.list_open_ports(),'protocols':protocol_rows(),'panel_port':system_ops.panel_port()})
@app.post('/firewall/open')
def firewall_open(request:Request,port:int=Form(...),proto:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token')):
    auth=require_login(request)
    if auth: return auth
    bad_csrf=csrf_redirect(request,csrf_token_value,'/firewall')
    if bad_csrf: return bad_csrf
    ok,msg=system_ops.open_port(port,proto); log_action('open firewall',f'{port}/{proto}','ok' if ok else 'error',msg); return RedirectResponse('/firewall',302)
@app.post('/firewall/close')
def firewall_close(request:Request,port:int=Form(...),proto:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token')):
    auth=require_login(request)
    if auth: return auth
    bad_csrf=csrf_redirect(request,csrf_token_value,'/firewall')
    if bad_csrf: return bad_csrf
    ok,msg=system_ops.close_port(port,proto,system_ops.panel_port()); log_action('close firewall',f'{port}/{proto}','ok' if ok else 'error',msg); return RedirectResponse('/firewall',302)
@app.get('/logs')
def logs_page(request:Request,kind:str='singbox'):
    auth=require_login(request)
    if auth: return auth
    protocols=protocol_rows()
    if kind=='system': content=system_ops.journal(None,200); title='系统日志'
    elif kind=='diagnostic': content=system_ops.diagnostic(protocols); title='完整诊断信息'
    else: content='\n\n'.join([f"===== {p['protocol_name']} / {p['service_name']} =====\n"+system_ops.journal(p['service_name'],120) for p in protocols]); title='sing-box 日志'
    return templates.TemplateResponse('logs.html',{'request':request,'active':'logs','title':title,'content':content})
@app.get('/settings')
def settings_page(request:Request):
    auth=require_login(request)
    if auth: return auth
    return templates.TemplateResponse('settings.html',{'request':request,'active':'settings','csrf_token':csrf_token(request),'panel_port':system_ops.panel_port()})
@app.post('/settings/password')
def change_password(request:Request,username:str=Form(...),password:str=Form(...),csrf_token_value:str=Form(...,alias='csrf_token')):
    auth=require_login(request)
    if auth: return auth
    bad_csrf=csrf_redirect(request,csrf_token_value,'/settings')
    if bad_csrf: return bad_csrf
    create_admin(username,password); return RedirectResponse('/settings',302)
if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--init-admin': create_admin(sys.argv[2],sys.argv[3]); print('admin initialized')
