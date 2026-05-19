import os,sys,io
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
def current_user(request):
    c=request.cookies.get('ivpn_session')
    if not c: return None
    try: return serializer.loads(c).get('username')
    except BadSignature: return None
def require_login(request): return RedirectResponse('/login',302) if not current_user(request) else None
def protocol_rows(): con=connect(); rows=con.execute('SELECT * FROM protocols ORDER BY id').fetchall(); con.close(); return [dict(r) for r in rows]
@app.on_event('startup')
def startup(): init_db()
@app.get('/login')
def login_page(request:Request): return templates.TemplateResponse('login.html',{'request':request,'error':''})
@app.post('/login')
def login(request:Request,username:str=Form(...),password:str=Form(...)):
    ok=verify_admin(username,password); ip=request.client.host if request.client else ''; con=connect(); con.execute('INSERT INTO login_logs(username,ip,success,message,created_at) VALUES (?,?,?,?,?)',(username,ip,1 if ok else 0,'login',datetime.now().strftime('%Y-%m-%d %H:%M:%S'))); con.commit(); con.close()
    if not ok: return templates.TemplateResponse('login.html',{'request':request,'error':'账号或密码错误'})
    resp=RedirectResponse('/',302); resp.set_cookie('ivpn_session',serializer.dumps({'username':username}),httponly=True,samesite='lax'); return resp
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
    protocols=protocol_rows(); return templates.TemplateResponse('dashboard.html',{'request':request,'active':'home','stats':system_ops.system_stats(),'net':system_ops.network_stats(),'protocols':protocols,'installed':[p for p in protocols if p['installed']],'singbox_version':system_ops.singbox_version(),'open_ports':system_ops.list_open_ports()})
@app.get('/protocols')
def protocols_page(request:Request):
    auth=require_login(request)
    if auth: return auth
    protocols=protocol_rows(); links={p['protocol_key']:protocol_installer.protocol_links(p['protocol_key']) if p['installed'] else [] for p in protocols}
    return templates.TemplateResponse('protocols.html',{'request':request,'active':'protocols','protocols':protocols,'links':links,'singbox_version':system_ops.singbox_version(),'service_status':system_ops.service_status})
@app.post('/protocols/{protocol_key}/{action}')
def protocol_action(request:Request,protocol_key:str,action:str):
    auth=require_login(request)
    if auth: return auth
    con=connect(); p=con.execute('SELECT * FROM protocols WHERE protocol_key=?',(protocol_key,)).fetchone(); con.close()
    if not p: return RedirectResponse('/protocols',302)
    try:
        if action=='install': protocol_installer.install_protocol(protocol_key)
        elif action in ('start','stop','restart'):
            code,out,err=system_ops.run_cmd(['systemctl',action,p['service_name']],20); log_action(action,p['service_name'],'ok' if code==0 else 'error',out or err)
    except Exception as e: log_action(action,protocol_key,'error',str(e))
    return RedirectResponse('/protocols',302)
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
    con=connect(); users=con.execute('SELECT * FROM users ORDER BY id DESC').fetchall(); protocols=con.execute('SELECT * FROM protocols ORDER BY id').fetchall(); con.close(); return templates.TemplateResponse('users.html',{'request':request,'active':'users','users':users,'protocols':protocols})
@app.post('/users/add')
def users_add(request:Request,username:str=Form(...),protocol_key:str=Form(...)):
    auth=require_login(request)
    if auth: return auth
    try: protocol_installer.add_user_to_protocol(protocol_key,username); log_action('add user',f'{protocol_key}:{username}')
    except Exception as e: log_action('add user',f'{protocol_key}:{username}','error',str(e))
    return RedirectResponse('/users',302)
@app.post('/users/{user_id}/delete')
def users_delete(request:Request,user_id:int):
    auth=require_login(request)
    if auth: return auth
    con=connect(); u=con.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone(); con.close()
    if u:
        try: protocol_installer.delete_user_from_protocol(u['protocol_key'],u['username']); log_action('delete user',f"{u['protocol_key']}:{u['username']}")
        except Exception as e: log_action('delete user',str(user_id),'error',str(e))
    return RedirectResponse('/users',302)
@app.get('/firewall')
def firewall_page(request:Request):
    auth=require_login(request)
    if auth: return auth
    return templates.TemplateResponse('firewall.html',{'request':request,'active':'firewall','ports':system_ops.list_open_ports(),'protocols':protocol_rows(),'panel_port':system_ops.panel_port()})
@app.post('/firewall/open')
def firewall_open(request:Request,port:int=Form(...),proto:str=Form(...)):
    auth=require_login(request)
    if auth: return auth
    ok,msg=system_ops.open_port(port,proto); log_action('open firewall',f'{port}/{proto}','ok' if ok else 'error',msg); return RedirectResponse('/firewall',302)
@app.post('/firewall/close')
def firewall_close(request:Request,port:int=Form(...),proto:str=Form(...)):
    auth=require_login(request)
    if auth: return auth
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
    return templates.TemplateResponse('settings.html',{'request':request,'active':'settings','panel_port':system_ops.panel_port()})
@app.post('/settings/password')
def change_password(request:Request,username:str=Form(...),password:str=Form(...)):
    auth=require_login(request)
    if auth: return auth
    create_admin(username,password); return RedirectResponse('/settings',302)
if __name__=='__main__':
    if len(sys.argv)==4 and sys.argv[1]=='--init-admin': create_admin(sys.argv[2],sys.argv[3]); print('admin initialized')
