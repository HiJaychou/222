import os
import sys
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, Request, Form, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeSerializer, BadSignature

from .db import init_db, create_admin, verify_admin, connect, log_action
from . import system_ops

BASE_DIR = Path(__file__).resolve().parent
SECRET_FILE = Path('/etc/freedom-vpn/web/session.secret')
SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(os.urandom(32).hex())
serializer = URLSafeSerializer(SECRET_FILE.read_text().strip(), salt='iwantrun-vpn-web')

app = FastAPI(title='iwantrun VPN Web Manager')
templates = Jinja2Templates(directory=str(BASE_DIR / 'templates'))
app.mount('/static', StaticFiles(directory=str(BASE_DIR / 'static')), name='static')

def current_user(request: Request):
    cookie = request.cookies.get('ivpn_session')
    if not cookie:
        return None
    try:
        data = serializer.loads(cookie)
        return data.get('username')
    except BadSignature:
        return None

def require_login(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse('/login', status_code=302)
    return None

def protocol_rows():
    con = connect()
    rows = con.execute('SELECT * FROM protocols ORDER BY id').fetchall()
    con.close()
    return [dict(r) for r in rows]

@app.on_event('startup')
def startup():
    init_db()

@app.get('/login')
def login_page(request: Request):
    return templates.TemplateResponse('login.html', {'request': request, 'error': ''})

@app.post('/login')
def login(request: Request, response: Response, username: str = Form(...), password: str = Form(...)):
    ip = request.client.host if request.client else ''
    ok = verify_admin(username, password)
    con = connect()
    con.execute('INSERT INTO login_logs(username, ip, success, message, created_at) VALUES (?, ?, ?, ?, ?)', (username, ip, 1 if ok else 0, 'login', datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    con.commit(); con.close()
    if not ok:
        return templates.TemplateResponse('login.html', {'request': request, 'error': '账号或密码错误'})
    resp = RedirectResponse('/', status_code=302)
    resp.set_cookie('ivpn_session', serializer.dumps({'username': username}), httponly=True, samesite='lax')
    return resp

@app.get('/logout')
def logout():
    resp = RedirectResponse('/login', status_code=302)
    resp.delete_cookie('ivpn_session')
    return resp

@app.get('/')
def dashboard(request: Request):
    auth = require_login(request)
    if auth: return auth
    stats = system_ops.system_stats()
    net = system_ops.network_stats()
    protocols = protocol_rows()
    installed = [p for p in protocols if p['installed']]
    return templates.TemplateResponse('dashboard.html', {'request': request, 'active': 'home', 'stats': stats, 'net': net, 'protocols': protocols, 'installed': installed, 'singbox_version': system_ops.singbox_version(), 'open_ports': system_ops.list_open_ports()})

@app.get('/protocols')
def protocols_page(request: Request):
    auth = require_login(request)
    if auth: return auth
    return templates.TemplateResponse('protocols.html', {'request': request, 'active': 'protocols', 'protocols': protocol_rows(), 'singbox_version': system_ops.singbox_version()})

@app.post('/protocols/{protocol_key}/{action}')
def protocol_action(request: Request, protocol_key: str, action: str):
    auth = require_login(request)
    if auth: return auth
    con = connect(); p = con.execute('SELECT * FROM protocols WHERE protocol_key=?', (protocol_key,)).fetchone(); con.close()
    if not p: return RedirectResponse('/protocols', status_code=302)
    service = p['service_name']
    if action in ('start', 'stop', 'restart'):
        cmd = {'start':'start','stop':'stop','restart':'restart'}[action]
        code, out, err = system_ops.run_cmd(['systemctl', cmd, service], timeout=20)
        log_action(f'{cmd} service', service, 'ok' if code == 0 else 'error', out or err)
    return RedirectResponse('/protocols', status_code=302)

@app.get('/users')
def users_page(request: Request):
    auth = require_login(request)
    if auth: return auth
    con = connect(); users = con.execute('SELECT * FROM users ORDER BY id DESC').fetchall(); protocols = con.execute('SELECT * FROM protocols ORDER BY id').fetchall(); con.close()
    return templates.TemplateResponse('users.html', {'request': request, 'active': 'users', 'users': users, 'protocols': protocols})

@app.post('/users/add')
def users_add(request: Request, username: str = Form(...), protocol_key: str = Form(...)):
    auth = require_login(request)
    if auth: return auth
    con = connect()
    try:
        con.execute('INSERT INTO users(username, protocol_key, enabled, created_at) VALUES (?, ?, 1, ?)', (username, protocol_key, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        con.commit(); log_action('add user', f'{protocol_key}:{username}')
    except Exception as e:
        log_action('add user', f'{protocol_key}:{username}', 'error', str(e))
    finally:
        con.close()
    return RedirectResponse('/users', status_code=302)

@app.post('/users/{user_id}/delete')
def users_delete(request: Request, user_id: int):
    auth = require_login(request)
    if auth: return auth
    con = connect(); con.execute('DELETE FROM users WHERE id=?', (user_id,)); con.commit(); con.close()
    log_action('delete user', str(user_id))
    return RedirectResponse('/users', status_code=302)

@app.get('/firewall')
def firewall_page(request: Request):
    auth = require_login(request)
    if auth: return auth
    return templates.TemplateResponse('firewall.html', {'request': request, 'active': 'firewall', 'ports': system_ops.list_open_ports(), 'protocols': protocol_rows(), 'panel_port': system_ops.panel_port()})

@app.post('/firewall/open')
def firewall_open(request: Request, port: int = Form(...), proto: str = Form(...)):
    auth = require_login(request)
    if auth: return auth
    ok, msg = system_ops.open_port(port, proto); log_action('open firewall port', f'{port}/{proto}', 'ok' if ok else 'error', msg)
    return RedirectResponse('/firewall', status_code=302)

@app.post('/firewall/close')
def firewall_close(request: Request, port: int = Form(...), proto: str = Form(...)):
    auth = require_login(request)
    if auth: return auth
    ok, msg = system_ops.close_port(port, proto, system_ops.panel_port()); log_action('close firewall port', f'{port}/{proto}', 'ok' if ok else 'error', msg)
    return RedirectResponse('/firewall', status_code=302)

@app.get('/logs')
def logs_page(request: Request, kind: str = 'singbox'):
    auth = require_login(request)
    if auth: return auth
    protocols = protocol_rows()
    if kind == 'system': content = system_ops.journal(None, 200); title = '系统日志'
    elif kind == 'diagnostic': content = system_ops.diagnostic(protocols); title = '完整诊断信息'
    else: content = system_ops.journal('sing-box', 200); title = 'sing-box 日志'
    return templates.TemplateResponse('logs.html', {'request': request, 'active': 'logs', 'kind': kind, 'title': title, 'content': content})

@app.get('/settings')
def settings_page(request: Request):
    auth = require_login(request)
    if auth: return auth
    return templates.TemplateResponse('settings.html', {'request': request, 'active': 'settings', 'panel_port': system_ops.panel_port()})

@app.post('/settings/password')
def change_password(request: Request, username: str = Form(...), password: str = Form(...)):
    auth = require_login(request)
    if auth: return auth
    create_admin(username, password); log_action('change admin password', username)
    return RedirectResponse('/settings', status_code=302)

if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--init-admin':
        create_admin(sys.argv[2], sys.argv[3])
        print('admin initialized')
