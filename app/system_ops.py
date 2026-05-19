import subprocess
import time
import json
from pathlib import Path
from typing import Dict, Any
import psutil

INFO_ROOT = Path('/etc/freedom-vpn')
WEB_SETTINGS = INFO_ROOT / 'web' / 'settings.json'
PROTECTED_PORTS = {22}

def run_cmd(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except Exception as e:
        return 1, '', str(e)

def fmt_bytes(num: float) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if num < 1024:
            return f'{num:.1f} {unit}'
        num /= 1024
    return f'{num:.1f} PB'

def system_stats() -> Dict[str, Any]:
    cpu = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    return {
        'cpu_percent': round(cpu, 1),
        'mem_used': fmt_bytes(mem.used),
        'mem_total': fmt_bytes(mem.total),
        'mem_percent': round(mem.percent, 1),
        'disk_used': fmt_bytes(disk.used),
        'disk_total': fmt_bytes(disk.total),
        'disk_percent': round(disk.percent, 1),
    }

_last_net = {'t': time.time(), 'sent': psutil.net_io_counters().bytes_sent, 'recv': psutil.net_io_counters().bytes_recv}

def network_stats() -> Dict[str, Any]:
    global _last_net
    now = time.time()
    counters = psutil.net_io_counters()
    dt = max(now - _last_net['t'], 0.1)
    up = (counters.bytes_sent - _last_net['sent']) / dt
    down = (counters.bytes_recv - _last_net['recv']) / dt
    _last_net = {'t': now, 'sent': counters.bytes_sent, 'recv': counters.bytes_recv}
    return {
        'up_speed': f'{fmt_bytes(max(up, 0))}/s',
        'down_speed': f'{fmt_bytes(max(down, 0))}/s',
        'total_sent': fmt_bytes(counters.bytes_sent),
        'total_recv': fmt_bytes(counters.bytes_recv),
    }

def service_status(service_name: str) -> str:
    code, out, _ = run_cmd(['systemctl', 'is-active', service_name], timeout=5)
    if code == 0:
        return '运行中'
    return out or '未运行'

def singbox_version() -> str:
    for path in ['/usr/local/bin/sing-box', 'sing-box']:
        code, out, err = run_cmd([path, 'version'], timeout=5)
        if code == 0 and out:
            return out.splitlines()[0]
    return '未安装'

def list_open_ports():
    code, out, err = run_cmd(['ss', '-lntup'], timeout=10)
    ports = []
    if code != 0:
        return ports
    for line in out.splitlines()[1:]:
        parts = line.split()
        proto = 'TCP' if parts and parts[0].lower().startswith('tcp') else 'UDP'
        local = parts[4] if len(parts) > 4 else ''
        if ':' in local:
            port = local.rsplit(':', 1)[-1]
            if port.isdigit():
                item = f'{port}/{proto}'
                if item not in ports:
                    ports.append(item)
    return sorted(ports, key=lambda x: int(x.split('/')[0]))

def which(name: str):
    from shutil import which as _which
    return _which(name)

def open_port(port: int, proto: str):
    proto = proto.lower()
    if proto not in ('tcp', 'udp'):
        return False, '协议只能是 TCP 或 UDP'
    if port < 1 or port > 65535:
        return False, '端口范围必须是 1-65535'
    if which('ufw'):
        run_cmd(['ufw', 'allow', f'{port}/{proto}'], timeout=15)
    if which('firewall-cmd'):
        run_cmd(['firewall-cmd', '--permanent', f'--add-port={port}/{proto}'], timeout=15)
        run_cmd(['firewall-cmd', '--reload'], timeout=15)
    return True, f'已尝试放行 {port}/{proto.upper()}'

def close_port(port: int, proto: str, panel_port: int | None = None):
    proto = proto.lower()
    if port in PROTECTED_PORTS:
        return False, '为了避免服务器失联，禁止在面板中关闭 SSH 端口 22'
    if panel_port and port == panel_port:
        return False, '不能关闭当前 Web 面板端口，否则会打不开面板'
    if proto not in ('tcp', 'udp'):
        return False, '协议只能是 TCP 或 UDP'
    if which('ufw'):
        run_cmd(['ufw', 'delete', 'allow', f'{port}/{proto}'], timeout=15)
    if which('firewall-cmd'):
        run_cmd(['firewall-cmd', '--permanent', f'--remove-port={port}/{proto}'], timeout=15)
        run_cmd(['firewall-cmd', '--reload'], timeout=15)
    return True, f'已尝试关闭 {port}/{proto.upper()}'

def panel_port() -> int | None:
    try:
        data = json.loads(WEB_SETTINGS.read_text())
        return int(data.get('panel_port'))
    except Exception:
        return None

def journal(service_name: str | None = None, lines: int = 200):
    if service_name:
        cmd = ['journalctl', '-u', service_name, '-n', str(lines), '--no-pager']
    else:
        cmd = ['journalctl', '-n', str(lines), '--no-pager']
    code, out, err = run_cmd(cmd, timeout=15)
    return out or err or '暂无日志'

def diagnostic(protocol_rows):
    s = []
    s.append('===== iwantrun VPN 诊断信息 =====')
    code, os_release, _ = run_cmd(['bash', '-lc', 'cat /etc/os-release | head -n 6'], timeout=5)
    s.append(os_release)
    s.append('')
    s.append(f'sing-box 版本：{singbox_version()}')
    s.append('')
    s.append('===== 协议状态 =====')
    for p in protocol_rows:
        s.append(f"{p['protocol_name']} | service={p['service_name']} | port={p['port']}/{p['port_type']} | status={service_status(p['service_name'])}")
    s.append('')
    s.append('===== 开放端口 =====')
    s.append(', '.join(list_open_ports()))
    s.append('')
    s.append('===== 系统最近日志 =====')
    s.append(journal(None, 80))
    return '\n'.join(s)
