import subprocess,time,json
from pathlib import Path
import psutil
WEB_SETTINGS=Path('/etc/freedom-vpn/web/settings.json')
def run_cmd(cmd,timeout=20):
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout); return p.returncode,p.stdout.strip(),p.stderr.strip()
    except Exception as e: return 1,'',str(e)
def fmt_bytes(num):
    for u in ['B','KB','MB','GB','TB']:
        if num<1024: return f'{num:.1f} {u}'
        num/=1024
    return f'{num:.1f} PB'
def system_stats():
    cpu=psutil.cpu_percent(interval=0.2); mem=psutil.virtual_memory(); disk=psutil.disk_usage('/')
    return {'cpu_percent':round(cpu,1),'mem_used':fmt_bytes(mem.used),'mem_total':fmt_bytes(mem.total),'mem_percent':round(mem.percent,1),'disk_used':fmt_bytes(disk.used),'disk_total':fmt_bytes(disk.total),'disk_percent':round(disk.percent,1)}
_last={'t':time.time(),'sent':psutil.net_io_counters().bytes_sent,'recv':psutil.net_io_counters().bytes_recv}
def network_stats():
    global _last; now=time.time(); c=psutil.net_io_counters(); dt=max(now-_last['t'],0.1); up=max((c.bytes_sent-_last['sent'])/dt,0); down=max((c.bytes_recv-_last['recv'])/dt,0); _last={'t':now,'sent':c.bytes_sent,'recv':c.bytes_recv}; return {'up_speed':fmt_bytes(up)+'/s','down_speed':fmt_bytes(down)+'/s','total_sent':fmt_bytes(c.bytes_sent),'total_recv':fmt_bytes(c.bytes_recv)}
def service_status(s):
    code,out,_=run_cmd(['systemctl','is-active',s],5); return '运行中' if code==0 else '未运行'
def singbox_version():
    for p in ['/usr/local/bin/sing-box','sing-box']:
        code,out,_=run_cmd([p,'version'],5)
        if code==0 and out: return out.splitlines()[0]
    return '未安装'
def list_open_ports():
    code,out,_=run_cmd(['ss','-lntup'],10); ports=[]
    if code!=0: return ports
    for line in out.splitlines()[1:]:
        parts=line.split(); proto=parts[0].upper(); local=parts[4] if len(parts)>4 else ''
        if ':' in local:
            port=local.rsplit(':',1)[-1]
            if port.isdigit():
                item=f"{port}/{'UDP' if proto=='UDP' else 'TCP'}"
                if item not in ports: ports.append(item)
    return sorted(ports,key=lambda x:(int(x.split('/')[0]),x.split('/')[1]))
def _which(n):
    from shutil import which
    return which(n)
def open_port(port,proto):
    proto=proto.lower()
    if _which('ufw'): run_cmd(['ufw','allow',f'{port}/{proto}'],15)
    if _which('firewall-cmd'): run_cmd(['firewall-cmd','--permanent',f'--add-port={port}/{proto}'],15); run_cmd(['firewall-cmd','--reload'],15)
    return True,f'已尝试放行 {port}/{proto.upper()}'
def close_port(port,proto,panel_port=None):
    proto=proto.lower()
    if port==22: return False,'禁止关闭 SSH 端口 22'
    if panel_port and port==panel_port: return False,'不能关闭当前 Web 面板端口'
    if _which('ufw'): run_cmd(['ufw','delete','allow',f'{port}/{proto}'],15)
    if _which('firewall-cmd'): run_cmd(['firewall-cmd','--permanent',f'--remove-port={port}/{proto}'],15); run_cmd(['firewall-cmd','--reload'],15)
    return True,f'已尝试关闭 {port}/{proto.upper()}'
def panel_port():
    try: return int(json.loads(WEB_SETTINGS.read_text()).get('panel_port'))
    except Exception: return None
def journal(service_name=None,lines=200):
    cmd=['journalctl','-n',str(lines),'--no-pager'] if not service_name else ['journalctl','-u',service_name,'-n',str(lines),'--no-pager']
    code,out,err=run_cmd(cmd,15); return out or err or '暂无日志'
def diagnostic(rows):
    _,osrel,_=run_cmd(['bash','-lc','cat /etc/os-release | head -n 6'],5)
    s=['===== iwantrun VPN 诊断信息 =====',osrel,'',f'sing-box 版本：{singbox_version()}','','===== 协议状态 =====']
    for p in rows: s.append(f"{p['protocol_name']} | service={p['service_name']} | port={p['port']}/{p['port_type']} | status={service_status(p['service_name'])}")
    s+=['','===== 开放端口 =====',', '.join(list_open_ports()),'','===== 系统最近日志 =====',journal(None,80)]
    return '\n'.join(s)
