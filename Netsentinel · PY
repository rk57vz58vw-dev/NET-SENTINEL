#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NET SENTINEL — مراقب الشبكات
=============================
- اكتشاف الأجهزة المتصلة بشبكتك (Ping Sweep + جدول ARP)
- مراقبة استهلاك الشبكة (رفع/تنزيل لحظي)
- تنبيه عند ظهور جهاز جديد (كونسول + ملف سجل + صوت + Telegram اختياري)
- لوحة تحكم مباشرة في المتصفح

يعمل بمكتبات بايثون القياسية فقط. (psutil اختياري لدقة أعلى في قياس الاستهلاك)

التشغيل:
    python netsentinel.py
    python netsentinel.py --subnet 192.168.1.0/24 --port 8080 --interval 30

ثم افتح:  http://localhost:8080

⚠️ استخدمه فقط على شبكتك الخاصة أو شبكة تملك إذنًا بمراقبتها.
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest

try:
    import psutil  # اختياري
except ImportError:
    psutil = None

IS_WIN = platform.system().lower() == "windows"
IS_MAC = platform.system().lower() == "darwin"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KNOWN_FILE = os.path.join(BASE_DIR, "known_devices.json")
LOG_FILE = os.path.join(BASE_DIR, "netsentinel.log")

# ---------------------------------------------------------------- الحالة العامة
state_lock = threading.Lock()
devices = {}                       # mac -> dict
events = deque(maxlen=100)         # آخر الأحداث
bw_history = deque(maxlen=120)     # (t, down_bps, up_bps)
stats = {
    "started": time.time(),
    "last_scan": None,
    "scanning": False,
    "total_down": 0,
    "total_up": 0,
    "subnet": "",
    "local_ip": "",
    "bw_source": "غير متاح",
}
known = {}                         # mac -> {"name":..., "first_seen":...}


# ---------------------------------------------------------------- أدوات مساعدة
def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(msg):
    line = f"[{now_str()}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def norm_mac(mac):
    parts = re.split(r"[:-]", mac.strip())
    return ":".join(p.zfill(2) for p in parts).lower()


def is_random_mac(mac):
    """العنوان العشوائي (Private MAC) تستخدمه الهواتف الحديثة."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def format_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def beep():
    try:
        if IS_WIN:
            import winsound
            winsound.Beep(1200, 400)
        else:
            sys.stdout.write("\a")
            sys.stdout.flush()
    except Exception:
        pass


def send_telegram(text):
    token = os.environ.get("NS_TG_TOKEN")
    chat = os.environ.get("NS_TG_CHAT")
    if not token or not chat:
        return
    try:
        data = json.dumps({"chat_id": chat, "text": text}).encode()
        req = urlrequest.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=data,
            headers={"Content-Type": "application/json"},
        )
        urlrequest.urlopen(req, timeout=8).read()
    except Exception as e:
        log(f"تعذّر إرسال تنبيه Telegram: {e}")


def load_known():
    global known
    if os.path.exists(KNOWN_FILE):
        try:
            with open(KNOWN_FILE, "r", encoding="utf-8") as f:
                known = json.load(f)
        except (OSError, ValueError):
            known = {}


def save_known():
    try:
        with open(KNOWN_FILE, "w", encoding="utf-8") as f:
            json.dump(known, f, ensure_ascii=False, indent=2)
    except OSError as e:
        log(f"تعذّر حفظ قائمة الأجهزة: {e}")


# ---------------------------------------------------------------- اكتشاف الأجهزة
def ping(ip):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "700", ip]
    elif IS_MAC:
        cmd = ["ping", "-c", "1", "-W", "700", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    except (subprocess.SubprocessError, OSError):
        pass


def read_arp_table():
    """يرجع {ip: mac} من جدول ARP الخاص بالنظام."""
    table = {}
    mac_re = re.compile(r"((?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2})")
    ip_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

    outputs = []
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp") as f:
                outputs.append(f.read())
        except OSError:
            pass
    if not outputs:
        for cmd in (["arp", "-a"], ["ip", "neigh"]):
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout
                if out:
                    outputs.append(out)
                    break
            except (subprocess.SubprocessError, OSError):
                continue

    for out in outputs:
        for line in out.splitlines():
            m_ip, m_mac = ip_re.search(line), mac_re.search(line)
            if not (m_ip and m_mac):
                continue
            ip, mac = m_ip.group(1), norm_mac(m_mac.group(1))
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue
            if ip.startswith(("224.", "239.")) or ip.endswith(".255"):
                continue
            table[ip] = mac
    return table


def resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


def scan_network(subnet, first_run):
    with state_lock:
        stats["scanning"] = True
    try:
        net = ipaddress.ip_network(subnet, strict=False)
        hosts = [str(h) for h in net.hosts()]
        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(ping, hosts))
        arp = read_arp_table()
        arp = {ip: mac for ip, mac in arp.items() if ipaddress.ip_address(ip) in net}

        seen_macs = set()
        new_found = []
        ts = now_str()

        for ip, mac in arp.items():
            seen_macs.add(mac)
            with state_lock:
                dev = devices.get(mac)
            if dev is None:
                name = resolve_name(ip)
                dev = {
                    "mac": mac, "ip": ip, "name": name,
                    "first_seen": ts, "last_seen": ts, "online": True,
                    "trusted": mac in known, "random_mac": is_random_mac(mac),
                    "is_me": ip == stats["local_ip"],
                }
                with state_lock:
                    devices[mac] = dev
                if mac not in known:
                    new_found.append(dev)
            else:
                with state_lock:
                    dev.update(ip=ip, last_seen=ts, online=True)
                    if not dev["name"]:
                        dev["name"] = resolve_name(ip)

        with state_lock:
            for mac, dev in devices.items():
                if mac not in seen_macs and not dev["is_me"]:
                    dev["online"] = False

        # أول تشغيل = تعلّم: كل ما يُكتشف يُعتبر موثوقًا
        if first_run:
            for dev in new_found:
                known[dev["mac"]] = {"name": dev["name"], "ip": dev["ip"], "first_seen": ts}
                dev["trusted"] = True
            save_known()
            log(f"وضع التعلّم: تم اعتماد {len(new_found)} جهاز كأجهزة موثوقة.")
        else:
            for dev in new_found:
                alert_new_device(dev)

        with state_lock:
            stats["last_scan"] = ts
    except Exception as e:
        log(f"خطأ أثناء الفحص: {e}")
    finally:
        with state_lock:
            stats["scanning"] = False


def alert_new_device(dev):
    label = dev["name"] or "بدون اسم"
    extra = " (عنوان MAC عشوائي)" if dev["random_mac"] else ""
    msg = f"🚨 جهاز جديد! IP={dev['ip']} | MAC={dev['mac']} | الاسم={label}{extra}"
    log(msg)
    with state_lock:
        events.appendleft({"time": now_str(), "level": "alert", "text": msg})
    beep()
    threading.Thread(target=send_telegram, args=(msg,), daemon=True).start()


def scanner_loop(subnet, interval):
    first_run = not os.path.exists(KNOWN_FILE)
    while True:
        scan_network(subnet, first_run)
        first_run = False
        time.sleep(interval)


# ---------------------------------------------------------------- مراقبة الاستهلاك
def read_counters(iface=None):
    """يرجع (bytes_recv, bytes_sent) إجمالي."""
    if psutil:
        stats["bw_source"] = "psutil"
        if iface:
            c = psutil.net_io_counters(pernic=True).get(iface)
            return (c.bytes_recv, c.bytes_sent) if c else None
        c = psutil.net_io_counters(pernic=True)
        rx = sum(v.bytes_recv for k, v in c.items() if not k.lower().startswith(("lo", "loopback")))
        tx = sum(v.bytes_sent for k, v in c.items() if not k.lower().startswith(("lo", "loopback")))
        return rx, tx

    if os.path.exists("/proc/net/dev"):
        stats["bw_source"] = "/proc/net/dev"
        rx = tx = 0
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name, data = line.split(":", 1)
                name = name.strip()
                if name == "lo" or (iface and name != iface):
                    continue
                cols = data.split()
                rx += int(cols[0])
                tx += int(cols[8])
        return rx, tx
    return None


def bandwidth_loop(iface):
    prev = read_counters(iface)
    prev_t = time.time()
    if prev is None:
        log("⚠️ مراقبة الاستهلاك غير متاحة على هذا النظام. ثبّت psutil:  pip install psutil")
        return
    while True:
        time.sleep(1)
        cur = read_counters(iface)
        t = time.time()
        if cur is None:
            continue
        dt = max(t - prev_t, 0.001)
        down = max(cur[0] - prev[0], 0) / dt
        up = max(cur[1] - prev[1], 0) / dt
        with state_lock:
            bw_history.append((t, down, up))
            stats["total_down"] += max(cur[0] - prev[0], 0)
            stats["total_up"] += max(cur[1] - prev[1], 0)
        prev, prev_t = cur, t


# ---------------------------------------------------------------- لوحة التحكم
HTML = r"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NET SENTINEL</title>
<style>
 :root{--bg:#0b1020;--card:#131a2e;--line:#22304f;--txt:#e6edf7;--mut:#8a98b5;--ok:#2ecc71;--bad:#ff4d5e;--acc:#38bdf8;--up:#f59e0b}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--txt);font-family:system-ui,Segoe UI,Tahoma,sans-serif}
 header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--line)}
 h1{margin:0;font-size:20px;letter-spacing:2px;color:var(--acc)} .pulse{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--ok);margin-inline-end:8px;animation:p 1.5s infinite}
 @keyframes p{50%{opacity:.3}}
 main{padding:20px 24px;display:grid;gap:16px;grid-template-columns:repeat(12,1fr)}
 .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
 .c3{grid-column:span 3}.c12{grid-column:span 12}.c8{grid-column:span 8}.c4{grid-column:span 4}
 @media(max-width:900px){.c3,.c8,.c4{grid-column:span 12}}
 .k{color:var(--mut);font-size:13px}.v{font-size:26px;font-weight:700;margin-top:6px;direction:ltr;text-align:right}
 table{width:100%;border-collapse:collapse;font-size:14px} th,td{padding:9px 8px;text-align:right;border-bottom:1px solid var(--line)}
 th{color:var(--mut);font-weight:600} td.l{direction:ltr;text-align:right;font-family:ui-monospace,Consolas,monospace}
 .tag{padding:2px 8px;border-radius:99px;font-size:12px}.on{background:#12351f;color:var(--ok)}.off{background:#2b2f3a;color:var(--mut)}
 .new{background:#3a1218;color:var(--bad)}.me{background:#10304a;color:var(--acc)}
 .ev{padding:8px 10px;border-radius:8px;margin-bottom:6px;font-size:13px;background:#1a2138;direction:rtl}.ev.alert{background:#3a1218;border:1px solid #6b1f2a}
 .ev small{color:var(--mut);display:block;direction:ltr;text-align:right}
 canvas{width:100%;height:230px;display:block}
 button{background:var(--acc);color:#04202e;border:0;border-radius:8px;padding:4px 10px;cursor:pointer;font-weight:700}
</style>
</head>
<body>
<header><h1>🛡️ NET SENTINEL</h1><div><span class="pulse"></span><span id="scan" class="k">...</span></div></header>
<main>
 <div class="card c3"><div class="k">⬇️ تنزيل الآن</div><div class="v" id="down">0</div></div>
 <div class="card c3"><div class="k">⬆️ رفع الآن</div><div class="v" id="up">0</div></div>
 <div class="card c3"><div class="k">الأجهزة المتصلة</div><div class="v" id="online">0</div></div>
 <div class="card c3"><div class="k">إجمالي الاستهلاك (منذ التشغيل)</div><div class="v" id="total" style="font-size:18px">0</div></div>

 <div class="card c12"><div class="k" style="margin-bottom:8px">استهلاك الشبكة (آخر دقيقتين) — <span style="color:var(--acc)">■ تنزيل</span> <span style="color:var(--up)">■ رفع</span></div><canvas id="chart" width="1200" height="230"></canvas></div>

 <div class="card c8"><div class="k" style="margin-bottom:8px">الأجهزة المكتشفة — <span id="meta"></span></div>
  <table><thead><tr><th>الحالة</th><th>IP</th><th>MAC</th><th>الاسم</th><th>أول ظهور</th><th>آخر ظهور</th><th></th></tr></thead><tbody id="rows"></tbody></table></div>
 <div class="card c4"><div class="k" style="margin-bottom:8px">سجل الأحداث</div><div id="events"></div></div>
</main>
<script>
const fmt=b=>{const u=['B/s','KB/s','MB/s','GB/s'];let i=0;while(b>=1024&&i<3){b/=1024;i++}return b.toFixed(1)+' '+u[i]};
const fmtB=b=>{const u=['B','KB','MB','GB','TB'];let i=0;while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(1)+' '+u[i]};
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function draw(h){
 const c=document.getElementById('chart'),x=c.getContext('2d'),W=c.width,H=c.height;x.clearRect(0,0,W,H);
 const max=Math.max(1024,...h.map(p=>Math.max(p[1],p[2])))*1.15;
 x.strokeStyle='#22304f';x.fillStyle='#8a98b5';x.font='12px sans-serif';
 for(let i=0;i<=4;i++){const y=H-20-(H-30)*i/4;x.beginPath();x.moveTo(60,y);x.lineTo(W,y);x.stroke();x.fillText(fmt(max*i/4),2,y+4)}
 const line=(idx,col)=>{if(h.length<2)return;x.strokeStyle=col;x.lineWidth=2;x.beginPath();
  h.forEach((p,i)=>{const px=60+(W-60)*i/(Math.max(h.length-1,1)),py=H-20-(H-30)*p[idx]/max;i?x.lineTo(px,py):x.moveTo(px,py)});x.stroke()};
 line(1,'#38bdf8');line(2,'#f59e0b');
}
async function trust(mac){await fetch('/api/trust?mac='+encodeURIComponent(mac),{method:'POST'});tick()}
async function tick(){
 try{
  const s=await (await fetch('/api/state')).json();
  const last=s.history.length?s.history[s.history.length-1]:[0,0,0];
  down.textContent=fmt(last[1]);up.textContent=fmt(last[2]);
  online.textContent=s.devices.filter(d=>d.online).length+' / '+s.devices.length;
  total.textContent='⬇ '+fmtB(s.stats.total_down)+'  ⬆ '+fmtB(s.stats.total_up);
  scan.textContent=s.stats.scanning?'جارٍ الفحص...':'آخر فحص: '+(s.stats.last_scan||'—');
  meta.textContent='الشبكة '+s.stats.subnet+' • جهازك '+s.stats.local_ip+' • مصدر القياس: '+s.stats.bw_source;
  rows.innerHTML=s.devices.sort((a,b)=>b.online-a.online).map(d=>`<tr>
   <td><span class="tag ${d.online?'on':'off'}">${d.online?'متصل':'غير متصل'}</span> ${d.trusted?'':'<span class="tag new">جديد</span>'} ${d.is_me?'<span class="tag me">أنت</span>':''}</td>
   <td class="l">${esc(d.ip)}</td><td class="l">${esc(d.mac)}${d.random_mac?' 🎭':''}</td><td>${esc(d.name||'—')}</td>
   <td class="l">${esc(d.first_seen)}</td><td class="l">${esc(d.last_seen)}</td>
   <td>${d.trusted?'':`<button onclick="trust('${esc(d.mac)}')">اعتماد</button>`}</td></tr>`).join('');
  events.innerHTML=s.events.length?s.events.map(e=>`<div class="ev ${e.level}">${esc(e.text)}<small>${esc(e.time)}</small></div>`).join(''):'<div class="k">لا أحداث بعد.</div>';
  draw(s.history);
 }catch(e){scan.textContent='انقطع الاتصال بالسكربت'}
}
tick();setInterval(tick,2000);
</script>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # إسكات سجل HTTP
        pass

    def _send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            self._send(200, HTML, "text/html; charset=utf-8")
        elif self.path == "/api/state":
            with state_lock:
                payload = {
                    "devices": list(devices.values()),
                    "events": list(events),
                    "history": [[round(t, 1), round(d, 1), round(u, 1)] for t, d, u in bw_history],
                    "stats": dict(stats),
                }
            self._send(200, json.dumps(payload, ensure_ascii=False), "application/json; charset=utf-8")
        else:
            self._send(404, "Not found", "text/plain")

    def do_POST(self):
        if self.path.startswith("/api/trust"):
            from urllib.parse import urlparse, parse_qs
            mac = parse_qs(urlparse(self.path).query).get("mac", [""])[0].lower()
            with state_lock:
                dev = devices.get(mac)
                if dev:
                    dev["trusted"] = True
                    known[mac] = {"name": dev["name"], "ip": dev["ip"], "first_seen": dev["first_seen"]}
                    events.appendleft({"time": now_str(), "level": "info", "text": f"✅ تم اعتماد الجهاز {dev['ip']} ({mac})"})
            save_known()
            self._send(200, "{}", "application/json")
        else:
            self._send(404, "Not found", "text/plain")


# ---------------------------------------------------------------- التشغيل
def main():
    ap = argparse.ArgumentParser(description="NET SENTINEL — مراقب الشبكات")
    ap.add_argument("--subnet", help="مثال: 192.168.1.0/24 (الافتراضي: يُكتشف تلقائيًا)")
    ap.add_argument("--interval", type=int, default=30, help="ثواني بين كل فحص (الافتراضي 30)")
    ap.add_argument("--port", type=int, default=8080, help="منفذ لوحة التحكم (الافتراضي 8080)")
    ap.add_argument("--host", default="127.0.0.1", help="استخدم 0.0.0.0 للوصول من أجهزة أخرى")
    ap.add_argument("--iface", help="اسم كرت الشبكة لقياس الاستهلاك (الافتراضي: الكل)")
    args = ap.parse_args()

    local_ip = get_local_ip()
    subnet = args.subnet or str(ipaddress.ip_network(local_ip + "/24", strict=False))
    stats["local_ip"], stats["subnet"] = local_ip, subnet

    load_known()
    log(f"NET SENTINEL يعمل — الشبكة: {subnet} | جهازك: {local_ip}")

    threading.Thread(target=scanner_loop, args=(subnet, args.interval), daemon=True).start()
    threading.Thread(target=bandwidth_loop, args=(args.iface,), daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    log(f"لوحة التحكم:  http://localhost:{args.port}   (للإيقاف: Ctrl+C)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("تم الإيقاف.")
        server.shutdown()


if __name__ == "__main__":
    main()
