set -eu
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
eval "$(dbus-launch --sh-syntax)"
/usr/libexec/at-spi-bus-launcher --launch-immediately >/tmp/atspi.log 2>&1 &
sleep 1
V=$(find /usr/share/icons -name "*.png" -size +2k | head -1); cp "$V" /tmp/valid.png

python3 - <<'PY'
import subprocess, time
import gi
gi.require_version("Atspi","2.0")
from gi.repository import Atspi

def walk(n,out=None):
    out=out if out is not None else []
    try:
        out.append((n.get_role_name(), n.get_name()))
        for i in range(n.get_child_count()): walk(n.get_child_at_index(i),out)
    except Exception: pass
    return out

def apps():
    r=[]
    for i in range(Atspi.get_desktop_count()):
        dk=Atspi.get_desktop(i)
        for j in range(dk.get_child_count()):
            a=dk.get_child_at_index(j)
            try:
                if a and a.get_name() and "eog" in a.get_name().lower(): r.append(a)
            except Exception: pass
    return r

def ticks(pid):
    try:
        st=open(f"/proc/{pid}/stat").read().split(); return int(st[13])+int(st[14])
    except Exception: return -1

def measure(poll_tree: bool, label: str):
    p=subprocess.Popen(["eog","--new-instance","/tmp/valid.png"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    t0=time.time(); pc,sc,quiet,samples = -1,0,None,[]
    while time.time()-t0 < 12:
        if poll_tree:
            [n for a in apps() for n in walk(a)]      # the observation under test
        c=ticks(p.pid); samples.append(c)
        if quiet is None:
            if c==pc and c>0:
                sc+=1
                if sc>=6: quiet=time.time()-t0
            else: sc=0
            pc=c
        if quiet: break
        time.sleep(0.05)
    print(f"  {label:34} cpu_quiet={f'{quiet:.2f}s' if quiet else 'NEVER'}  "
          f"final_ticks={samples[-1]}  growth={samples[-1]-samples[0]}")
    p.terminate()
    try: p.wait(timeout=5)
    except Exception: p.kill()
    for _ in range(80):
        if not apps(): break
        time.sleep(0.05)

measure(False, "CPU polled alone")
measure(True,  "CPU polled WHILE walking AT-SPI")
measure(False, "CPU polled alone (repeat)")
PY
