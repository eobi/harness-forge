set -eu
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
eval "$(dbus-launch --sh-syntax)"
/usr/libexec/at-spi-bus-launcher --launch-immediately >/tmp/atspi.log 2>&1 &
sleep 1
V=$(find /usr/share/icons -name "*.png" -size +2k | head -1); cp "$V" /tmp/valid.png
printf 'not a png at all' > /tmp/garbage.png

python3 - <<'PY'
import subprocess, time
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

def walk(n, out=None):
    out = out if out is not None else []
    try:
        out.append((n.get_role_name(), n.get_name()))
        for i in range(n.get_child_count()):
            walk(n.get_child_at_index(i), out)
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

def buttons(n, out=None):
    out = out if out is not None else []
    try:
        if n.get_role_name() == "push button": out.append(n)
        for i in range(n.get_child_count()): buttons(n.get_child_at_index(i), out)
    except Exception: pass
    return out

for label in ("valid","garbage"):
    p = subprocess.Popen(["eog","--new-instance",f"/tmp/{label}.png"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0,prev,stable,nodes = time.time(),-1,0,[]
    while time.time()-t0 < 20:
        nodes=[n for a in apps() for n in walk(a)]
        if len(nodes)==prev and len(nodes)>5:
            stable+=1
            if stable>=6: break
        else: stable=0
        prev=len(nodes); time.sleep(0.05)
    before = len(nodes)
    # THE LIVENESS ORACLE: act on the app, then re-enumerate. A process that services an
    # accessibility action is not hung, whatever its window is doing. This is independent
    # of the window-and-close behaviour that produced five false hangs out of six.
    acted, t1 = False, time.time()
    for a in apps():
        for b in buttons(a)[:1]:
            try:
                b.do_action(0); acted = True
            except Exception: pass
    dt = (time.time()-t1)*1000
    after = len([n for a in apps() for n in walk(a)])
    print(f"  {label:8} nodes_before={before:3} acted={acted} action_ms={dt:5.1f} "
          f"nodes_after={after:3} -> {'SERVICING' if after>0 else 'NO RESPONSE'}")
    p.terminate()
    try: p.wait(timeout=5)
    except Exception: p.kill()
    for _ in range(60):
        if not apps(): break
        time.sleep(0.05)
PY
