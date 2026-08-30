set -eu
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
eval "$(dbus-launch --sh-syntax)"
/usr/libexec/at-spi-bus-launcher --launch-immediately >/tmp/atspi.log 2>&1 &
sleep 1
V=$(find /usr/share/icons -name "*.png" -size +2k | head -1); cp "$V" /tmp/valid.png
head -c 60  /tmp/valid.png > /tmp/hdr_only.png          # header, no image data
head -c 400 /tmp/valid.png > /tmp/truncated.png         # partial image data
cp /tmp/valid.png /tmp/badmagic.png && printf 'X' | dd of=/tmp/badmagic.png bs=1 seek=1 conv=notrunc 2>/dev/null
cp /tmp/valid.png /tmp/badcrc.png    && printf '\xff\xff' | dd of=/tmp/badcrc.png bs=1 seek=40 conv=notrunc 2>/dev/null
printf 'not a png at all' > /tmp/garbage.png
ls -l /tmp/*.png | awk '{print "  ", $5, $9}'

python3 - <<'PY'
import subprocess, time
import gi
gi.require_version("Atspi", "2.0")
from gi.repository import Atspi

ERROR_ROLES = ("info bar", "alert", "dialog", "notification")

def walk(n, d=0, out=None):
    out = out if out is not None else []
    try:
        out.append((d, n.get_role_name(), n.get_name()))
        for i in range(n.get_child_count()):
            walk(n.get_child_at_index(i), d+1, out)
    except Exception:
        pass
    return out

def apps():
    r = []
    for i in range(Atspi.get_desktop_count()):
        dk = Atspi.get_desktop(i)
        for j in range(dk.get_child_count()):
            a = dk.get_child_at_index(j)
            try:
                if a and a.get_name() and "eog" in a.get_name().lower(): r.append(a)
            except Exception: pass
    return r

print(f"  {'input':12} {'nodes':>5}  verdict")
for label in ("valid","hdr_only","truncated","badmagic","badcrc","garbage"):
    p = subprocess.Popen(["eog","--new-instance",f"/tmp/{label}.png"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0, prev, stable, nodes = time.time(), -1, 0, []
    while time.time()-t0 < 20:
        nodes = [n for a in apps() for n in walk(a)]
        if len(nodes)==prev and len(nodes)>5:
            stable += 1
            if stable>=6: break
        else: stable = 0
        prev = len(nodes); time.sleep(0.05)
    hits = [(n[1],n[2]) for n in nodes
            if n[1] in ERROR_ROLES or (n[2] and "error" in str(n[2]).lower())]
    print(f"  {label:12} {len(nodes):>5}  {'REJECTED ' + str(hits[:1]) if hits else 'accepted'}")
    p.terminate()
    try: p.wait(timeout=5)
    except Exception: p.kill()
    for _ in range(60):
        if not apps(): break
        time.sleep(0.05)
PY
