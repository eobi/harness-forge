set -eu
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
eval "$(dbus-launch --sh-syntax)"
/usr/libexec/at-spi-bus-launcher --launch-immediately >/tmp/atspi.log 2>&1 &
sleep 1
# a REAL pdf, produced by ghostscript rather than hand-written
gs -q -sDEVICE=pdfwrite -o /tmp/valid.pdf -c "/Helvetica findfont 24 scalefont setfont 72 700 moveto (harness forge gui lab) show showpage" 2>/dev/null
head -c 400 /tmp/valid.pdf > /tmp/truncated.pdf
cp /tmp/valid.pdf /tmp/badhdr.pdf && printf 'XXXX' | dd of=/tmp/badhdr.pdf bs=1 seek=1 conv=notrunc 2>/dev/null
printf 'not a pdf at all' > /tmp/garbage.pdf
ls -l /tmp/*.pdf | awk '{print "  ", $5, $9}'

python3 - <<'PY'
import subprocess, time
import gi
gi.require_version("Atspi","2.0")
from gi.repository import Atspi

def walk(n,out=None):
    out = out if out is not None else []
    try:
        out.append((n.get_role_name(), n.get_name()))
        for i in range(n.get_child_count()): walk(n.get_child_at_index(i),out)
    except Exception: pass
    return out

def apps(match):
    r=[]
    for i in range(Atspi.get_desktop_count()):
        dk=Atspi.get_desktop(i)
        for j in range(dk.get_child_count()):
            a=dk.get_child_at_index(j)
            try:
                if a and a.get_name() and match in a.get_name().lower(): r.append(a)
            except Exception: pass
    return r

for lab in ("valid","truncated","badhdr","garbage"):
    p=subprocess.Popen(["evince",f"/tmp/{lab}.pdf"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    t0,prev,stable,nodes=time.time(),-1,0,[]
    while time.time()-t0<25:
        nodes=[n for a in apps("evince") for n in walk(a)]
        if len(nodes)==prev and len(nodes)>5:
            stable+=1
            if stable>=8: break
        else: stable=0
        prev=len(nodes); time.sleep(0.05)
    alerts=[(r,nm) for r,nm in nodes if r in ("alert","info bar","dialog","notification")]
    print(f"  {lab:10} nodes={len(nodes):3}  alerts={alerts}")
    p.terminate()
    try: p.wait(timeout=5)
    except Exception: p.kill()
    for _ in range(80):
        if not apps("evince"): break
        time.sleep(0.05)
PY
