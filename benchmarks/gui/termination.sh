set -eu
export DISPLAY=:99
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
eval "$(dbus-launch --sh-syntax)"
/usr/libexec/at-spi-bus-launcher --launch-immediately >/tmp/atspi.log 2>&1 &
sleep 1
V=$(find /usr/share/icons -name "*.png" -size +2k | head -1); cp "$V" /tmp/valid.png
head -c 60 /tmp/valid.png > /tmp/hdr_only.png
printf 'not a png at all' > /tmp/garbage.png

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
        st = open(f"/proc/{pid}/stat").read().split()
        return int(st[13]) + int(st[14])
    except Exception:
        return -1

QUIET_POLLS = 6          # 6 x 50 ms of no change
print(f"  {'input':10} {'window':>8} {'cpu_quiet':>10} {'tree_stable':>12} {'delta':>7} {'nodes':>6}")
rows=[]
for lab in ("valid","hdr_only","garbage"):
    p=subprocess.Popen(["eog","--new-instance",f"/tmp/{lab}.png"],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    t0=time.time(); win=None; tree_stable=None; cpu_quiet=None
    pn,sn,pc,sc,nodes = -1,0,-1,0,[]
    while time.time()-t0 < 25:
        c = ticks(p.pid)
        if cpu_quiet is None:
            if c == pc and c > 0:
                sc += 1
                if sc >= QUIET_POLLS: cpu_quiet = time.time()-t0
            else: sc = 0
            pc = c
        nodes=[n for a in apps() for n in walk(a)]
        if win is None and nodes: win = time.time()-t0
        if tree_stable is None:
            if len(nodes)==pn and len(nodes)>5:
                sn+=1
                if sn>=QUIET_POLLS: tree_stable = time.time()-t0
            else: sn=0
            pn=len(nodes)
        if tree_stable and cpu_quiet: break
        time.sleep(0.05)
    d = (tree_stable-cpu_quiet) if (tree_stable and cpu_quiet) else None
    fmt=lambda x: f"{x:.2f}s" if x is not None else "  --  "
    print(f"  {lab:10} {fmt(win):>8} {fmt(cpu_quiet):>10} {fmt(tree_stable):>12} "
          f"{(f'{d:+.2f}s' if d is not None else '  --  '):>7} {len(nodes):>6}")
    rows.append((lab,cpu_quiet,tree_stable))
    p.terminate()
    try: p.wait(timeout=5)
    except Exception: p.kill()
    for _ in range(80):
        if not apps(): break
        time.sleep(0.05)
ok=[r for r in rows if r[1] and r[2]]
if ok:
    print(f"\n  cpu_quiet is earlier in {sum(1 for _,c,t in ok if c<t)}/{len(ok)} cases; "
          f"mean gap {sum(t-c for _,c,t in ok)/len(ok):+.2f}s")
PY
