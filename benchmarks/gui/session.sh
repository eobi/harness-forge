# One isolated session: private display, private session bus, and the XDG_RUNTIME_DIR
# without which GTK stalls before mapping a window and says nothing at all.
export DISPLAY=:99
export XDG_RUNTIME_DIR=/run/user/0
mkdir -p "$XDG_RUNTIME_DIR" && chmod 700 "$XDG_RUNTIME_DIR"
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >/tmp/xvfb.log 2>&1 &
for _ in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
eval "$(dbus-launch --sh-syntax)"
/usr/libexec/at-spi-bus-launcher --launch-immediately >/tmp/atspi.log 2>&1 &
sleep 1
