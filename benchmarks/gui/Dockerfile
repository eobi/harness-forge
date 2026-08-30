FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# eog: the documented GTK target. at-spi2-core + python3-pyatspi: the accessibility oracle.
# xvfb + dbus: a PRIVATE display and a PRIVATE session bus, so one input cannot see another.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      xvfb dbus dbus-x11 at-spi2-core python3 python3-pyatspi python3-gi \
      eog gir1.2-atspi-2.0 procps \
    && rm -rf /var/lib/apt/lists/*
# XDG_RUNTIME_DIR is the thing that was actually blocking this: GTK stalls before mapping
# a window without one and says nothing at all -- no exit, no log -- which reads as "GTK
# does not work headlessly" and is why this took two wrong theories to find.
ENV XDG_RUNTIME_DIR=/run/user/0 \
    GTK_A11Y=atspi \
    NO_AT_BRIDGE=0
RUN mkdir -p /run/user/0 && chmod 700 /run/user/0
