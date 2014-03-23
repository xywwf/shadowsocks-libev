if BUILD_WINCOMPAT
SUBDIRS = libev src
else
if BUILD_BADVPN
SUBDIRS = libasyncns libev badvpn src
else
SUBDIRS = libasyncns libev src
endif
endif
ACLOCAL_AMFLAGS = -I m4
man_MANS = shadowsocks.8
