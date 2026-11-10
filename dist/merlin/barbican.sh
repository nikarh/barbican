#!/bin/sh
# Runs barbican-edge-ipset on Asuswrt-Merlin, which has no service manager: restarts it when it stops, logs to
# syslog. /jffs/scripts/services-start starts it, firewall-start puts the rules back after a firewall restart.
#
#   barbican.sh start | stop | restart | restore | status
DIR=/jffs/barbican
BIN=$DIR/barbican-edge-ipset
CONF=$DIR/barbican.conf
PIDFILE=/tmp/barbican-edge.pid

supervise() {
	while [ -f "$PIDFILE" ]; do
		"$BIN" --config "$CONF" 2>&1 | logger -t barbican-edge
		[ -f "$PIDFILE" ] && sleep 5
	done
}

case "$1" in
	start)
		[ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null && exit 0
		"$BIN" --config "$CONF" restore 2>&1 | logger -t barbican-edge
		echo $$ >"$PIDFILE"
		supervise </dev/null >/dev/null 2>&1 &
		echo $! >"$PIDFILE"
		;;
	stop)
		[ -f "$PIDFILE" ] || exit 0
		pid=$(cat "$PIDFILE")
		rm -f "$PIDFILE"
		kill "$pid" 2>/dev/null
		# The daemon saves its state on SIGTERM.
		killall -TERM barbican-edge-ipset 2>/dev/null
		;;
	restart)
		"$0" stop
		sleep 1
		"$0" start
		;;
	restore)
		"$BIN" --config "$CONF" restore 2>&1 | logger -t barbican-edge
		;;
	status)
		"$BIN" --config "$CONF" status
		;;
	*)
		echo "usage: $0 start|stop|restart|restore|status" >&2
		exit 2
		;;
esac
