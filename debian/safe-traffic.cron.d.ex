#
# Regular cron jobs for the safe-traffic package.
#
0 4	* * *	root	[ -x /usr/bin/safe-traffic_maintenance ] && /usr/bin/safe-traffic_maintenance
