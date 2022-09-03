#!/bin/bash

check_pid() {
	if [[ -f ${1} ]]; then
		pid=`cat ${1}`
		if [[ x"${pid}" != x"" && -d /proc/${pid} ]]; then
			echo ${pid}
			return 1
		fi
	fi
	# No pid file found or pid file not removed when process terminated.
	return 0
}
