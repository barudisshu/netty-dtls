#!/bin/bash

BASEDIR=$(cd $(dirname "$0") && pwd)
. ${BASEDIR}/common.sh
workdir=$(echo "$BASEDIR" | sed -e "s/\/bin//g")

PID_FILE=${workdir}/pid

pid=$( check_pid ${PID_FILE} )

if [[ ! -z "$pid" && "$pid" != " " ]]; then
	echo "application pid: ${pid}"
	kill ${pid}
	if [[ $? -eq 0 ]]; then
		rm -f ${PID_FILE}
		echo "stop http2 server successful!"
	else
		echo "stop http2 server fail!"
	fi
else
	echo "http2 server is not running."
fi
