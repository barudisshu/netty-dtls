#!/bin/bash

java -version
BASEDIR=$(cd $(dirname "$0") && pwd)
. ${BASEDIR}/common.sh

workdir=$(echo "$BASEDIR" | sed -e "s/\/bin//g")
PID_FILE=${workdir}/pid
NOHUP_FILE=${workdir}/nohup.out

JAVA_OPTS="\
					 -server \
					 -Xms512m \
					 -Xmx512m \
					 -XX:-UseGCOverheadLimit"

pid=$( check_pid $PID_FILE )

if [[ ! -z "$pid" && "$pid" != " " ]];then
    echo "http2 server is already running."
else
		nohup java ${JAVA_OPTS} -jar ${workdir}/netty-dtls-1.0-SNAPSHOT.jar > ${NOHUP_FILE} < /dev/null 2>&1 &
		pid=$!
		sleep 1
		echo "start http2 server successfully!"
		echo "Usage: "
		echo "       curl -k -v --http2 http://127.0.0.1:8080"
		echo ""
fi
echo "application pid: $pid"
echo ${pid} > ${PID_FILE}
