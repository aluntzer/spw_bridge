#!/bin/bash


usage () {
	echo ""
	echo "Usage: $0 <link 1> <link 2>"
	echo ""
	echo "link 1 port is 1234, link 2 port is 1235"
	echo ""
}

if [ -z "$2" ]
then
	usage
	exit
fi


if [[ ! -p /tmp/backpipe ]]
then
	mkfifo /tmp/backpipe
fi


# link 1
../spw_bridge/spw_bridge -c $1 -d 4 -n 44:2:0:0 -p 1234 -P &

sleep 1

# link 2
../spw_bridge/spw_bridge -c $2 -d 4 -n 24:2:0:0 -p 1235 -P &

nc localhost 1234 < /tmp/backpipe | nc localhost 1235 > /tmp/backpipe &


#trap 'kill $(jobs -pr)' SIGINT SIGTERM EXIT

wait

rm /tmp/backpipe
