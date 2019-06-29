#!/bin/sh

set -x
set -e
umask 0000
ulimit -n 1024
sleep 10
exec "$@"
