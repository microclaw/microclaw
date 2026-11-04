#!/bin/sh
set -e
[ "$(sh greet.sh world)" = "hello, world" ] || { echo "unexpected: $(sh greet.sh world)"; exit 1; }
echo ok
