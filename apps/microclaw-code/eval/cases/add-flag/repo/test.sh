#!/bin/sh
set -e
[ "$(sh count.sh a b)" = "count: 2" ]
[ "$(sh count.sh --shout a b)" = "COUNT: 2" ]
echo ok
