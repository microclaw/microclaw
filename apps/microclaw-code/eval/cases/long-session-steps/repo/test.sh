#!/bin/sh
set -e
[ "$(sh calc.sh add 2 3)" = "5" ]
[ "$(sh calc.sh sub 7 2)" = "5" ]
[ "$(sh calc.sh mul 4 3)" = "12" ]
[ "$(sh calc.sh div 9 2)" = "4" ]
if sh calc.sh div 1 0 2>/dev/null; then echo "div by zero must fail"; exit 1; fi
grep -q 'sub' README.md
grep -q 'div' README.md
echo ok
