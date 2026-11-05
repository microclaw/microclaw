#!/bin/sh
# Usage: calc.sh add A B
case "$1" in
  add) echo $(( $2 + $3 )) ;;
  *) echo "unknown op: $1" >&2; exit 2 ;;
esac
