#!/bin/sh
set -e
for f in tools/hello.sh tools/count.sh; do
  [ -f "$f" ] || { echo "missing $f"; exit 1; }
  head -n1 "$f" | grep -qx '#!/bin/sh' || { echo "$f: first line is not #!/bin/sh"; exit 1; }
  if grep -q '\[\[' "$f"; then echo "$f uses [[ ]]"; exit 1; fi
done
[ "$(sh tools/hello.sh world)" = "hello world" ] || { echo "hello.sh output"; exit 1; }
[ "$(sh tools/count.sh a b c)" = "3" ] || { echo "count.sh output"; exit 1; }
echo ok
