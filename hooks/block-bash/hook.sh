#!/bin/sh
payload="$(cat)"

echo "$payload" | grep -q '"tool_name":"bash"'
if [ $? -eq 0 ]; then
  echo '{"action":"block","reason":"bash is disabled by sample hook"}'
  exit 0
fi

echo '{"action":"allow"}'
