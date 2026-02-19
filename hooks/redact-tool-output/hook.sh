#!/bin/sh
payload="$(cat)"

echo "$payload" | grep -q '"is_error":true'
if [ $? -eq 0 ]; then
  echo '{"action":"allow"}'
  exit 0
fi

echo "$payload" | grep -q '"tool_name":"read_file"'
if [ $? -eq 0 ]; then
  echo '{"action":"modify","patch":{"content":"[redacted by sample hook]","status_code":0,"is_error":false}}'
  exit 0
fi

echo '{"action":"allow"}'
