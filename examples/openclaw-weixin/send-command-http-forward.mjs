#!/usr/bin/env node

const bridgeUrl = process.env.WEIXIN_BRIDGE_URL?.trim();
if (!bridgeUrl) {
  console.error("WEIXIN_BRIDGE_URL is required");
  process.exit(1);
}

const rawPayload = process.env.MICROCLAW_WEIXIN_PAYLOAD?.trim();
if (!rawPayload) {
  console.error("MICROCLAW_WEIXIN_PAYLOAD is required");
  process.exit(1);
}

let payload;
try {
  payload = JSON.parse(rawPayload);
} catch (error) {
  console.error(`invalid MICROCLAW_WEIXIN_PAYLOAD: ${error}`);
  process.exit(1);
}

const headers = {
  "content-type": "application/json",
};

const bridgeToken = process.env.WEIXIN_BRIDGE_TOKEN?.trim();
if (bridgeToken) {
  headers.authorization = `Bearer ${bridgeToken}`;
}

const response = await fetch(bridgeUrl, {
  method: "POST",
  headers,
  body: JSON.stringify(payload),
});

if (!response.ok) {
  const body = await response.text().catch(() => "");
  console.error(`bridge request failed: ${response.status} ${body}`.trim());
  process.exit(1);
}

const responseText = await response.text().catch(() => "");
if (responseText.trim()) {
  process.stdout.write(responseText.trim());
}
