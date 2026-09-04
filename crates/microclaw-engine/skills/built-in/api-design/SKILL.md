---
name: api-design
description: "Design clean, consistent HTTP/REST (and JSON) APIs: resources and URLs, methods, status codes, request/response shapes, pagination, errors, versioning, and auth. Use when users are designing or reviewing an API, an endpoint, or a payload, or ask what status code / shape to return. Triggers on mentions of API, REST, endpoint, route, status code, payload, pagination, versioning, webhook, 接口, 设计 api, 状态码, 分页, 鉴权."
license: Proprietary. LICENSE.txt has complete terms
compatibility: "No external dependencies. Works on macOS, Linux, and Windows."
---

# API Design

Aim for boring, predictable APIs. Consistency beats cleverness — a caller should be able
to guess the next endpoint.

## Resources & methods

- Name resources as plural nouns: `/users`, `/users/{id}`, `/users/{id}/orders`.
- Map methods to intent: `GET` (read, safe), `POST` (create/action), `PUT` (full replace),
  `PATCH` (partial update), `DELETE` (remove). GET/PUT/DELETE should be idempotent.
- Avoid verbs in paths (`/createUser` ✗). For non-CRUD actions, POST a sub-resource
  (`POST /orders/{id}/refund`).

## Status codes (use the right one)

- 200 OK, 201 Created (+ `Location`), 202 Accepted (async), 204 No Content.
- 400 bad input, 401 unauthenticated, 403 forbidden, 404 not found, 409 conflict,
  422 validation failed, 429 rate-limited (+ `Retry-After`).
- 500 server error (never leak internals), 503 unavailable.

## Consistent shapes

```json
// Error envelope — same shape everywhere
{ "error": { "code": "invalid_amount", "message": "amount must be > 0", "field": "amount" } }

// List with pagination
{ "data": [ ... ], "next_cursor": "abc123", "has_more": true }
```

## Guidance

- Prefer **cursor** pagination over offset for large/changing sets.
- Version explicitly (`/v1/...` or a header); never break v1 callers silently.
- Use ISO 8601 timestamps, consistent snake_case or camelCase (pick one), and stable IDs.
- Validate input and return 4xx with a precise message; reserve 5xx for real server faults.
- Make writes idempotent where possible (idempotency keys for POST that creates money/orders).
- Document each endpoint: method, path, params, example request/response, error cases.
