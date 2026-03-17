# Reverse Engineering Notes: `hottub.spacemoehre.de` API

## Scope

This document summarizes black-box API reconnaissance for:

- `https://hottub.spacemoehre.de/api/videos`
- supporting endpoint: `https://hottub.spacemoehre.de/api/status`

## High-level behavior

- `GET /` returns a redirect to a custom scheme (`hottub://source?...`), suggesting this service is intended to be consumed by a client app, not a normal browser flow.
- `/api/videos` rejects `GET` with `405 Method Not Allowed`.
- `/api/videos` accepts `POST` when the request is JSON.
- `/api/videos` returns `400 Content type error` when request body is not JSON.

## Request contract inferred for `/api/videos`

### Required transport

- Method: `POST`
- Header: `Content-Type: application/json`
- Body: JSON object (`{}` is valid)

### Error signatures

- Missing/incorrect content-type: `400` + `Content type error`
- Empty (non-JSON) body with JSON content type: `400` + JSON deserialize error text

### Accepted payload keys (inferred)

Empirically observed to alter results:

- `page` (number)
- `channel` (string)
- `query` (string)

## Response contract inferred for `/api/videos`

Top-level shape:

```json
{
  "pageInfo": {
    "hasNextPage": true,
    "resultsPerPage": 10
  },
  "items": [
    {
      "id": "...",
      "title": "...",
      "url": "...",
      "thumb": "...",
      "preview": "...",
      "channel": "...",
      "duration": 0,
      "isLive": false,
      "views": 0
    }
  ]
}
```

Notes:

- `items` is much larger than `resultsPerPage`; this suggests either an internal feed aggregation model or non-traditional pagination semantics.
- `id` format varies by source/channel.

## `/api/status` (capability discovery endpoint)

`/api/status` returns a large JSON descriptor containing:

- service metadata (`id`, `name`, `description`, branding fields)
- `channels[]` list with per-channel metadata and filter options
- subscription and NSFW capability flags

This endpoint appears to be the primary machine-readable schema/capability source for client UI construction.

## Minimal reproducible calls

```bash
# Fails: wrong method
curl -i https://hottub.spacemoehre.de/api/videos

# Works: JSON POST
curl -i -X POST \
  -H 'content-type: application/json' \
  --data '{}' \
  https://hottub.spacemoehre.de/api/videos

# Probe server-provided channel/filter metadata
curl -i https://hottub.spacemoehre.de/api/status
```

## Practical reverse-engineered client flow

1. Fetch `/api/status` once to get channel list + available options.
2. Build a JSON payload for `/api/videos`:
   - default discovery: `{}`
   - filter by source: `{"channel":"..."}`
   - text search: `{"query":"..."}`
   - page shift: `{"page":2}`
3. POST to `/api/videos` and render returned `items`.
4. Use `pageInfo.hasNextPage` as a continuation hint (treat semantics as advisory).

## Confidence and caveats

- Confidence is **high** for transport/method/content-type contract.
- Confidence is **medium** for full payload schema (additional keys may exist).
- Unknowns remain around auth/rate limits/premium-only filters and exact pagination semantics.
