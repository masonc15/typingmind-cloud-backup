# S3 to Dropbox API Mapping

## Core Method Mappings

### S3Service → DropboxService

| S3 Method | S3 API | Dropbox Method | Dropbox API | Notes |
|-----------|--------|----------------|-------------|-------|
| `initialize()` | AWS SDK initialization | `initialize()` | Create `Dropbox` instance | Use access token instead of AWS credentials |
| `loadSDK()` | Load AWS SDK from CDN | `loadSDK()` | Load Dropbox SDK from CDN | Change SDK URL |
| `upload(key, data, isMetadata, itemKey)` | `s3.upload()` | `upload(key, data, isMetadata, itemKey)` | `dbx.filesUpload()` | Convert key to path (add `/` prefix) |
| `uploadRaw(key, data)` | `s3.upload()` | `uploadRaw(key, data)` | `dbx.filesUpload()` | No encryption |
| `download(key, isMetadata)` | `s3.getObject()` | `download(key, isMetadata)` | `dbx.filesDownload()` | Returns file blob, need to read |
| `downloadRaw(key)` | `s3.getObject()` | `downloadRaw(key)` | `dbx.filesDownload()` | Returns file blob |
| `delete(key)` | `s3.deleteObject()` | `delete(key)` | `dbx.filesDeleteV2()` | Path format required |
| `list(prefix)` | `s3.listObjectsV2()` | `list(prefix)` | `dbx.filesListFolder()` | Handle pagination with cursor |
| `downloadWithResponse(key)` | `s3.getObject()` | `downloadWithResponse(key)` | `dbx.filesDownload()` | Return full response object |
| `copyObject(source, dest)` | `s3.copyObject()` | `copyObject(source, dest)` | `dbx.filesCopyV2()` | Server-side copy |

### New Methods for Batch Operations

| Method | Dropbox API | Purpose |
|--------|-------------|---------|
| `copyBatch(entries)` | `dbx.filesCopyBatchV2()` | Copy multiple files server-side |
| `copyBatchCheck(asyncJobId)` | `dbx.filesCopyBatchCheckV2()` | Check batch copy status |
| `deleteBatch(entries)` | `dbx.filesDeleteBatch()` | Delete multiple files |

## Path Conversions

### S3 → Dropbox Path Format

| S3 Path | Dropbox Path | Notes |
|---------|--------------|-------|
| `metadata.json` | `/metadata.json` | Add leading slash |
| `items/CHAT_xxx.enc` | `/items/CHAT_xxx.enc` | Add leading slash |
| `backups/daily-20231027/` | `/backups/daily-20231027` | Add leading slash, remove trailing slash |
| `` (empty, for list root) | `` (empty string) | Root folder listing |

### Important Path Rules
- Dropbox paths must start with `/` (except empty string for root)
- Dropbox paths must NOT end with `/` for files
- Dropbox folders don't have trailing `/`
- Empty string `""` represents root folder in list operations

## Error Code Mappings

| S3 Error | S3 Code | Dropbox Error | Dropbox Code | Notes |
|----------|---------|---------------|--------------|-------|
| Not Found | 404 / NoSuchKey | Not Found | 409 (path/not_found) | Different error structure |
| Rate Limited | 429 | Rate Limited | 429 | Both use 429 |
| Unauthorized | 401 | Unauthorized | 401 | Token invalid |
| Storage Quota | N/A | Over Quota | 507 | Insufficient storage |
| Conflict | N/A | Conflict | 409 (path/conflict) | File already exists |

## Authentication Differences

### S3 (AWS SDK)
```javascript
AWS.config.update({
  accessKeyId: accessKey,
  secretAccessKey: secretKey,
  region: region
});
const s3 = new AWS.S3();
```

### Dropbox (SDK)
```javascript
const dbx = new Dropbox({
  accessToken: accessToken,
  fetch: fetch  // Required for browser
});
```

## SDK Loading

### S3
- URL: `https://sdk.amazonaws.com/js/aws-sdk-2.1692.0.min.js`
- Global: `window.AWS`

### Dropbox
- URL: `https://unpkg.com/dropbox@10.34.0/dist/Dropbox-sdk.min.js`
- Global: `window.Dropbox`
- Note: May need isomorphic-fetch polyfill

## API Response Differences

### Upload Response
**S3:** Returns `{ ETag, Location, Bucket, Key }`
**Dropbox:** Returns `{ name, path_lower, path_display, id, ... }`

### Download Response
**S3:** Returns `{ Body, ContentType, ETag, LastModified, ... }`
**Dropbox:** Returns `{ name, path_lower, ..., fileBlob }` - blob in separate property

### List Response
**S3:** Returns `{ Contents: [{ Key, Size, LastModified, ETag }], IsTruncated, NextContinuationToken }`
**Dropbox:** Returns `{ entries: [{ .tag, name, path_lower, path_display }], cursor, has_more }`

## Batch Operations

### Dropbox Batch Copy Flow
```javascript
// 1. Start batch copy
const response = await dbx.filesCopyBatchV2({
  entries: [
    { from_path: '/items/file1.enc', to_path: '/backup/items/file1.enc' },
    { from_path: '/items/file2.enc', to_path: '/backup/items/file2.enc' }
  ],
  autorename: false
});

// 2. Check if async job started
if (response.result['.tag'] === 'async_job_id') {
  // 3. Poll for completion
  const jobId = response.result.async_job_id;
  const checkResponse = await dbx.filesCopyBatchCheckV2({ async_job_id: jobId });
  // Check checkResponse.result['.tag'] for 'complete' or 'in_progress'
}
```

## Configuration Changes

### S3 Config
```javascript
{
  bucketName: "string",
  region: "string",
  accessKey: "string",
  secretKey: "string",
  endpoint: "string" (optional),
  encryptionKey: "string"
}
```

### Dropbox Config
```javascript
{
  appKey: "string",         // Dropbox App Key
  accessToken: "string",    // OAuth access token
  refreshToken: "string",   // OAuth refresh token
  tokenExpiry: "number",    // Timestamp when token expires
  encryptionKey: "string"   // Keep encryption!
}
```

## OAuth Flow (PKCE)

### Steps
1. Generate code verifier (128 random chars)
2. Generate code challenge (SHA256 of verifier, base64 encoded)
3. Redirect to Dropbox authorization URL with challenge
4. User authorizes app
5. Dropbox redirects back with authorization code
6. Exchange code for access token using verifier
7. Store access token and refresh token

### Key URLs
- Authorization: `https://www.dropbox.com/oauth2/authorize`
- Token Exchange: `https://api.dropboxapi.com/oauth2/token`

## Rate Limiting

### Dropbox Rate Limits
- Per-user rate limiting
- Returns 429 with `Retry-After` header
- Implement exponential backoff (already exists in `withRetry`)

## Storage Limits

- Free tier: 2GB (vs S3/R2 which varies)
- Need to handle 507 errors for over-quota situations
- Typical TypingMind data: < 50MB (well within limit)

## Implementation Priority

1. **Critical (Must have for MVP)**
   - initialize(), loadSDK()
   - upload(), download()
   - list(), delete()
   - OAuth authentication flow

2. **Important (Needed for full functionality)**
   - copyObject() for server-side backups
   - copyBatch() for efficient batch operations
   - Error handling and retries
   - Token refresh logic

3. **Nice to have (Enhancements)**
   - Better rate limit handling using Retry-After
   - Streaming for large files
   - Progress callbacks for uploads/downloads
