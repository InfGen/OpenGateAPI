# Secure CORS Proxy API

A secure Node.js proxy API that enables frontend-only applications to fetch content from external websites that normally block requests due to CORS restrictions.

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
node server.js

# Or use watch mode (Node.js 18+)
npm run dev
```

The server will start on `http://localhost:3000`.

Open **`http://localhost:3000/`** in your browser to access the interactive test interface.

## Deploy to Render

Click the button below to deploy instantly to Render:

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/InfGen/FreeAPI)

Or deploy manually:
1. Push this repo to GitHub
2. Create a new Web Service on Render
3. Connect your GitHub repo
4. Use these settings:
   - **Build Command:** `npm install`
   - **Start Command:** `npm start`
   - **Environment:** Node

## Features

### Core Features
- **GET /fetch** - Fetch any URL with query parameter
- **CORS enabled** - Allow all origins (`*`)
- **Content type preservation** - JSON, HTML, text, etc.

### Security Features
- URL validation (http/https only)
- Blocks dangerous targets:
  - localhost, 127.0.0.1, 0.0.0.0
  - Internal IP ranges (192.168.x.x, 10.x.x.x, 172.16.x.x)
  - file:// protocol
- Domain allowlist - only allowed domains can be accessed
- Sanitized headers (no cookies/auth forwarding)
- Safe User-Agent

### Rate Limiting
- 60 requests per minute per IP
- Returns 429 status when exceeded

### Advanced Features
- **POST /fetch** - Supports custom methods, headers, and body
- **GET /screenshot** - Capture webpage screenshots with Puppeteer
- **HTML Rewrite Mode** - Proxy resources through the API
- **Request logging** - Timestamps and IP logging

## API Endpoints

### GET /fetch

Fetch content from a URL.

**Query Parameters:**
- `url` (required) - The target URL to fetch
- `rewrite` (optional) - Set to `true` to rewrite HTML resources

**Example:**
```bash
curl "http://localhost:3000/fetch?url=https://example.com"
```

**With HTML rewrite:**
```bash
curl "http://localhost:3000/fetch?url=https://example.com&rewrite=true"
```

The `rewrite=true` parameter rewrites all resource URLs in the HTML to proxy through this API:
- `src` attributes (images, scripts, iframes, videos)
- `href` attributes (links, stylesheets)
- `srcset` and `data-srcset` (responsive images)
- `data-src` (lazy-loaded images)
- `poster` (video thumbnails)
- `action` (form submissions)
- CSS `url()` in inline styles and `<style>` tags
- CSS `@import` rules

### POST /fetch

Advanced fetch with custom options.

**Request Body:**
```json
{
  "url": "https://api.example.com/data",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"key\": \"value\"}"
}
```

**Example:**
```bash
curl -X POST "http://localhost:3000/fetch" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://httpbin.org/post",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body": "{\"test\": \"data\"}"
  }'
```

### GET /screenshot

Capture a screenshot of a webpage using Puppeteer.

**Query Parameters:**
- `url` (required) - The target URL to screenshot
- `width` (optional) - Viewport width in pixels (default: 1920)
- `height` (optional) - Viewport height in pixels (default: 1080)
- `fullPage` (optional) - Set to `true` for full page screenshot (default: false)
- `waitFor` (optional) - Milliseconds to wait after load (default: 3000)
- `selector` (optional) - Wait for specific CSS selector before screenshot

**Example:**
```bash
curl "http://localhost:3000/screenshot?url=https://example.com" \
  -o screenshot.png
```

**Full page screenshot:**
```bash
curl "http://localhost:3000/screenshot?url=https://example.com&fullPage=true" \
  -o fullpage.png
```

**Custom viewport:**
```bash
curl "http://localhost:3000/screenshot?url=https://example.com&width=1280&height=720" \
  -o mobile.png
```

**Returns:** PNG image with `Content-Type: image/png`

### GET /health

Health check endpoint.

**Example:**
```bash
curl "http://localhost:3000/health"
```

### GET /social/generate

Generate fake social data (emails, phone numbers, names, usernames).

**Query Parameters:**
- `type` (required) - Type to generate: `email`, `phone`, `name`, `username`
- `count` (optional) - Number of items (max 100, default: 1)

**Example:**
```bash
# Generate 1 fake email
curl "http://localhost:3000/social/generate?type=email"

# Generate 5 fake phone numbers
curl "http://localhost:3000/social/generate?type=phone&count=5"
```

**Response:**
```json
{
  "type": "email",
  "count": 1,
  "data": "john.smith123@gmail.com"
}
```

### POST /text/parse-entities

Extract entities (emails, phones, URLs, names, dates) from text.

**Request Body:**
```json
{
  "text": "My email is bluh@bluh.com and my number is +1 234 334 343"
}
```

**Example:**
```bash
curl -X POST "http://localhost:3000/text/parse-entities" \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact john@example.com or call +1 555 123 4567"}'
```

**Response:**
```json
{
  "text": "Contact john@example.com or call +1 555 123 4567",
  "emails": ["john@example.com"],
  "phones": ["+1 555 123 4567"],
  "urls": [],
  "names": [],
  "dates": []
}
```

## Configuration

### Domain Allowlist (Optional)

By default, **all URLs are allowed**. To restrict to specific domains, edit `ALLOWED_DOMAINS` in `server.js`:

```javascript
const ALLOWED_DOMAINS = [
  'example.com',
  'api.github.com',
  // Add allowed domains here (empty array = allow all)
];
```

### Rate Limiting

Modify the rate limiter configuration:

```javascript
const limiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 60,              // requests per window
});
```

## Frontend Usage Example

```javascript
// Simple GET request
async function fetchThroughProxy(targetUrl) {
  const proxyUrl = `http://localhost:3000/fetch?url=${encodeURIComponent(targetUrl)}`;
  const response = await fetch(proxyUrl);
  return response.json();
}

// POST request with body
async function postThroughProxy(targetUrl, data) {
  const response = await fetch('http://localhost:3000/fetch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: targetUrl,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
  });
  return response.json();
}
```

## Error Responses

All errors return JSON with `error` and optional `details`:

```json
{
  "error": "Invalid or disallowed URL",
  "details": "URL must be a valid http/https URL and in the allowed domains list"
}
```

Common status codes:
- `400` - Bad request (invalid URL, method, etc.)
- `403` - Blocked domain (e.g., YouTube, Netflix)
- `429` - Rate limit exceeded
- `502` - Failed to fetch target URL

## Limitations

- **YouTube is blocked** - Returns error "YouTube's homepage is not available through this proxy"
- **Netflix and other streaming sites** are blocked due to DRM and complexity
- **WebSockets** are not proxied
- **Streaming video** may have issues due to buffering and range requests
- **Sites with strict CSP headers** may block proxied resources

## Security Considerations

1. **Always configure the domain allowlist** - Only add domains you trust
2. **Monitor logs** - Check for suspicious request patterns
3. **Use in development** - For production, consider adding authentication
4. **Rate limiting** - Adjust limits based on your use case

## Requirements

- Node.js >= 18.0.0

## License

MIT
