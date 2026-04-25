# OpenGate API V2.0

A free API that lets users do more with less effort.


Open **`http://localhost:3000/`** in your browser to access the interactive test interface.

## Quick Tests

Click the buttons below to test different features:

[![Load a website](https://img.shields.io/badge/Load-Website-blue?style=for-the-badge)](https://opengate-8dyx.onrender.com/fetch?url=https://example.com&rewrite=true)

[![Generate a random name](https://img.shields.io/badge/Random-Name-green?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=name)

[![Generate a random email](https://img.shields.io/badge/Random-Email-orange?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=email)

[![Generate a random phone number](https://img.shields.io/badge/Random-Phone-red?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=phone)

[![Generate a random username](https://img.shields.io/badge/Random-Username-purple?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=username)


### Features:

## Fetch 
- **/fetch** - Fetch any URL with query parameter
- **Example** - https://opengate-8dyx.onrender.com/fetch?url=https://example.com&rewrite=true
----------------------------------------------------------------------------------------------------
## Screenshot - WIP

**/screenshot** Capture a screenshot of a webpage using Puppeteer.

**Query Parameters:**
- `?url=` (required) - The target URL to screenshot
- `&width=` (optional) - Viewport width in pixels (default: `1920`)
- `&height=` (optional) - Viewport height in pixels (default: `1080`)
- `&fullPage` (optional) - Set to `true` for full page screenshot (default: `false`)
- `&waitFor=` (optional) - Milliseconds to wait after load (default: `3000`)
- `&selector=` (optional) - Wait for specific CSS selector before screenshot

**Example:**
```example
curl "http://opengate-8dyx.onrender.com/screenshot?url=https://example.com" \
  -o screenshot.png
```

**Full page screenshot:**
```bash
curl "http://opengate-8dyx.onrender.com/screenshot?url=https://example.com&fullPage=true" \
  -o fullpage.png
```

**Custom viewport:**
```bash
curl "http://opengate-8dyx.onrender.com/screenshot?url=https://example.com&width=1280&height=720" \
  -o mobile.png
```

**Returns:** PNG image with `Content-Type: image/png`

### Health

**/health** - Health check endpoint.

**Example:**
```URL
Https://opengate-8dyx.onrender.com/health
```
---------------------------------------------------------------------------------------
### Social Generations

Generate fake social data (emails, phone numbers, names, usernames).

**Query Parameters:**
- `?type=` (required) - Types to generate: `email`, `phone`, `name`, `username`
- `&count=` (optional) - Number of items (max 100, default: 1)

**Example:**
```URL
# Generate 1 fake email
http://https://opengate-8dyx.onrender.com/social/generate?type=email

# Generate 5 fake phone numbers
http://https://opengate-8dyx.onrender.com/social/generate?type=phone&count=5
```


### /text/parse-entities

Extract entities (emails, phones, URLs, names, dates) from text.

**Request Body:**
```json
{
  "text": "My email is bluh@bluh.com and my number is +1 234 334 343"
}
```

**Example:**
```Curl
curl -X POST "http://https://opengate-8dyx.onrender.com/text/parse-entities" \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact Monkey@OpenGate.com or call +1 604 674 6331"}'
```

**Response:**
```json
{
  "text": "Contact Monkey@OpenGate.com or call +1 604 674 6331",
  "emails": ["Monkey@OpenGate.com"],
  "phones": ["+1 604 674 6331"],
  "urls": [],
  "names": [],
  "dates": []
}
```



## Error Responses

All errors return JSON with `error` and optional `details`:

Common status codes:
- `400` - Bad request (invalid URL, method, etc.)
- `403` - Blocked domain (e.g., YouTube, Netflix)
- `429` - Rate limit exceeded
- `502` - Failed to fetch target URL

## Limitations

- **YouTube is blocked** - Returns error "YouTube's homepage is not available through this proxy"
- **Netflix and other streaming sites** are blocked due to DRM and complexity
- **WebSockets** are not proxied...yet
- **Streaming video** may have issues due to buffering and range requests
- **Sites with strict CSP headers** may block proxied resources - fixing

### Next Features: 

- Better CSS handling
- /yt-audio?url= (Convert a youtube video into .webm for playback
- /convert?from=mp4&to=mp3 (Convert file types)
- /Ai?prompt=Hey (sends a request to an ai model and sends response

## License

MIT
