# OpenGate API V2.0

A free API that lets users do more with less effort.


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
## Utility Endpoints

**/timestamp** - Returns current time in multiple formats
```bash
curl "https://opengate-8dyx.onrender.com/timestamp"
```
Returns: `{ "iso": "...", "utc": "...", "unix": ..., "readable": "...", "unix_seconds": ... }`

**/ip** - Returns user's IP address
```bash
curl "https://opengate-8dyx.onrender.com/ip"
```

**/location** - Returns user's location via IP address
```bash
curl "https://opengate-8dyx.onrender.com/location"
```
Returns: `{ "ip": "...", "country": "...", "city": "...", "latitude": ..., "longitude": ..., "timezone": "..." }`

**/timezone** - Returns user's timezone
```bash
curl "https://opengate-8dyx.onrender.com/timezone"
```

**/slug?text=** - Converts text to URL slugs
```bash
curl "https://opengate-8dyx.onrender.com/slug?text=Hello%20World"
# Returns: { "input": "Hello World", "slug": "hello-world" }
```

**/scrape?url=** - Returns headers, links, and title from a URL
```bash
curl "https://opengate-8dyx.onrender.com/scrape?url=https://example.com"
```
Returns: `{ "url": "...", "title": "...", "description": "...", "links": [...], "h1s": [...], "link_count": ... }`

**/ping?url=** - Measures response time for a URL
```bash
curl "https://opengate-8dyx.onrender.com/ping?url=https://example.com"
```
Returns: `{ "url": "...", "status": 200, "response_time_ms": ..., "response_time_seconds": ... }`

**/count-text?text=** - Returns character count, word count, and sentence count
```bash
curl "https://opengate-8dyx.onrender.com/count-text?text=Hello%20world."
```
Returns: `{ "text": "...", "characters": ..., "words": ..., "sentences": ..., "paragraphs": ... }`

**/hex-to-colour?hex=** - Returns colour name from hex code
```bash
curl "https://opengate-8dyx.onrender.com/hex-to-colour?hex=FF0000"
```
Returns: `{ "hex": "#FF0000", "rgb": "rgb(255, 0, 0)", "colour_name": "Red" }`

**/sanitize?text=** - Removes unsafe characters
```bash
curl "https://opengate-8dyx.onrender.com/sanitize?text=<script>alert('xss')</script>"
```
Returns: `{ "original": "...", "sanitized": "scriptalert(xss)/script" }`

**/delay?ms=** - Simulates API delay (max 30000ms)
```bash
curl "https://opengate-8dyx.onrender.com/delay?ms=2000"
```
Returns: `{ "delayed_ms": 2000, "message": "Delayed for 2000 milliseconds" }`

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
- ✓ /yt-audio?url= (Convert a youtube video into .webm for playback
- ✓ /timestamp (Returns current time in multiple formats
- ✓ /ip (Returns users IP address
- ✓ /location (Returns users location via IP address
- ✓ /timezone (Returns users timezone
- ✓ /slug?text= (Converts text to URL slugs
- ✓ /scrape?url= (Returns headers, links, title
- ✓ /ping?url= (Response time from site
- ✓ /count-text?text= (Character, word, sentence count
- ✓ /hex-to-colour?hex= (Hex to colour name
- ✓ /sanitize?text= (Removes unsafe characters
- ✓ /delay?ms= (Simulates API delay
- /convert?from=mp4&to=mp3 (Convert file types)
- /Ai?prompt=Hey (sends a request to an ai model and sends response

## License

MIT
