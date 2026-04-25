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
## YouTube Audio

**/yt-audio** Download YouTube videos as audio files (.webm format).

**Query Parameters:**
- `?url=` (required) - The YouTube video URL

**Example:**
```bash
curl "https://opengate-8dyx.onrender.com/yt-audio?url=https://www.youtube.com/watch?v=dQw4w9WgXcQ" \
  -o audio.webm
```

**Supported URLs:**
- `youtube.com/watch?v=...`
- `youtu.be/...`
- `youtube.com/embed/...`
- `youtube.com/shorts/...`

**Returns:** Audio file with `Content-Type: audio/webm` (or other available audio format)

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
- /convert?from=mp4&to=mp3 (Convert file types)
- /Ai?prompt=Hey (sends a request to an ai model and sends response

## License

MIT
