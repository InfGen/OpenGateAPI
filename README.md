# OpenGate API V2.0

A free API that lets users do more with less effort.


## Quick Tests

Click the buttons below to test different features:

[![Load a website](https://img.shields.io/badge/Load-Website-blue?style=for-the-badge)](https://opengate-8dyx.onrender.com/fetch?url=https://example.com&rewrite=true)

[![Generate a random name](https://img.shields.io/badge/Random-Name-green?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=name)

[![Generate a random email](https://img.shields.io/badge/Random-Email-orange?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=email)

[![Generate a random phone number](https://img.shields.io/badge/Random-Phone-red?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=phone)

[![Generate a random username](https://img.shields.io/badge/Random-Username-purple?style=for-the-badge)](https://opengate-8dyx.onrender.com/social/generate?type=username)

---

## Fetch Endpoint

**/fetch** - Fetch any URL with CORS headers and optional HTML rewriting.

```bash
curl "https://opengate-8dyx.onrender.com/fetch?url=https://example.com&rewrite=true"
```

**Query Parameters:**
- `?url=` (required) - The URL to fetch
- `&rewrite=` (optional) - Rewrite HTML to proxy resources through the API

---

## Utility Endpoints

### /timestamp
Returns current time in multiple formats.

```bash
curl "https://opengate-8dyx.onrender.com/timestamp"
```

**Response:**
```json
{
  "iso": "2024-01-15T10:30:00.000Z",
  "utc": "Mon, 15 Jan 2024 10:30:00 GMT",
  "unix": 1705315800000,
  "readable": "1/15/2024, 10:30:00 AM",
  "unix_seconds": 1705315800
}
```

---

### /ip
Returns your IP address.

```bash
curl "https://opengate-8dyx.onrender.com/ip"
```

**Response:**
```json
{ "ip": "203.0.113.42" }
```

---

### /location
Returns your location based on IP address.

```bash
curl "https://opengate-8dyx.onrender.com/location"
```

**Response:**
```json
{
  "ip": "203.0.113.42",
  "country": "United States",
  "countryCode": "US",
  "region": "California",
  "city": "San Francisco",
  "zip": "94102",
  "latitude": 37.7749,
  "longitude": -122.4194,
  "timezone": "America/Los_Angeles"
}
```

---

### /timezone
Returns your timezone information.

```bash
curl "https://opengate-8dyx.onrender.com/timezone"
```

**Response:**
```json
{
  "timezone": "America/New_York",
  "offset": -300,
  "offset_hours": -5,
  "abbr": "EST"
}
```

---

### /slug
Converts text to URL-friendly slugs.

```bash
curl "https://opengate-8dyx.onrender.com/slug?text=Hello%20World"
```

**Response:**
```json
{
  "input": "Hello World",
  "slug": "hello-world"
}
```

---

### /scrape
Extracts metadata from a webpage (title, description, links, headers).

```bash
curl "https://opengate-8dyx.onrender.com/scrape?url=https://example.com"
```

**Response:**
```json
{
  "url": "https://example.com",
  "title": "Example Domain",
  "description": "Example domain description",
  "links": ["https://www.iana.org/domains/example"],
  "h1s": ["Example Domain"],
  "h2s": [],
  "link_count": 1
}
```

---

### /ping
Measures response time for a URL.

```bash
curl "https://opengate-8dyx.onrender.com/ping?url=https://example.com"
```

**Response:**
```json
{
  "url": "https://example.com",
  "status": 200,
  "response_time_ms": 145,
  "response_time_seconds": 0.145
}
```

---

### /count-text
Analyzes text and returns counts.

```bash
curl "https://opengate-8dyx.onrender.com/count-text?text=Hello%20world.%20How%20are%20you?"
```

**Response:**
```json
{
  "text": "Hello world. How are you?",
  "characters": 26,
  "words": 5,
  "sentences": 2,
  "paragraphs": 1
}
```

---

### /uuid
Generate UUIDs.

```bash
curl "https://opengate-8dyx.onrender.com/uuid"
```

---

### /base64
Encode or decode base64.

```bash
# Encode
curl "https://opengate-8dyx.onrender.com/base64?text=Hello"

# Decode
curl "https://opengate-8dyx.onrender.com/base64?text=SGVsbG8=&decode=true"
```

---

### /hash
Generate hash of text.

```bash
curl "https://opengate-8dyx.onrender.com/hash?text=Hello&type=sha256"
```

---

### /json-format
Format or validate JSON.

```bash
curl "https://opengate-8dyx.onrender.com/json-format?text=%7B%22a%22:1%7D"
```

---

### /random
Generate random values.

```bash
# Random number
curl "https://opengate-8dyx.onrender.com/random?type=number&min=1&max=100"

# Random password
curl "https://opengate-8dyx.onrender.com/random?type=password&length=16"

# Random choice
curl "https://opengate-8dyx.onrender.com/random?type=choice&options=cat,dog,bird"
```

---

### /jwt-decode
Decode JWT tokens.

```bash
curl "https://opengate-8dyx.onrender.com/jwt-decode?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
```

---

### /color-convert
Convert between color formats.

```bash
# From hex
curl "https://opengate-8dyx.onrender.com/color-convert?hex=FF0000"

# From RGB
curl "https://opengate-8dyx.onrender.com/color-convert?rgb=255,0,0"

# From HSL
curl "https://opengate-8dyx.onrender.com/color-convert?hsl=0,100,50"
```

---

### /joke
Get a random joke.

```bash
curl "https://opengate-8dyx.onrender.com/joke"
```

---

### /word
Dictionary lookup.

```bash
curl "https://opengate-8dyx.onrender.com/word?text=hello"
```

---

### /hex-to-colour
Converts hex color codes to colour names.

```bash
curl "https://opengate-8dyx.onrender.com/hex-to-colour?hex=FF0000"
```

**Response:**
```json
{
  "hex": "#FF0000",
  "rgb": "rgb(255, 0, 0)",
  "colour_name": "Red"
}
```

---

### /sanitize
Removes unsafe characters from text.

```bash
curl "https://opengate-8dyx.onrender.com/sanitize?text=<script>alert('xss')</script>"
```

**Response:**
```json
{
  "original": "<script>alert('xss')</script>",
  "sanitized": "scriptalert(xss)/script"
}
```

---

### /delay
Simulates an API delay for testing.

```bash
curl "https://opengate-8dyx.onrender.com/delay?ms=2000"
```

**Response:**
```json
{
  "delayed_ms": 2000,
  "message": "Delayed for 2000 milliseconds"
}
```

---

## Health Check

**/health** - Check if the API is running.

```bash
curl "https://opengate-8dyx.onrender.com/health"
```

---

## Social Generations

**/social/generate** - Generate fake social data.

```bash
# Generate a random email
curl "https://opengate-8dyx.onrender.com/social/generate?type=email"

# Generate 5 fake phone numbers
curl "https://opengate-8dyx.onrender.com/social/generate?type=phone&count=5"
```

**Query Parameters:**
- `?type=` (required) - Type to generate: `email`, `phone`, `name`, `username`
- `&count=` (optional) - Number of items (max 100, default: 1)

---

## Text Utilities

### /text/parse-entities
Extracts entities (emails, phones, URLs, names, dates) from text.

```bash
curl -X POST "https://opengate-8dyx.onrender.com/text/parse-entities" \
  -H "Content-Type: application/json" \
  -d '{"text": "Contact us at hello@example.com or call +1 555 123 4567"}'
```

**Response:**
```json
{
  "text": "Contact us at hello@example.com or call +1 555 123 4567",
  "emails": ["hello@example.com"],
  "phones": ["+1 555 123 4567"],
  "urls": [],
  "names": [],
  "dates": []
}
```

---

## Error Responses

All errors return JSON with `error` and optional `details`:

- `400` - Bad request (invalid URL, missing parameters)
- `403` - Blocked domain
- `429` - Rate limit exceeded
- `500` - Internal server error
- `502` - Failed to fetch target URL

---

## Limitations

- **YouTube is blocked** - Returns error for YouTube URLs
- **Netflix and streaming sites** are blocked due to DRM
- **Rate limit** - 60 requests per minute per IP

---

## License

MIT
