# OpenGate API - NPM Package

A free API that lets users do more with less effort.

## Install

```bash
npm install opengate-api
```

## Usage

```javascript
const OpenGate = require('opengate-api');
const api = new OpenGate();

// AI Text Generation
const text = await api.aiText('Hello world');

// Get AI Image URL
const imageUrl = api.getAiImageUrl('a beautiful sunset', { width: 1024 });

// Rewrite text
const rewritten = await api.aiRewrite('Hello world', 'casual');

// Summarize URL
const summary = await api.aiSummarize({ url: 'https://example.com' });

// Get favicon
const favicon = await api.favicon('https://github.com');

// Generate data
const name = await api.socialGenerate('name');

// Text utilities
const slug = await api.slug('Hello World');
const hash = await api.hash('password', 'sha256');
const uuid = await api.uuid();
```

## API Endpoints

### AI Endpoints
- `/ai-text?prompt=` - AI text generation
- `/ai-image?prompt=` - AI image generation
- `/ai-rewrite?text=&tone=` - Rewrite text with tone
- `/ai-summarize?text=` or `?url=` - Summarize content
- `/models` - List AI models
- `/ai-rewrite-tones` - List rewrite tones

### Utility Endpoints
- `/fetch?url=` - CORS proxy
- `/favicon?url=` - Get favicon URL
- `/slug?text=` - URL slug generator
- `/base64?text=` - Base64 encode/decode
- `/uuid` - Generate UUIDs
- `/hash?text=` - Hash generator
- `/social/generate?type=` - Generate fake data
- `/word?text=` - Dictionary lookup
- `/joke` - Random jokes

## Custom Base URL

```javascript
const api = new OpenGate('https://your-custom-deployment.com');
```
