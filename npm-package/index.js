/**
 * OpenGate API - A free API that lets users do more with less effort
 * 
 * Install: npm install opengate-api
 * Usage: const opengate = require('opengate-api');
 *        // Access endpoints via https://api.opengate.dev or your own deployment
 */

const BASE_URL = process.env.OPENGATE_BASE_URL || 'https://opengate-8dyx.onrender.com';

class OpenGateAPI {
  constructor(baseUrl = BASE_URL) {
    this.baseUrl = baseUrl;
  }

  // Fetch any URL with CORS support
  async fetch(url, options = {}) {
    const params = new URLSearchParams({ url });
    if (options.rewrite) params.set('rewrite', 'true');
    if (options.stream) params.set('stream', 'true');
    const response = await fetch(`${this.baseUrl}/fetch?${params}`);
    return response;
  }

  // Generate AI text
  async aiText(prompt, model = 'openai') {
    const params = new URLSearchParams({ prompt, model });
    const response = await fetch(`${this.baseUrl}/ai-text?${params}`);
    return response.json();
  }

  // Generate AI image (returns URL)
  getAiImageUrl(prompt, options = {}) {
    const params = new URLSearchParams({ prompt, ...options });
    return `${this.baseUrl}/ai-image?${params}`;
  }

  // Generate AI image (returns buffer)
  async aiImage(prompt, options = {}) {
    const params = new URLSearchParams({ prompt, ...options });
    const response = await fetch(`${this.baseUrl}/ai-image?${params}`);
    return response.buffer();
  }

  // Rewrite text with tone
  async aiRewrite(text, tone = 'professional') {
    const params = new URLSearchParams({ text, tone });
    const response = await fetch(`${this.baseUrl}/ai-rewrite?${params}`);
    return response.json();
  }

  // Summarize text or URL
  async aiSummarize(options = {}) {
    const params = new URLSearchParams(options);
    const response = await fetch(`${this.baseUrl}/ai-summarize?${params}`);
    return response.json();
  }

  // Get favicon URL
  async favicon(url) {
    const params = new URLSearchParams({ url });
    const response = await fetch(`${this.baseUrl}/favicon?${params}`);
    return response.json();
  }

  // Generate random data
  async socialGenerate(type, count = 1) {
    const params = new URLSearchParams({ type, count });
    const response = await fetch(`${this.baseUrl}/social/generate?${params}`);
    return response.json();
  }

  // Text utilities
  async slug(text) {
    const params = new URLSearchParams({ text });
    const response = await fetch(`${this.baseUrl}/slug?${params}`);
    return response.json();
  }

  async base64(text, decode = false) {
    const params = new URLSearchParams({ text, decode: decode.toString() });
    const response = await fetch(`${this.baseUrl}/base64?${params}`);
    return response.json();
  }

  async uuid(count = 1) {
    const params = new URLSearchParams({ count: count.toString() });
    const response = await fetch(`${this.baseUrl}/uuid?${params}`);
    return response.json();
  }

  async hash(text, type = 'sha256') {
    const params = new URLSearchParams({ text, type });
    const response = await fetch(`${this.baseUrl}/hash?${params}`);
    return response.json();
  }

  // Info endpoints
  async models() {
    const response = await fetch(`${this.baseUrl}/models`);
    return response.json();
  }

  async aiRewriteTones() {
    const response = await fetch(`${this.baseUrl}/ai-rewrite-tones`);
    return response.json();
  }

  async aiImageInfo() {
    const response = await fetch(`${this.baseUrl}/ai-image-info`);
    return response.json();
  }
}

module.exports = OpenGateAPI;
