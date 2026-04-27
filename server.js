const express = require('express');
const rateLimit = require('express-rate-limit');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// Configuration
// ============================================

// Get proxy base URL from request headers or default
function getProxyBase(req) {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'https';
  const host = req.headers.host || 'localhost:3000';
  return `${protocol}://${host}`;
}

// Domain allowlist - set to empty array to allow all domains
const ALLOWED_DOMAINS = [];

// Blocked domains with custom error messages
const BLOCKED_DOMAINS = {
  'youtube.com': 'YouTube\'s homepage is not available through this proxy.',
  'www.youtube.com': 'YouTube\'s homepage is not available through this proxy.',
  'm.youtube.com': 'YouTube\'s homepage is not available through this proxy.',
  'youtube-nocookie.com': 'YouTube is not available through this proxy.',
  'youtu.be': 'YouTube is not available through this proxy.',
};

// Blocked IP patterns (private/internal networks)
const BLOCKED_IP_PATTERNS = [
  /^127\./,                          // localhost (127.x.x.x)
  /^0\.0\.0\.0/,                      // 0.0.0.0
  /^10\./,                           // 10.x.x.x (Class A private)
  /^172\.(1[6-9]|2[0-9]|3[0-1])\./,   // 172.16.x.x - 172.31.x.x (Class B private)
  /^192\.168\./,                      // 192.168.x.x (Class C private)
  /^169\.254\./,                      // Link-local
  /^::1$/,                            // IPv6 localhost
  /^fc00:/i,                          // IPv6 private
  /^fe80:/i,                          // IPv6 link-local
];

// Browser-like User-Agent to prevent blocking
const BROWSER_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// ============================================
// Middleware
// ============================================

// Parse JSON bodies for POST requests
app.use(express.json());

// CORS middleware - allow all origins
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Logging middleware
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  console.log(`[${timestamp}] ${ip} - ${req.method} ${req.path}`);
  next();
});

// Rate limiting - 60 requests per minute per IP
// Skip rate limiting for proxied sub-resources (images, CSS, JS) to avoid counting them against the limit
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  message: {
    error: 'Rate limit exceeded',
    details: 'Too many requests from this IP, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Skip if this is an internal proxy request (rewritten resource)
    return req.query._proxy === '1';
  }
});
app.use(limiter);

// ============================================
// Security Functions
// ============================================

/**
 * Validates and parses a URL string
 * @param {string} urlString - The URL to validate
 * @returns {URL|null|object} - Parsed URL object, null if invalid, or object with error info if blocked
 */
function validateUrl(urlString) {
  if (!urlString || typeof urlString !== 'string') {
    return { valid: false, error: 'Invalid or missing URL' };
  }

  let parsed;
  try {
    parsed = new URL(urlString);
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }

  // Only allow http and https protocols
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: 'Only HTTP and HTTPS protocols are allowed' };
  }

  // Extract hostname for validation
  const hostname = parsed.hostname.toLowerCase();

  // Block localhost
  if (hostname === 'localhost' || hostname === 'localhost.localdomain') {
    return { valid: false, error: 'Localhost access is blocked' };
  }

  // Block by IP patterns
  if (BLOCKED_IP_PATTERNS.some(pattern => pattern.test(hostname))) {
    return { valid: false, error: 'Private/internal IP addresses are blocked' };
  }

  // Check blocked domains with specific error messages
  for (const [blockedDomain, errorMessage] of Object.entries(BLOCKED_DOMAINS)) {
    if (hostname === blockedDomain || hostname.endsWith('.' + blockedDomain)) {
      return { valid: false, error: errorMessage, blockedDomain: true };
    }
  }

  // Check domain allowlist (if configured)
  if (ALLOWED_DOMAINS.length > 0) {
    const isAllowed = ALLOWED_DOMAINS.some(domain => 
      hostname === domain || hostname.endsWith('.' + domain)
    );
    
    if (!isAllowed) {
      return { valid: false, error: 'Domain is not in the allowlist' };
    }
  }

  return parsed;
}

/**
 * Creates safe headers for the outgoing request
 * Removes sensitive headers and sets safe defaults
 * @param {object} customHeaders - Optional custom headers from request
 * @param {string} targetUrl - The target URL to fetch
 * @param {object} originalReq - Original Express request for forwarding Range headers
 * @returns {object} - Sanitized headers
 */
function createSafeHeaders(customHeaders = {}, targetUrl = '', originalReq = null) {
  // Headers that must never be forwarded
  const BLOCKED_HEADERS = [
    'cookie',
    'cookie2',
    'authorization',
    'proxy-authorization',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'forwarded',
    'via',
  ];

  // Determine content type from URL extension for Accept header
  const url = targetUrl.toLowerCase();
  let acceptHeader = '*/*';
  
  if (url.match(/\.(jpg|jpeg|png|gif|webp|svg|ico|bmp)(\?|$)/)) {
    acceptHeader = 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8';
  } else if (url.match(/\.(css)(\?|$)/)) {
    acceptHeader = 'text/css,*/*;q=0.1';
  } else if (url.match(/\.(js)(\?|$)/)) {
    acceptHeader = '*/*';
  } else if (url.match(/\.(html|htm)(\?|$)/)) {
    acceptHeader = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
  }

  const safeHeaders = {
    'User-Agent': BROWSER_USER_AGENT,
    'Accept': acceptHeader,
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Referer': targetUrl,
  };

  // Forward Range header for partial content requests (images, videos)
  if (originalReq && originalReq.headers['range']) {
    safeHeaders['Range'] = originalReq.headers['range'];
  }

  // Copy allowed custom headers
  for (const [key, value] of Object.entries(customHeaders)) {
    const lowerKey = key.toLowerCase();
    if (!BLOCKED_HEADERS.includes(lowerKey)) {
      safeHeaders[key] = value;
    }
  }

  return safeHeaders;
}

/**
 * Rewrites HTML content to proxy URLs through this API
 * Handles: src, href, srcset, data-src, poster, action, srcdoc, and CSS url()
 * Also removes/modifies CSP headers that block iframes
 * @param {string} html - The HTML content to rewrite
 * @param {string} baseUrl - The base URL of the fetched page
 * @returns {string} - Rewritten HTML
 */
function rewriteHtml(html, baseUrl) {
  const base = new URL(baseUrl);
  const baseOrigin = base.origin;
  
  // Helper to resolve relative URLs
  const resolveUrl = (url) => {
    try {
      // Skip data URIs, javascript:, mailto:, tel:
      if (url.startsWith('data:') || url.startsWith('javascript:') || 
          url.startsWith('mailto:') || url.startsWith('tel:') ||
          url.startsWith('#')) {
        return url;
      }
      return new URL(url, base).href;
    } catch {
      return url;
    }
  };
  
  // Helper to create proxy URL - add _proxy=1 marker to skip rate limiting for sub-resources
  const proxyUrl = (url) => `/fetch?url=${encodeURIComponent(resolveUrl(url))}&_proxy=1`;
  
  // Remove CSP meta tags that block iframes and scripts
  html = html.replace(/<meta[^>]+content-security-policy[^>]*>/gi, '<meta http-equiv="Content-Security-Policy" content="default-src * \'unsafe-inline\' \'unsafe-eval\' data: blob:;">');
  html = html.replace(/<meta[^>]+http-equiv=["']?content-security-policy["']?[^>]*>/gi, '');
  
  // Remove X-Frame-Options headers simulation via meta tag
  html = html.replace(/<meta[^>]+x-frame-options[^>]*>/gi, '');
  
  // Rewrite src attributes (images, scripts, iframes, videos, audio)
  html = html.replace(
    /\bsrc\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `src="${proxyUrl(url)}"`
  );
  
  // Rewrite srcdoc attributes (inline iframe content - convert to data URL with proxy)
  html = html.replace(
    /\bsrcdoc\s*=\s*["']([^"']+)["']/gi,
    (match, content) => {
      // Base64 encode the srcdoc content and wrap in srcdoc pointing to blob
      const encoded = Buffer.from(content).toString('base64');
      return `srcdoc="<meta http-equiv='Content-Security-Policy' content=\"default-src * 'unsafe-inline' 'unsafe-eval' data: blob:;\"><script>location.replace('data:text/html;base64,${encoded}');<\/script>"`
    }
  );
  
  // Rewrite srcset attributes (responsive images)
  html = html.replace(
    /\bsrcset\s*=\s*["']([^"']+)["']/gi,
    (match, srcset) => {
      const urls = srcset.split(',').map(part => {
        const [url, descriptor] = part.trim().split(/\s+/);
        return `${proxyUrl(url)}${descriptor ? ' ' + descriptor : ''}`;
      });
      return `srcset="${urls.join(', ')}"`;
    }
  );
  
  // Rewrite data-src attributes (lazy loading libraries)
  html = html.replace(
    /\bdata-src\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `data-src="${proxyUrl(url)}"`
  );
  
  // Rewrite data-srcset attributes (lazy responsive images)
  html = html.replace(
    /\bdata-srcset\s*=\s*["']([^"']+)["']/gi,
    (match, srcset) => {
      const urls = srcset.split(',').map(part => {
        const [url, descriptor] = part.trim().split(/\s+/);
        return `${proxyUrl(url)}${descriptor ? ' ' + descriptor : ''}`;
      });
      return `data-srcset="${urls.join(', ')}"`;
    }
  );
  
  // Rewrite poster attributes (video thumbnails)
  html = html.replace(
    /\bposter\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `poster="${proxyUrl(url)}"`
  );
  
  // Rewrite action attributes (forms)
  html = html.replace(
    /\baction\s*=\s*["']([^"']+)["']/gi,
    (match, url) => {
      if (url.startsWith('#') || url.startsWith('javascript:')) {
        return match;
      }
      return `action="${proxyUrl(url)}"`;
    }
  );
  
  // Rewrite background attribute (deprecated but still used)
  html = html.replace(
    /\bbackground\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `background="${proxyUrl(url)}"`
  );
  
  // Rewrite CSS url() references in inline styles
  html = html.replace(
    /style\s*=\s*["']([^"']*)["']/gi,
    (match, styleContent) => {
      const rewrittenStyle = styleContent.replace(
        /url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi,
        (urlMatch, url) => `url("${proxyUrl(url)}")`
      );
      return `style="${rewrittenStyle}"`;
    }
  );
  
  // Rewrite <style> tag contents
  html = html.replace(
    /(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
    (match, openTag, cssContent, closeTag) => {
      const rewrittenCss = cssContent.replace(
        /url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi,
        (urlMatch, url) => `url("${proxyUrl(url)}")`
      );
      // Also handle @import rules
      const rewrittenCssWithImports = rewrittenCss.replace(
        /@import\s+(?:url\s*\()?\s*["']([^"']+)["']\s*\)?/gi,
        (importMatch, url) => `@import url("${proxyUrl(url)}")`
      );
      return `${openTag}${rewrittenCssWithImports}${closeTag}`;
    }
  );
  
  // Inject base tag to fix relative URLs
  if (!html.includes('<base ')) {
    html = html.replace(/<head([^>]*)>/i, `<head$1><base href="${baseOrigin}/">`);
  }
  
  // Remove blocking scripts that check parent frame
  html = html.replace(/if\s*\([\"']?parent[\"']?\s*[!=]=?/g, 'if (false &&');
  html = html.replace(/if\s*\(window\s*!=\s*top\s*\)/g, 'if (false && window != top)');
  html = html.replace(/top\.location/g, 'location');
  
  // Rewrite href attributes (links, stylesheets, etc.)
  html = html.replace(
    /\bhref\s*=\s*["']([^"']+)["']/gi,
    (match, url) => {
      if (url.startsWith('#') || url.startsWith('javascript:') || 
          url.startsWith('mailto:') || url.startsWith('tel:')) {
        return match;
      }
      return `href="${proxyUrl(url)}"`;
    }
  );
  
  // Rewrite srcset attributes (responsive images)
  html = html.replace(
    /\bsrcset\s*=\s*["']([^"']+)["']/gi,
    (match, srcset) => {
      const urls = srcset.split(',').map(part => {
        const [url, descriptor] = part.trim().split(/\s+/);
        return `${proxyUrl(url)}${descriptor ? ' ' + descriptor : ''}`;
      });
      return `srcset="${urls.join(', ')}"`;
    }
  );
  
  // Rewrite data-src attributes (lazy loading libraries)
  html = html.replace(
    /\bdata-src\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `data-src="${proxyUrl(url)}"`
  );
  
  // Rewrite data-srcset attributes (lazy responsive images)
  html = html.replace(
    /\bdata-srcset\s*=\s*["']([^"']+)["']/gi,
    (match, srcset) => {
      const urls = srcset.split(',').map(part => {
        const [url, descriptor] = part.trim().split(/\s+/);
        return `${proxyUrl(url)}${descriptor ? ' ' + descriptor : ''}`;
      });
      return `data-srcset="${urls.join(', ')}"`;
    }
  );
  
  // Rewrite poster attributes (video thumbnails)
  html = html.replace(
    /\bposter\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `poster="${proxyUrl(url)}"`
  );
  
  // Rewrite action attributes (forms)
  html = html.replace(
    /\baction\s*=\s*["']([^"']+)["']/gi,
    (match, url) => {
      if (url.startsWith('#') || url.startsWith('javascript:')) {
        return match;
      }
      return `action="${proxyUrl(url)}"`;
    }
  );
  
  // Rewrite background attribute (deprecated but still used)
  html = html.replace(
    /\bbackground\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `background="${proxyUrl(url)}"`
  );
  
  // Rewrite CSS url() references in inline styles
  html = html.replace(
    /style\s*=\s*["']([^"']*)["']/gi,
    (match, styleContent) => {
      const rewrittenStyle = styleContent.replace(
        /url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi,
        (urlMatch, url) => `url("${proxyUrl(url)}")`
      );
      return `style="${rewrittenStyle}"`;
    }
  );
  
  // Rewrite <style> tag contents
  html = html.replace(
    /(<style[^>]*>)([\s\S]*?)(<\/style>)/gi,
    (match, openTag, cssContent, closeTag) => {
      const rewrittenCss = cssContent.replace(
        /url\s*\(\s*["']?([^"')]+)["']?\s*\)/gi,
        (urlMatch, url) => `url("${proxyUrl(url)}")`
      );
      // Also handle @import rules
      const rewrittenCssWithImports = rewrittenCss.replace(
        /@import\s+(?:url\s*\()?\s*["']([^"']+)["']\s*\)?/gi,
        (importMatch, url) => `@import url("${proxyUrl(url)}")`
      );
      return `${openTag}${rewrittenCssWithImports}${closeTag}`;
    }
  );
  
  // Rewrite <link rel="stylesheet"> href (already handled above, but ensure we capture css)
  // This is just a comment - href rewrite above handles it
  
  // Inject loading animation styles and scripts for images
  const loadingAnimationCode = `
<style data-proxy-loader="true">
  /* Proxy Loading Animation Styles */
  .proxy-img-loading {
    position: relative;
    background: linear-gradient(90deg, #1a1a2e 0%, #16213e 50%, #1a1a2e 100%);
    background-size: 200% 100%;
    animation: proxy-shimmer 1.5s infinite;
    min-height: 50px;
    min-width: 50px;
    border-radius: 4px;
    overflow: hidden;
  }
  .proxy-img-loading::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 40px;
    height: 40px;
    border: 3px solid rgba(88, 166, 255, 0.2);
    border-top-color: #58a6ff;
    border-radius: 50%;
    animation: proxy-spin 1s linear infinite;
  }
  .proxy-img-loading::after {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    width: 24px;
    height: 24px;
    border: 2px solid rgba(46, 160, 67, 0.3);
    border-top-color: #2ea043;
    border-radius: 50%;
    animation: proxy-spin 1.5s linear infinite reverse;
  }
  @keyframes proxy-shimmer {
    0% { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  @keyframes proxy-spin {
    to { transform: translate(-50%, -50%) rotate(360deg); }
  }
  .proxy-img-loaded {
    animation: proxy-fade-in 0.3s ease-in;
  }
  @keyframes proxy-fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  .proxy-img-error {
    position: relative;
    background: #3d0d0d;
    min-height: 50px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 4px;
  }
  .proxy-img-error::before {
    content: '⚠️ Failed to load';
    color: #f85149;
    font-size: 12px;
    font-family: system-ui, sans-serif;
  }
</style>
<script data-proxy-loader="true">
(function() {
  function initProxyLoader() {
    const images = document.querySelectorAll('img:not([data-proxy-initialized])');
    images.forEach(function(img) {
      img.setAttribute('data-proxy-initialized', 'true');
      
      // Skip if no src or already loaded
      if (!img.src || img.complete) return;
      
      // Add loading class
      img.classList.add('proxy-img-loading');
      
      // Handle load event
      img.addEventListener('load', function() {
        img.classList.remove('proxy-img-loading');
        img.classList.add('proxy-img-loaded');
      });
      
      // Handle error event
      img.addEventListener('error', function() {
        img.classList.remove('proxy-img-loading');
        img.classList.add('proxy-img-error');
        console.warn('[Proxy] Failed to load image:', img.src);
      });
      
      // Remove loading class if already cached/loaded
      if (img.complete && img.naturalWidth > 0) {
        img.classList.remove('proxy-img-loading');
        img.classList.add('proxy-img-loaded');
      }
    });
  }
  
  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initProxyLoader);
  } else {
    initProxyLoader();
  }
  
  // Run again after a delay to catch dynamically added images
  setTimeout(initProxyLoader, 500);
  setTimeout(initProxyLoader, 1500);
  
  // Watch for new images added to DOM
  if (window.MutationObserver) {
    const observer = new MutationObserver(function(mutations) {
      let hasNewImages = false;
      mutations.forEach(function(mutation) {
        mutation.addedNodes.forEach(function(node) {
          if (node.nodeName === 'IMG' || (node.querySelector && node.querySelector('img'))) {
            hasNewImages = true;
          }
        });
      });
      if (hasNewImages) {
        setTimeout(initProxyLoader, 50);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
</script>
<script data-proxy-nav="true">
(function() {
  // Store the original proxy URL pattern
  const PROXY_BASE = window.location.origin;
  const CURRENT_TARGET = new URLSearchParams(window.location.search).get('url') || '';
  const BASE_TARGET = CURRENT_TARGET ? new URL(CURRENT_TARGET).origin : '';
  
  // Helper to convert any URL to proxied URL
  function toProxyUrl(url) {
    // Already a proxy URL - decode and re-encode to clean it
    if (url && url.includes('/fetch?url=')) {
      try {
        const match = url.match(/[?&]url=([^&]+)/);
        if (match) {
          url = decodeURIComponent(match[1]);
        }
      } catch(e) {}
    }
    
    if (!url || url.startsWith(PROXY_BASE + '/fetch')) return url;
    if (url.startsWith('javascript:') || url.startsWith('#') || url.startsWith('data:')) return url;
    if (url.startsWith('http://') || url.startsWith('https://')) {
      return PROXY_BASE + '/fetch?url=' + encodeURIComponent(url) + '&rewrite=true';
    }
    // Relative URL - resolve against current target
    if (CURRENT_TARGET) {
      try {
        const resolved = new URL(url, CURRENT_TARGET).href;
        return PROXY_BASE + '/fetch?url=' + encodeURIComponent(resolved) + '&rewrite=true';
      } catch(e) {}
    }
    return url;
  }
  
  // Intercept history.pushState
  const originalPushState = history.pushState;
  history.pushState = function(state, title, url) {
    if (url) {
      // Block attempts to navigate to root (which strips query params)
      if (url === '/' || url === '' || url === window.location.origin + '/' || url === 'http://localhost:3000/' || url === 'http://localhost:3000') {
        console.log('[Proxy] BLOCKED pushState to root:', url);
        return;
      }
      const proxiedUrl = toProxyUrl(url);
      console.log('[Proxy] Intercepted pushState:', url, '->', proxiedUrl);
      return originalPushState.call(this, state, title, proxiedUrl);
    }
    return originalPushState.call(this, state, title, url);
  };
  
  // Intercept history.replaceState
  const originalReplaceState = history.replaceState;
  history.replaceState = function(state, title, url) {
    if (url) {
      // Block attempts to navigate to root (which strips query params)
      if (url === '/' || url === '' || url === window.location.origin + '/' || url === 'http://localhost:3000/' || url === 'http://localhost:3000') {
        console.log('[Proxy] BLOCKED replaceState to root:', url);
        return;
      }
      const proxiedUrl = toProxyUrl(url);
      console.log('[Proxy] Intercepted replaceState:', url, '->', proxiedUrl);
      return originalReplaceState.call(this, state, title, proxiedUrl);
    }
    return originalReplaceState.call(this, state, title, url);
  };
  
  // Intercept window.location changes
  let locationHandler = {
    set: function(obj, prop, value) {
      if (prop === 'href') {
        const proxiedUrl = toProxyUrl(value);
        console.log('[Proxy] Intercepted location.href:', value, '->', proxiedUrl);
        obj.href = proxiedUrl;
        return true;
      }
      obj[prop] = value;
      return true;
    }
  };
  
  // Wrap location.assign and location.replace
  const originalAssign = window.location.assign;
  window.location.assign = function(url) {
    const proxiedUrl = toProxyUrl(url);
    console.log('[Proxy] Intercepted location.assign:', url, '->', proxiedUrl);
    return originalAssign.call(window.location, proxiedUrl);
  };
  
  const originalReplace = window.location.replace;
  window.location.replace = function(url) {
    const proxiedUrl = toProxyUrl(url);
    console.log('[Proxy] Intercepted location.replace:', url, '->', proxiedUrl);
    return originalReplace.call(window.location, proxiedUrl);
  };
  
  // Intercept link clicks
  document.addEventListener('click', function(e) {
    const link = e.target.closest('a');
    if (link && link.href && !link.href.startsWith(PROXY_BASE + '/fetch')) {
      if (link.href.startsWith('http://') || link.href.startsWith('https://')) {
        e.preventDefault();
        const proxiedUrl = toProxyUrl(link.href);
        console.log('[Proxy] Intercepted link click:', link.href, '->', proxiedUrl);
        window.location.href = proxiedUrl;
      }
    }
  }, true);
  
  // Override <base> tag to prevent URL resolution issues
  function fixBaseTag() {
    const baseTag = document.querySelector('base');
    if (baseTag && CURRENT_TARGET) {
      const targetBase = new URL(CURRENT_TARGET);
      baseTag.href = targetBase.origin + targetBase.pathname;
    }
  }
  
  // Run base tag fix
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fixBaseTag);
  } else {
    fixBaseTag();
  }
  
  // Monitor for dynamically added base tags
  if (window.MutationObserver) {
    const observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        mutation.addedNodes.forEach(function(node) {
          if (node.nodeName === 'BASE' || (node.querySelector && node.querySelector('base'))) {
            fixBaseTag();
          }
        });
      });
    });
    observer.observe(document.head || document.documentElement, { childList: true, subtree: true });
  }
  
  console.log('[Proxy] URL interception active. Base target:', BASE_TARGET);
  
  // AGGRESSIVE: Create a Proxy for window.location to catch ALL access
  const PROXY_URL = window.location.href;
  const PROXY_PATH = window.location.pathname + window.location.search;
  
  try {
    // Monitor for URL changes and force them back immediately
    let urlCheckInterval = setInterval(function() {
      const currentHref = window.location.href;
      const currentPath = window.location.pathname + window.location.search;
      
      // If URL was stripped to just localhost:3000 without /fetch, restore it
      if (currentHref.indexOf('/fetch?') === -1 && currentHref.indexOf('localhost:3000') !== -1) {
        console.log('[Proxy] URL WAS STRIPPED! Restoring:', PROXY_URL);
        window.location.replace(PROXY_URL);
        clearInterval(urlCheckInterval);
      }
    }, 100);
    
    // Stop checking after 30 seconds
    setTimeout(function() {
      clearInterval(urlCheckInterval);
    }, 30000);
    
    // Override document.location as well
    Object.defineProperty(document, 'location', {
      get: function() {
        return window.location;
      },
      set: function(val) {
        window.location.href = val;
      }
    });
    
    // Override window.location with a Proxy
    const originalLocation = window.location;
    const locationProxy = new Proxy(originalLocation, {
      get: function(target, prop) {
        if (prop === 'href') {
          return PROXY_URL;
        }
        if (prop === 'pathname') {
          return PROXY_PATH;
        }
        if (prop === 'search') {
          return '?' + PROXY_URL.split('?')[1];
        }
        if (typeof target[prop] === 'function') {
          return target[prop].bind(target);
        }
        return target[prop];
      },
      set: function(target, prop, value) {
        if (prop === 'href') {
          const proxied = toProxyUrl(value);
          console.log('[Proxy] Blocked location.href change to:', value, 'redirecting to:', proxied);
          target.href = proxied;
          return true;
        }
        target[prop] = value;
        return true;
      }
    });
    
    // Try to override window.location (this may fail in strict mode but worth a shot)
    try {
      window.location = locationProxy;
    } catch(e) {
      console.log('[Proxy] Could not override window.location (expected in some browsers)');
    }
    
    // Hook into popstate to catch back button navigation
    window.addEventListener('popstate', function(e) {
      const currentHref = window.location.href;
      if (currentHref.indexOf('/fetch?') === -1 && currentHref.indexOf('localhost:3000') !== -1) {
        console.log('[Proxy] popstate URL stripped, restoring');
        e.preventDefault();
        e.stopPropagation();
        window.location.replace(PROXY_URL);
        return false;
      }
    }, true);
    
    // Prevent form submissions that might navigate away
    document.addEventListener('submit', function(e) {
      const form = e.target;
      if (form.action && form.action.indexOf('/fetch?') === -1) {
        console.log('[Proxy] Intercepting form submission to:', form.action);
        form.action = toProxyUrl(form.action);
      }
    }, true);
    
    // Catch beforeunload to prevent accidental navigation
    window.addEventListener('beforeunload', function(e) {
      const currentHref = window.location.href;
      if (currentHref.indexOf('/fetch?') === -1 && currentHref.indexOf('localhost:3000') !== -1) {
        console.log('[Proxy] Navigation detected, forcing back to proxy URL');
        window.location.replace(PROXY_URL);
        e.preventDefault();
        e.returnValue = '';
        return '';
      }
    });
    
    // Override window.open to intercept new windows
    const originalOpen = window.open;
    window.open = function(url, target, features) {
      if (url) {
        const proxied = toProxyUrl(url);
        console.log('[Proxy] Intercepted window.open:', url, '->', proxied);
        return originalOpen.call(window, proxied, target, features);
      }
      return originalOpen.call(window, url, target, features);
    };
    
    // Create an invisible iframe to detect navigation
    try {
      const checkerFrame = document.createElement('iframe');
      checkerFrame.style.display = 'none';
      checkerFrame.name = 'proxy-url-checker';
      document.body.appendChild(checkerFrame);
      
      // Check URL every 50ms for rapid changes
      setInterval(function() {
        const current = window.location.href;
        if (current !== PROXY_URL && current.indexOf('/fetch?') === -1 && current.indexOf('localhost:3000') !== -1) {
          console.log('[Proxy] Rapid URL change detected!');
          window.location.replace(PROXY_URL);
        }
      }, 50);
    } catch(e) {}
    
  } catch(e) {
    console.error('[Proxy] Advanced interception error:', e);
  }
})();
</script>
`;
  
  // Insert before closing </head> or before closing </body> or at the start
  if (html.includes('</head>')) {
    html = html.replace('</head>', loadingAnimationCode + '</head>');
  } else if (html.includes('</body>')) {
    html = html.replace('</body>', loadingAnimationCode + '</body>');
  } else if (html.includes('<html')) {
    html = html.replace(/<html[^>]*>/i, '$&' + loadingAnimationCode);
  } else {
    html = loadingAnimationCode + html;
  }
  
  return html;
}

// ============================================
// Route Handlers
// ============================================

/**
 * Performs the actual fetch and returns response
 * Handles both text and binary content properly
 */
async function performFetch(req, res, targetUrl, options = {}) {
  const { method = 'GET', headers = {}, body = null } = options;
  const shouldStream = req.query.stream === 'true';

  // Create safe request configuration
  const fetchOptions = {
    method: method.toUpperCase(),
    headers: createSafeHeaders(headers, targetUrl, req),
    redirect: 'follow',
  };

  // Add body for POST/PUT/PATCH requests
  if (body && ['POST', 'PUT', 'PATCH'].includes(method.toUpperCase())) {
    fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  try {
    const response = await fetch(targetUrl, fetchOptions);

    // Get content type
    const contentType = response.headers.get('content-type') || 'application/octet-stream';

    // Check if rewrite mode is enabled (only for HTML)
    const shouldRewrite = req.query.rewrite === 'true' && contentType.includes('text/html');

    // Streaming mode for HTML - sends content as it arrives
    if (shouldStream && contentType.includes('text/html')) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Transfer-Encoding', 'chunked');
      res.setHeader('Cache-Control', 'no-cache');

      const proxyBase = getProxyBase(req);

      // Write intro with click handler
      const intro = `<!DOCTYPE html><html><head><meta charset="utf-8"><base href="${targetUrl}"></head><body><script>
    var BASE='${proxyBase}',TARGET='${targetUrl}';
    document.addEventListener('click',function(e){
    var l=e.target.closest&&e.target.closest('a')||(e.target.tagName=='A'?e.target:null);
    if(l){e.preventDefault();window.location.href=BASE+'/fetch?url='+encodeURIComponent(new URL(l.href,TARGET).href)+'&rewrite=true&stream=true';}
    });
    <\/script>`;
      res.write(intro);

      // Use async iterator for streaming
      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      const pump = async () => {
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) {
              res.write('</body></html>');
              res.end();
              return;
            }
            res.write(value);
          }
        } catch (err) {
          console.error('Stream error:', err);
          res.write('</body></html>');
          res.end();
        }
      };

      pump();
      return;
    }

    // For HTML with rewrite enabled, we need text
    if (shouldRewrite) {
      const textBody = await response.text();
      const rewrittenHtml = rewriteHtml(textBody, targetUrl);
      res.setHeader('Content-Type', 'text/html');
      return res.send(rewrittenHtml);
    }

    // For JSON, parse and return as JSON
    if (contentType.includes('application/json')) {
      const textBody = await response.text();
      try {
        const jsonData = JSON.parse(textBody);
        return res.json(jsonData);
      } catch {
        return res.type('text').send(textBody);
      }
    }
    
    // For all other content (images, CSS, JS, etc.), stream binary data
    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    
    // Forward important headers
    const forwardHeaders = ['content-type', 'cache-control', 'etag', 'last-modified', 'expires', 'content-length', 'accept-ranges', 'content-range'];
    for (const header of forwardHeaders) {
      const value = response.headers.get(header);
      if (value) {
        res.set(header, value);
      }
    }
    
    // Add CORS headers to allow the proxied resource to be used anywhere
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    
    // Log image loading for debugging
    if (contentType.startsWith('image/')) {
      console.log(`[Image] ${targetUrl} -> ${buffer.length} bytes, status: ${response.status}`);
    }
    
    res.status(response.status);
    res.send(buffer);
    
  } catch (error) {
    console.error('Fetch error:', error.message);
    return res.status(502).json({
      error: 'Failed to fetch target URL',
      details: error.message
    });
  }
}

// GET /fetch endpoint
app.get('/fetch', async (req, res) => {
  const { url } = req.query;

  // Validate URL
  const validation = validateUrl(url);
  if (validation.valid === false) {
    return res.status(403).json({
      error: validation.error,
      details: validation.blockedDomain ? 'This domain is blocked by the proxy' : 'URL validation failed'
    });
  }

  await performFetch(req, res, validation.href);
});

// POST /fetch endpoint (advanced feature)
app.post('/fetch', async (req, res) => {
  const { url, method = 'GET', headers = {}, body = null } = req.body;

  // Validate URL
  const validation = validateUrl(url);
  if (validation.valid === false) {
    return res.status(403).json({
      error: validation.error,
      details: validation.blockedDomain ? 'This domain is blocked by the proxy' : 'URL validation failed'
    });
  }

  // Validate HTTP method
  const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
  if (!allowedMethods.includes(method.toUpperCase())) {
    return res.status(400).json({
      error: 'Invalid HTTP method',
      details: `Method must be one of: ${allowedMethods.join(', ')}`
    });
  }

  await performFetch(req, res, validation.href, { method, headers, body });
});

// ============================================
// Utility Endpoints
// ============================================

// GET /timestamp - Returns current time in multiple formats
app.get('/timestamp', (req, res) => {
  const now = new Date();
  res.json({
    iso: now.toISOString(),
    utc: now.toUTCString(),
    unix: now.getTime(),
    readable: now.toLocaleString(),
    unix_seconds: Math.floor(now.getTime() / 1000)
  });
});

// GET /timezone - Returns user's timezone
app.get('/timezone', (req, res) => {
  const now = new Date();
  res.json({
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    offset: now.getTimezoneOffset(),
    offset_hours: -(now.getTimezoneOffset() / 60),
    abbr: now.toLocaleTimeString('en-US', { timeZoneName: 'short' }).split(' ').pop()
  });
});

// GET /slug - Converts text to URL slugs
app.get('/slug', (req, res) => {
  const { text } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }
  const slug = text
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  res.json({ input: text, slug: slug });
});

// GET /scrape - Returns headers, links, and title from a URL
app.get('/scrape', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  try {
    const validation = validateUrl(url);
    if (validation.valid === false) {
      return res.status(403).json({ error: validation.error });
    }

    const response = await fetch(validation.href, {
      headers: { 'User-Agent': BROWSER_USER_AGENT }
    });
    const html = await response.text();

    // Extract title
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : '';

    // Extract meta description
    const descMatch = html.match(/<meta[^>]*name="description"[^>]*content="([^"]+)"/i);
    const description = descMatch ? descMatch[1] : '';

    // Extract links
    const linkMatches = html.match(/<a[^>]*href="([^"]+)"[^>]*>/gi) || [];
    const links = linkMatches
      .map(m => {
        const match = m.match(/href="([^"]+)"/);
        return match ? match[1] : null;
      })
      .filter(l => l && !l.startsWith('#') && !l.startsWith('javascript:'));

    // Extract headers
    const h1s = (html.match(/<h1[^>]*>([^<]+)<\/h1>/gi) || []).map(m => m.replace(/<[^>]+>/g, ''));
    const h2s = (html.match(/<h2[^>]*>([^<]+)<\/h2>/gi) || []).map(m => m.replace(/<[^>]+>/g, ''));

    res.json({
      url: validation.href,
      title: title,
      description: description,
      links: [...new Set(links)].slice(0, 100),
      h1s: h1s.slice(0, 20),
      h2s: h2s.slice(0, 20),
      link_count: links.length
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to scrape URL', details: error.message });
  }
});

// GET /ping - Measures response time for a URL
app.get('/ping', async (req, res) => {
  const { url } = req.query;
  if (!url) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }

  try {
    const validation = validateUrl(url);
    if (validation.valid === false) {
      return res.status(403).json({ error: validation.error });
    }

    const start = Date.now();
    const response = await fetch(validation.href, {
      headers: { 'User-Agent': BROWSER_USER_AGENT }
    });
    const end = Date.now();

    res.json({
      url: validation.href,
      status: response.status,
      response_time_ms: end - start,
      response_time_seconds: (end - start) / 1000
    });
  } catch (error) {
    res.status(500).json({ error: 'Ping failed', details: error.message });
  }
});

// GET /count-text - Returns character count, word count, and sentence count
app.get('/count-text', (req, res) => {
  const { text } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }

  const charCount = text.length;
  const wordCount = text.trim().split(/\s+/).filter(w => w.length > 0).length;
  const sentenceCount = (text.match(/[.!?]+/g) || []).length || (text.trim().length > 0 ? 1 : 0);
  const paragraphCount = (text.match(/\n\n+/g) || []).length + (text.trim().length > 0 ? 1 : 0);

  res.json({
    text: text,
    characters: charCount,
    words: wordCount,
    sentences: sentenceCount,
    paragraphs: paragraphCount
  });
});

// GET /hex-to-colour - Returns colour name from hex code
app.get('/hex-to-colour', (req, res) => {
  const { hex } = req.query;
  if (!hex) {
    return res.status(400).json({ error: 'Missing hex parameter' });
  }

  const colorNames = {
    '#FF0000': 'Red', '#00FF00': 'Lime', '#0000FF': 'Blue',
    '#FFFF00': 'Yellow', '#FF00FF': 'Magenta', '#00FFFF': 'Cyan',
    '#FFFFFF': 'White', '#000000': 'Black', '#808080': 'Gray',
    '#FFA500': 'Orange', '#800080': 'Purple', '#FFC0CB': 'Pink',
    '#A52A2A': 'Brown', '#000080': 'Navy', '#808000': 'Olive',
    '#008000': 'Green', '#800000': 'Maroon', '#0000FF': 'Blue',
    '#008080': 'Teal', '#4169E1': 'Royal Blue', '#DC143C': 'Crimson',
    '#FFD700': 'Gold', '#C0C0C0': 'Silver', '#2E8B57': 'Sea Green',
    '#FF6347': 'Tomato', '#9370DB': 'Medium Purple', '#3CB371': 'Medium Sea Green',
    '#FF69B4': 'Hot Pink', '#DDA0DD': 'Plum', '#B0C4DE': 'Light Steel Blue'
  };

  const cleanHex = '#' + hex.replace('#', '').toUpperCase();
  const rgbMatch = cleanHex.match(/^#?([A-Fa-f0-9]{6})$/);
  
  if (!rgbMatch) {
    return res.status(400).json({ error: 'Invalid hex code format' });
  }

  const r = parseInt(cleanHex.slice(1, 3), 16);
  const g = parseInt(cleanHex.slice(3, 5), 16);
  const b = parseInt(cleanHex.slice(5, 7), 16);

  // Find closest named color
  let closestName = 'Unknown';
  let closestDist = Infinity;
  for (const [namedHex, name] of Object.entries(colorNames)) {
    const nr = parseInt(namedHex.slice(1, 3), 16);
    const ng = parseInt(namedHex.slice(3, 5), 16);
    const nb = parseInt(namedHex.slice(5, 7), 16);
    const dist = Math.sqrt(Math.pow(r - nr, 2) + Math.pow(g - ng, 2) + Math.pow(b - nb, 2));
    if (dist < closestDist) {
      closestDist = dist;
      closestName = name;
    }
  }

  res.json({
    hex: cleanHex,
    rgb: `rgb(${r}, ${g}, ${b})`,
    colour_name: closestName
  });
});

// GET /sanitize - Removes unsafe characters
app.get('/sanitize', (req, res) => {
  const { text } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }

  const sanitized = text
    .replace(/[<>'"&]/g, '')
    .replace(/[\x00-\x1F]/g, '')
    .trim();

  res.json({
    original: text,
    sanitized: sanitized
  });
});

// GET /delay - Simulates API delay
app.get('/delay', async (req, res) => {
  const ms = Math.min(parseInt(req.query.ms) || 2000, 30000);
  
  await new Promise(resolve => setTimeout(resolve, ms));
  
  res.json({
    delayed_ms: ms,
    message: `Delayed for ${ms} milliseconds`
  });
});

// GET /uuid - Generate UUIDs
app.get('/uuid', (req, res) => {
  const count = Math.min(parseInt(req.query.count) || 1, 100);
  const uuids = [];
  for (let i = 0; i < count; i++) {
    uuids.push(crypto.randomUUID());
  }
  res.json({ count: uuids.length, uuids: count === 1 ? uuids[0] : uuids });
});

// GET /base64 - Encode or decode base64
app.get('/base64', (req, res) => {
  const { text, decode } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }
  
  try {
    if (decode === 'true' || decode === '1') {
      const decoded = Buffer.from(text, 'base64').toString('utf-8');
      res.json({ original: text, decoded: decoded });
    } else {
      const encoded = Buffer.from(text, 'utf-8').toString('base64');
      res.json({ original: text, encoded: encoded });
    }
  } catch (error) {
    res.status(400).json({ error: 'Invalid input', details: error.message });
  }
});

// GET /hash - Generate hash of text
app.get('/hash', (req, res) => {
  const { text, type = 'sha256' } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }
  
  const types = ['md5', 'sha1', 'sha256', 'sha512'];
  const hashType = types.includes(type) ? type : 'sha256';
  
  crypto.subtle.digest(hashType, new TextEncoder().encode(text)).then(hash => {
    const hashHex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    res.json({ text: text, type: hashType, hash: hashHex });
  }).catch(() => {
    res.status(500).json({ error: 'Hash generation failed' });
  });
});

// GET /json-format - Format or validate JSON
app.get('/json-format', (req, res) => {
  const { text, minify } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }
  
  try {
    const parsed = JSON.parse(text);
    const formatted = minify === 'true' ? JSON.stringify(parsed) : JSON.stringify(parsed, null, 2);
    res.json({ valid: true, formatted: formatted });
  } catch (error) {
    res.json({ valid: false, error: error.message });
  }
});

// GET /random - Generate random values
app.get('/random', (req, res) => {
  const type = req.query.type || 'number';
  const min = parseInt(req.query.min) || 0;
  const max = parseInt(req.query.max) || 100;
  const count = Math.min(parseInt(req.query.count) || 1, 100);
  
  if (type === 'number') {
    const numbers = [];
    for (let i = 0; i < count; i++) {
      numbers.push(Math.floor(Math.random() * (max - min + 1)) + min);
    }
    res.json({ type: 'number', count: numbers.length, values: count === 1 ? numbers[0] : numbers });
  } else if (type === 'password') {
    const length = Math.min(parseInt(req.query.length) || 16, 128);
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    for (let i = 0; i < length; i++) {
      password += chars[Math.floor(Math.random() * chars.length)];
    }
    res.json({ type: 'password', password: password });
  } else if (type === 'choice') {
    const options = (req.query.options || '').split(',').filter(Boolean);
    if (options.length === 0) {
      return res.status(400).json({ error: 'Missing options parameter (comma-separated)' });
    }
    res.json({ choice: options[Math.floor(Math.random() * options.length)] });
  } else {
    res.status(400).json({ error: 'Invalid type. Use: number, password, or choice' });
  }
});

// GET /jwt-decode - Decode JWT token
app.get('/jwt-decode', (req, res) => {
  const { token } = req.query;
  if (!token) {
    return res.status(400).json({ error: 'Missing token parameter' });
  }
  
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return res.status(400).json({ error: 'Invalid JWT format' });
    }
    
    const header = JSON.parse(Buffer.from(parts[0], 'base64').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString());
    
    res.json({
      header: header,
      payload: payload,
      signature: parts[2]
    });
  } catch (error) {
    res.status(400).json({ error: 'Failed to decode JWT', details: error.message });
  }
});

// GET /color-convert - Convert between color formats
app.get('/color-convert', (req, res) => {
  const { hex, rgb, hsl } = req.query;
  
  try {
    let r, g, b;
    
    if (hex) {
      const clean = hex.replace('#', '');
      if (!/^[0-9A-Fa-f]{6}$/.test(clean)) {
        return res.status(400).json({ error: 'Invalid hex format' });
      }
      r = parseInt(clean.substring(0, 2), 16);
      g = parseInt(clean.substring(2, 4), 16);
      b = parseInt(clean.substring(4, 6), 16);
    } else if (rgb) {
      const match = rgb.match(/(\d+),\s*(\d+),\s*(\d+)/);
      if (!match) {
        return res.status(400).json({ error: 'Invalid RGB format (use: 255,255,255)' });
      }
      r = parseInt(match[1]);
      g = parseInt(match[2]);
      b = parseInt(match[3]);
    } else if (hsl) {
      const match = hsl.match(/(\d+),\s*(\d+)%?,\s*(\d+)%?/);
      if (!match) {
        return res.status(400).json({ error: 'Invalid HSL format (use: 0,100,50)' });
      }
      const h = parseInt(match[1]) / 360;
      const s = parseInt(match[2]) / 100;
      const l = parseInt(match[3]) / 100;
      const [r1, g1, b1] = hslToRgb(h, s, l);
      r = r1; g = g1; b = b1;
    } else {
      return res.status(400).json({ error: 'Provide hex, rgb, or hsl parameter' });
    }
    
    const hexVal = '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase();
    const [h, s, l] = rgbToHsl(r, g, b);
    
    res.json({
      hex: hexVal,
      rgb: `rgb(${r}, ${g}, ${b})`,
      hsl: `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`,
      rgba: `rgba(${r}, ${g}, ${b}, 1)`
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Helper: RGB to HSL
function rgbToHsl(r, g, b) {
  r /= 255; g /= 255; b /= 255;
  const max = Math.max(r, g, b), min = Math.min(r, g, b);
  let h, s, l = (max + min) / 2;
  if (max === min) {
    h = s = 0;
  } else {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r: h = ((g - b) / d + (g < b ? 6 : 0)) / 6; break;
      case g: h = ((b - r) / d + 2) / 6; break;
      case b: h = ((r - g) / d + 4) / 6; break;
    }
  }
  return [h, s, l];
}

// Helper: HSL to RGB
function hslToRgb(h, s, l) {
  let r, g, b;
  if (s === 0) {
    r = g = b = l;
  } else {
    const hue2rgb = (p, q, t) => {
      if (t < 0) t += 1;
      if (t > 1) t -= 1;
      if (t < 1/6) return p + (q - p) * 6 * t;
      if (t < 1/2) return q;
      if (t < 2/3) return p + (q - p) * (2/3 - t) * 6;
      return p;
    };
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
    const p = 2 * l - q;
    r = hue2rgb(p, q, h + 1/3);
    g = hue2rgb(p, q, h);
    b = hue2rgb(p, q, h - 1/3);
  }
  return [Math.round(r * 255), Math.round(g * 255), Math.round(b * 255)];
}

// GET /joke - Random joke
app.get('/joke', async (req, res) => {
  try {
    const response = await fetch('https://v2.jokeapi.dev/joke/Any?safe-mode');
    const data = await response.json();
    
    if (data.type === 'single') {
      res.json({ joke: data.joke, type: 'single' });
    } else {
      res.json({ setup: data.setup, delivery: data.delivery, type: 'twopart' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch joke' });
  }
});

// GET /word - Dictionary lookup
app.get('/word', async (req, res) => {
  const { text } = req.query;
  if (!text) {
    return res.status(400).json({ error: 'Missing text parameter' });
  }
  
  try {
    const response = await fetch(`https://api.dictionaryapi.dev/api/v2/entries/en/${encodeURIComponent(text)}`);
    const data = await response.json();
    
    if (!response.ok) {
      return res.status(404).json({ error: 'Word not found' });
    }
    
    const word = data[0];
    const meanings = word.meanings.map(m => ({
      partOfSpeech: m.partOfSpeech,
      definitions: m.definitions.slice(0, 3).map(d => ({
        definition: d.definition,
        example: d.example
      }))
    }));
    
    res.json({
      word: word.word,
      phonetic: word.phonetic || '',
      meanings: meanings
    });
  } catch (error) {
    res.status(500).json({ error: 'Dictionary lookup failed' });
  }
});

// GET /ai-text - Generate text using Pollinations AI
app.get('/ai-text', async (req, res) => {
  const { prompt, model = 'openai' } = req.query;
  
  if (!prompt) {
    return res.status(400).json({ error: 'Missing prompt parameter' });
  }
  
  try {
    const url = `https://gen.pollinations.ai/text/${encodeURIComponent(prompt)}?model=${model}`;
    const response = await fetch(url);
    const text = await response.text();
    res.json({ prompt: prompt, response: text.trim(), model: model });
  } catch (error) {
    res.status(500).json({ error: 'AI request failed', details: error.message });
  }
});

// GET /models - List available AI models
app.get('/models', (req, res) => {
  res.json({
    models: [
      { id: 'openai', name: 'OpenAI', description: 'Fast and reliable GPT-style responses' },
      { id: 'gemini-fast', name: 'Gemini Fast', description: 'Quick Google Gemini responses' },
      { id: 'deepseek', name: 'DeepSeek', description: 'DeepSeek language model' },
      { id: 'claude-fast', name: 'Claude Fast', description: 'Fast Anthropic Claude responses' }
    ]
  });
});

// GET /ai-image - Generate AI images using Pollinations
app.get('/ai-image', async (req, res) => {
  const { prompt, width = 1024, height = 1024, model = 'flux', safe = 'true', enhance = 'false', seed = '-1' } = req.query;
  
  if (!prompt) {
    return res.status(400).json({ error: 'Missing prompt parameter' });
  }
  
  try {
    const safeMode = safe === 'true' || safe === '1';
    const enhanced = enhance === 'true' || enhance === '1';
    
    const url = `https://image.pollinations.ai/prompt/${encodeURIComponent(prompt)}?width=${width}&height=${height}&model=${model}&safe=${safeMode}&enhance=${enhanced}&seed=${seed}`;
    
    res.json({
      prompt: prompt,
      image_url: url,
      width: parseInt(width),
      height: parseInt(height),
      model: model,
      safe_mode: safeMode,
      enhanced: enhanced,
      seed: parseInt(seed)
    });
  } catch (error) {
    res.status(500).json({ error: 'Image generation failed', details: error.message });
  }
});

// GET /ai-image-info - Get info about AI image generation
app.get('/ai-image-info', (req, res) => {
  res.json({
    endpoint: '/ai-image',
    description: 'Generate AI images using Pollinations',
    parameters: {
      prompt: { type: 'string', required: true, description: 'The image description' },
      width: { type: 'number', default: 1024, description: 'Image width (e.g., 512, 1024, 1536)' },
      height: { type: 'number', default: 1024, description: 'Image height (e.g., 512, 1024, 1536)' },
      model: { type: 'string', default: 'flux', description: 'AI model to use' },
      safe: { type: 'boolean', default: true, description: 'NSFW filter (true/false)' },
      enhance: { type: 'boolean', default: false, description: 'AI prompt rewrite (true/false)' },
      seed: { type: 'number', default: -1, description: 'Random seed (-1 for random)' }
    },
    models: [
      { id: 'flux', name: 'Flux', description: 'Default high-quality model' },
      { id: 'zimage', name: 'Zimage', description: 'Zoe AI model' },
      { id: 'gptimage', name: 'GPTImage', description: 'OpenAI image model' },
      { id: 'klein', name: 'Klein', description: 'Alternative model' },
      { id: 'image-4', name: 'Image 4', description: 'Latest image model' },
      { id: 'frok-imagine', name: 'Frok Imagine', description: 'Creative model' },
      { id: 'nanobanana', name: 'Nanobanana', description: 'Unique stylized model' },
      { id: 'seedream', name: 'Seedream', description: 'Dream-like images' }
    ],
    examples: [
      'GET /ai-image?prompt=a%20beautiful%20sunset',
      'GET /ai-image?prompt=cute%20cat&width=512&height=512&model=flux',
      'GET /ai-image?prompt=space%20ship&safe=false&enhance=true'
    ]
  });
});

// Social data generation endpoint
app.get('/social/generate', (req, res) => {
  const { type, count = 1 } = req.query;
  const num = Math.min(parseInt(count) || 1, 100);
  
  const generators = {
    email: () => {
      const domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'protonmail.com', 'icloud.com', 'mail.com'];
      const firstNames = ['john', 'jane', 'alex', 'sam', 'mike', 'sarah', 'david', 'emma', 'chris', 'lisa', 'robert', 'jennifer'];
      const lastNames = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis', 'rodriguez', 'martinez'];
      const first = firstNames[Math.floor(Math.random() * firstNames.length)];
      const last = lastNames[Math.floor(Math.random() * lastNames.length)];
      const domain = domains[Math.floor(Math.random() * domains.length)];
      const num = Math.floor(Math.random() * 999) + 1;
      const patterns = [`${first}.${last}`, `${first}${last}`, `${first}_${last}`, `${first}${num}`, `${last}${num}`, `${first}.${last}${num}`];
      const pattern = patterns[Math.floor(Math.random() * patterns.length)];
      return `${pattern}@${domain}`;
    },
    phone: () => {
      const formats = ['+1 (###) ###-####', '###-###-####', '(###) ###-####', '+1 ### ### ####'];
      const format = formats[Math.floor(Math.random() * formats.length)];
      return format.replace(/#/g, () => Math.floor(Math.random() * 10));
    },
    name: () => {
      const firstNames = ['James', 'Mary', 'John', 'Patricia', 'Robert', 'Jennifer', 'Michael', 'Linda', 'William', 'Elizabeth', 'David', 'Susan', 'Richard', 'Jessica', 'Joseph', 'Sarah', 'Thomas', 'Karen', 'Charles', 'Nancy'];
      const lastNames = ['Smith', 'Johnson', 'Williams', 'Brown', 'Jones', 'Garcia', 'Miller', 'Davis', 'Rodriguez', 'Martinez', 'Hernandez', 'Lopez', 'Gonzalez', 'Wilson', 'Anderson'];
      return `${firstNames[Math.floor(Math.random() * firstNames.length)]} ${lastNames[Math.floor(Math.random() * lastNames.length)]}`;
    },
    username: () => {
      const adjectives = ['cool', 'happy', 'sad', 'fast', 'slow', 'big', 'small', 'dark', 'light', 'loud', 'quiet', 'new', 'old'];
      const nouns = ['tiger', 'eagle', 'shark', 'wolf', 'bear', 'lion', 'fox', 'hawk', 'dragon', 'phoenix', 'ninja', 'coder', 'gamer'];
      const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
      const noun = nouns[Math.floor(Math.random() * nouns.length)];
      const num = Math.floor(Math.random() * 9999) + 1;
      return `${adj}_${noun}_${num}`;
    }
  };
  
  if (!type || !generators[type]) {
    return res.status(400).json({
      error: 'Invalid or missing type parameter',
      supportedTypes: Object.keys(generators),
      example: '/social/generate?type=email&count=5'
    });
  }
  
  const results = Array.from({ length: num }, () => generators[type]());
  
  res.json({
    type,
    count: num,
    data: num === 1 ? results[0] : results
  });
});

// Text entity parsing endpoint
app.post('/text/parse-entities', (req, res) => {
  const { text } = req.body;
  
  if (!text || typeof text !== 'string') {
    return res.status(400).json({
      error: 'Missing or invalid text parameter',
      example: { text: 'My email is john@example.com and my number is +1 234 567 8900' }
    });
  }
  
  // Email regex
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  
  // Phone regex (various formats)
  const phoneRegex = /(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g;
  
  // URL regex
  const urlRegex = /https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_+.~#?&/=]*)/g;
  
  // Simple date patterns
  const dateRegex = /\b(?:\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4}|\d{4}[\/\.-]\d{1,2}[\/\.-]\d{1,2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{4})\b/gi;
  
  // Name detection (capitalized words that could be names - simplified heuristic)
  const nameRegex = /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b/g;
  
  const extract = (regex) => {
    const matches = text.match(regex);
    return matches ? [...new Set(matches)] : [];
  };
  
  // Filter out common false positives for names
  const commonWords = ['The', 'This', 'That', 'These', 'Those', 'There', 'Their', 'They', 'What', 'When', 'Where', 'Which', 'Who', 'Whose', 'Why', 'How', 'And', 'But', 'Or', 'Yet', 'For', 'Nor', 'So', 'As', 'If', 'Then', 'Than', 'To', 'Of', 'In', 'On', 'At', 'By', 'With', 'From', 'Up', 'About', 'Into', 'Over', 'After', 'My', 'Your', 'His', 'Her', 'Its', 'Our', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday', 'January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  
  const names = extract(nameRegex).filter(name => {
    const words = name.split(/\s+/);
    return !words.some(word => commonWords.includes(word));
  });
  
  res.json({
    text: text.substring(0, 1000),
    emails: extract(emailRegex),
    phones: extract(phoneRegex),
    urls: extract(urlRegex),
    names: names,
    dates: extract(dateRegex)
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Test interface - interactive API tester
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CORS Proxy API Tester</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0d1117;
      color: #c9d1d9;
      padding: 40px 20px;
      max-width: 900px;
      margin: 0 auto;
      line-height: 1.6;
    }
    h1 { color: #58a6ff; margin-bottom: 10px; }
    .subtitle { color: #8b949e; margin-bottom: 30px; }
    .section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .section h2 {
      color: #58a6ff;
      font-size: 18px;
      margin-bottom: 15px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    label { display: block; margin-bottom: 5px; color: #8b949e; font-size: 14px; }
    input, select, textarea {
      width: 100%;
      padding: 10px 12px;
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      font-size: 14px;
      margin-bottom: 12px;
    }
    input:focus, select:focus, textarea:focus {
      outline: none;
      border-color: #58a6ff;
    }
    button {
      background: #238636;
      color: white;
      border: none;
      padding: 10px 20px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
    }
    button:hover { background: #2ea043; }
    button:disabled { opacity: 0.6; cursor: not-allowed; }
    .row { display: flex; gap: 12px; }
    .row > * { flex: 1; }
    .checkbox { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; }
    .checkbox input { width: auto; margin: 0; }
    .result {
      background: #0d1117;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 15px;
      margin-top: 15px;
      min-height: 100px;
      max-height: 400px;
      overflow: auto;
      font-family: 'Monaco', 'Consolas', monospace;
      font-size: 13px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .error { color: #f85149; }
    .success { color: #3fb950; }
    .info { color: #8b949e; font-size: 13px; margin-top: 8px; }
    .method-get { color: #3fb950; }
    .method-post { color: #f0883e; }
    .endpoints {
      display: grid;
      gap: 10px;
    }
    .endpoint {
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 10px;
      background: #0d1117;
      border-radius: 6px;
      font-family: monospace;
      font-size: 13px;
    }
    .method {
      background: #238636;
      color: white;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: bold;
    }
    .method.post { background: #f0883e; }
    .hidden { display: none; }
  </style>
</head>
<body>
  <h1>CORS Proxy API</h1>
  <p class="subtitle">Test your proxy requests below. All URLs are allowed (except localhost/private IPs).</p>
  <p class="subtitle" style="font-size: 12px; margin-top: -20px; opacity: 0.8;">
    Note: YouTube, Netflix and other streaming sites are blocked. Complex JavaScript apps may not work perfectly.
  </p>

  <div class="section">
    <h2>Endpoints</h2>
    <div class="endpoints">
      <div class="endpoint">
        <span class="method">GET</span>
        <span>/fetch?url=&lt;url&gt;&rewrite=true</span>
      </div>
      <div class="endpoint">
        <span class="method post">POST</span>
        <span>/fetch</span>
      </div>
      <div class="endpoint">
        <span class="method">GET</span>
        <span>/screenshot?url=&lt;url&gt;&width=1920&height=1080</span>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>Simple GET Test</h2>
    <label>Target URL</label>
    <input type="text" id="getUrl" placeholder="https://api.github.com/users/github" value="https://httpbin.org/get">
    <div class="checkbox">
      <input type="checkbox" id="getRewrite">
      <label for="getRewrite" style="margin:0">Rewrite HTML (proxies src/href through this API)</label>
    </div>
    <button onclick="testGet()">Send GET Request</button>
    <div id="getResult" class="result hidden"></div>
  </div>

  <div class="section">
    <h2>Advanced POST Test</h2>
    <div class="row">
      <div>
        <label>Target URL</label>
        <input type="text" id="postUrl" placeholder="https://httpbin.org/post" value="https://httpbin.org/post">
      </div>
      <div>
        <label>Method</label>
        <select id="postMethod">
          <option>POST</option>
          <option>PUT</option>
          <option>PATCH</option>
          <option>DELETE</option>
        </select>
      </div>
    </div>
    <label>Custom Headers (JSON)</label>
    <input type="text" id="postHeaders" placeholder='{"Content-Type": "application/json"}' value='{"Content-Type": "application/json"}'>
    <label>Request Body</label>
    <textarea id="postBody" rows="4" placeholder='{"test": "data"}'>{"test": "data", "timestamp": "2024-01-01"}</textarea>
    <button onclick="testPost()">Send Request</button>
    <div id="postResult" class="result hidden"></div>
  </div>

  <div class="section">
    <h2>CORS Test (Direct vs Proxy)</h2>
    <label>URL to test CORS (try fetching directly)</label>
    <input type="text" id="corsUrl" placeholder="https://api.github.com/users/github" value="https://httpbin.org/get">
    <button onclick="testCors()">Compare Direct vs Proxy</button>
    <div id="corsResult" class="result hidden"></div>
  </div>

  <div class="section">
    <h2>Screenshot Test</h2>
    <label>URL to Screenshot</label>
    <input type="text" id="screenshotUrl" placeholder="https://example.com" value="https://httpbin.org/html">
    <div class="row">
      <div>
        <label>Width (px)</label>
        <input type="number" id="screenshotWidth" value="1920" min="320" max="3840">
      </div>
      <div>
        <label>Height (px)</label>
        <input type="number" id="screenshotHeight" value="1080" min="240" max="2160">
      </div>
    </div>
    <div class="checkbox">
      <input type="checkbox" id="screenshotFullPage">
      <label for="screenshotFullPage" style="margin:0">Full page screenshot (ignores height)</label>
    </div>
    <button onclick="testScreenshot()">Take Screenshot</button>
    <div id="screenshotResult" class="result hidden"></div>
  </div>

  <script>
    const API_BASE = window.location.origin;

    async function testGet() {
      const url = document.getElementById('getUrl').value;
      const rewrite = document.getElementById('getRewrite').checked;
      const result = document.getElementById('getResult');
      
      if (!url) { result.textContent = 'Please enter a URL'; result.className = 'result error'; return; }
      
      result.classList.remove('hidden');
      result.textContent = 'Loading...';
      
      try {
        const proxyUrl = \`/fetch?url=\${encodeURIComponent(url)}\${rewrite ? '&rewrite=true' : ''}\`;
        const start = Date.now();
        const response = await fetch(proxyUrl);
        const duration = Date.now() - start;
        
        const contentType = response.headers.get('content-type');
        let data;
        
        if (contentType && contentType.includes('application/json')) {
          data = await response.json();
        } else {
          data = await response.text();
        }
        
        result.innerHTML = \`<span class="success">✓ Success (\${duration}ms)</span>\n\nStatus: \${response.status}\nContent-Type: \${contentType || 'unknown'}\n\n\${typeof data === 'string' ? data.substring(0, 5000) : JSON.stringify(data, null, 2)}\`;
        result.className = 'result success';
      } catch (err) {
        result.innerHTML = \`<span class="error">✗ Error</span>\n\n\${err.message}\`;
        result.className = 'result error';
      }
    }

    async function testPost() {
      const url = document.getElementById('postUrl').value;
      const method = document.getElementById('postMethod').value;
      const headersStr = document.getElementById('postHeaders').value;
      const body = document.getElementById('postBody').value;
      const result = document.getElementById('postResult');
      
      if (!url) { result.textContent = 'Please enter a URL'; result.className = 'result error'; return; }
      
      result.classList.remove('hidden');
      result.textContent = 'Loading...';
      
      try {
        let headers = {};
        if (headersStr) {
          headers = JSON.parse(headersStr);
        }
        
        const start = Date.now();
        const response = await fetch(\`/fetch\`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, method, headers, body })
        });
        const duration = Date.now() - start;
        
        const data = await response.json();
        result.innerHTML = \`<span class="success">✓ Success (\${duration}ms)</span>\n\nStatus: \${response.status}\n\n\${JSON.stringify(data, null, 2)}\`;
        result.className = 'result success';
      } catch (err) {
        result.innerHTML = \`<span class="error">✗ Error</span>\n\n\${err.message}\`;
        result.className = 'result error';
      }
    }

    async function testCors() {
      const url = document.getElementById('corsUrl').value;
      const result = document.getElementById('corsResult');
      
      result.classList.remove('hidden');
      result.innerHTML = 'Testing direct fetch (may fail due to CORS)...';
      
      let directResult = '';
      try {
        const start = Date.now();
        await fetch(url);
        directResult = \`<span class="success">Direct: Success (unexpected - no CORS!)</span>\`;
      } catch (err) {
        directResult = \`<span class="error">Direct: CORS Error (expected)</span>\n\${err.message}\`;
      }
      
      result.innerHTML = directResult + '\n\nTesting via proxy...';
      
      try {
        const start = Date.now();
        const proxyResponse = await fetch(\`/fetch?url=\${encodeURIComponent(url)}\`);
        const data = await proxyResponse.json();
        const duration = Date.now() - start;
        
        result.innerHTML = directResult + \`
\n\n<span class="success">Proxy: Success (\${duration}ms)</span>
\nStatus: \${proxyResponse.status}
\n\${JSON.stringify(data, null, 2).substring(0, 2000)}\`;
      } catch (err) {
        result.innerHTML = directResult + \`
\n\n<span class="error">Proxy: Error</span>
\n\${err.message}\`;
      }
    }

    async function testScreenshot() {
      const url = document.getElementById('screenshotUrl').value;
      const width = document.getElementById('screenshotWidth').value;
      const height = document.getElementById('screenshotHeight').value;
      const fullPage = document.getElementById('screenshotFullPage').checked;
      const result = document.getElementById('screenshotResult');
      
      if (!url) { result.textContent = 'Please enter a URL'; result.className = 'result error'; return; }
      
      result.classList.remove('hidden');
      result.innerHTML = '<span class="info"> Taking screenshot with Puppeteer... (may take 5-10 seconds)</span>';
      
      try {
        const params = new URLSearchParams({
          url: url,
          width: width,
          height: height,
          fullPage: fullPage
        });
        
        const start = Date.now();
        const response = await fetch(\`/screenshot?\${params.toString()}\`);
        const duration = Date.now() - start;
        
        if (!response.ok) {
          const errorData = await response.json();
          result.innerHTML = \`<span class="error"> Screenshot Failed (\${duration}ms)</span>
\n\nStatus: \${response.status}
\nError: \${errorData.error}
\n\${errorData.details || ''}\`;
          result.className = 'result error';
          return;
        }
        
        const blob = await response.blob();
        const imageUrl = URL.createObjectURL(blob);
        
        result.innerHTML = \`<span class="success"> Screenshot Complete (\${duration}ms)</span>
\n\nSize: \${(blob.size / 1024).toFixed(1)} KB
\nDimensions: \${width}x\${height}\${fullPage ? ' (Full Page)' : ''}
\n\n<img src="\${imageUrl}" style="max-width: 100%; border: 1px solid #30363d; border-radius: 4px; margin-top: 10px;" alt="Screenshot">\`;
        result.className = 'result success';
      } catch (err) {
        result.innerHTML = \`<span class="error"> Error</span>
\n\n\${err.message}\`;
        result.className = 'result error';
      }
    }
  </script>
</body>
</html>
`);
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    details: 'Use GET /fetch?url=<url>, POST /fetch with JSON body, or GET /screenshot?url=<url>'
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// ============================================
// Server Startup
// ============================================

app.listen(PORT, () => {
  console.log(`Secure Proxy API running on http://localhost:${PORT}`);
  console.log(`\nEndpoints:`);
  console.log(`  GET  /fetch?url=<url>&rewrite=true`);
  console.log(`  POST /fetch`);
  console.log(`  GET  /screenshot?url=<url>&width=1920&height=1080&fullPage=false`);
  console.log(`  GET  /social/generate?type=email|phone|name|username&count=5`);
  console.log(`  POST /text/parse-entities`);
  console.log(`  GET  /health`);
  console.log(`\nAllowed domains: ${ALLOWED_DOMAINS.length > 0 ? ALLOWED_DOMAINS.join(', ') : 'ALL (no restrictions)'}`);
  const blockedList = Object.keys(BLOCKED_DOMAINS);
  console.log(`\nBlocked domains: ${blockedList.length > 0 ? blockedList.join(', ') : 'None'}`);
  console.log(`\nTest interface: http://localhost:${PORT}/`);
});
