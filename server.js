const express = require('express');
const rateLimit = require('express-rate-limit');
const { URL } = require('url');
const puppeteer = require('puppeteer');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// Screenshot Browser Instance
// ============================================

let browser = null;

/**
 * Get or create shared browser instance for screenshots
 */
async function getBrowser() {
  if (!browser) {
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-accelerated-2d-canvas',
        '--disable-gpu',
        '--window-size=1920,1080',
      ],
    });
    console.log('[Screenshot] Browser instance launched');
  }
  return browser;
}

/**
 * Take a screenshot of a webpage
 * @param {string} targetUrl - URL to screenshot
 * @param {object} options - Screenshot options
 * @returns {Buffer} - PNG image buffer
 */
async function takeScreenshot(targetUrl, options = {}) {
  const {
    width = 1920,
    height = 1080,
    fullPage = false,
    waitFor = 3000,
    selector = null,
    timeout = 30000,
  } = options;

  const browserInstance = await getBrowser();
  const page = await browserInstance.newPage();

  try {
    // Set viewport
    await page.setViewport({
      width: parseInt(width),
      height: parseInt(height),
      deviceScaleFactor: 1,
    });

    // Block unnecessary resources for faster loading
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      const resourceType = req.resourceType();
      if (resourceType === 'font' || resourceType === 'media' || resourceType === 'stylesheet') {
        req.abort();
      } else {
        req.continue();
      }
    });

    // Navigate to page - use 'load' instead of 'networkidle2' for faster completion
    await page.goto(targetUrl, {
      waitUntil: 'load',
      timeout: parseInt(timeout),
    });

    // Wait for specified time
    await new Promise(resolve => setTimeout(resolve, parseInt(waitFor)));

    // Wait for selector if specified
    if (selector) {
      try {
        await page.waitForSelector(selector, { timeout: 5000 });
      } catch (e) {
        console.log(`[Screenshot] Selector "${selector}" not found, continuing...`);
      }
    }

    // Take screenshot
    const screenshotOptions = {
      type: 'png',
      encoding: 'binary',
    };

    if (fullPage) {
      screenshotOptions.fullPage = true;
    }

    const screenshot = await page.screenshot(screenshotOptions);

    return Buffer.from(screenshot);
  } finally {
    await page.close();
  }
}

// ============================================
// Configuration
// ============================================

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
 * Handles: src, href, srcset, data-src, poster, action, and CSS url()
 * @param {string} html - The HTML content to rewrite
 * @param {string} baseUrl - The base URL of the fetched page
 * @returns {string} - Rewritten HTML
 */
function rewriteHtml(html, baseUrl) {
  const base = new URL(baseUrl);
  
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
  
  // Rewrite src attributes (images, scripts, iframes, videos, audio)
  html = html.replace(
    /\bsrc\s*=\s*["']([^"']+)["']/gi,
    (match, url) => `src="${proxyUrl(url)}"`
  );
  
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
    
    // For HTML with rewrite enabled, we need text
    if (shouldRewrite) {
      const textBody = await response.text();
      const rewrittenHtml = rewriteHtml(textBody, targetUrl);
      res.set('Content-Type', 'text/html');
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

// GET /screenshot endpoint
app.get('/screenshot', async (req, res) => {
  const { 
    url, 
    width = 1920, 
    height = 1080, 
    fullPage = 'false',
    waitFor = 3000,
    selector = null,
  } = req.query;

  // Validate URL
  const validation = validateUrl(url);
  if (validation.valid === false) {
    return res.status(403).json({
      error: validation.error,
      details: validation.blockedDomain ? 'This domain is blocked by the proxy' : 'URL validation failed'
    });
  }

  // Parse fullPage parameter
  const fullPageBool = fullPage === 'true' || fullPage === '1';
  
  // Allow custom timeout (max 120 seconds)
  const timeoutMs = Math.min(parseInt(req.query.timeout) || 30000, 120000);

  try {
    console.log(`[Screenshot] Capturing: ${url} (${width}x${height}, fullPage=${fullPageBool}, timeout=${timeoutMs}ms)`);
    
    const screenshotBuffer = await takeScreenshot(validation.href, {
      width,
      height,
      fullPage: fullPageBool,
      waitFor,
      selector,
      timeout: timeoutMs,
    });

    // Set headers for image response
    res.set('Content-Type', 'image/png');
    res.set('Content-Length', screenshotBuffer.length);
    res.set('Cache-Control', 'public, max-age=300'); // Cache for 5 minutes
    
    res.send(screenshotBuffer);
    
    console.log(`[Screenshot] Completed: ${screenshotBuffer.length} bytes`);
  } catch (error) {
    console.error('[Screenshot] Error:', error.message);
    
    // Check if it's a navigation error
    if (error.message.includes('net::') || error.message.includes('Navigation failed')) {
      return res.status(502).json({
        error: 'Failed to navigate to target URL',
        details: error.message
      });
    }
    
    // Check for timeout specifically
    if (error.message.includes('timeout') || error.message.includes('Timeout')) {
      return res.status(504).json({
        error: 'Navigation timeout - page took too long to load',
        details: error.message,
        suggestion: 'Try increasing timeout with ?timeout=60000 (up to 120000ms), or the page may be too slow/unresponsive'
      });
    }
    
    return res.status(500).json({
      error: 'Screenshot failed',
      details: error.message
    });
  }
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
