const express = require('express');
const fetch = require('node-fetch');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// Allow all origins
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Health check
app.get('/health', (req, res) => res.json({ status: 'online' }));

// ── MAIN PROXY ──
app.get('/proxy', async (req, res) => {
  let target = req.query.url;
  if (!target) return res.status(400).json({ error: 'Missing ?url=' });

  try {
    target = decodeURIComponent(target);
    const targetUrl = new URL(target);
    if (!['http:', 'https:'].includes(targetUrl.protocol)) throw new Error('Bad protocol');

    // Block private IPs
    const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
    const blockedPfx = ['10.', '192.168.', '172.'];
    if (blocked.includes(targetUrl.hostname) || blockedPfx.some(p => targetUrl.hostname.startsWith(p))) {
      return res.status(403).send('Blocked');
    }

    let finalUrl = target;
    let response;

    // Follow up to 5 redirects manually
    for (let i = 0; i < 5; i++) {
      response = await makeRequest(finalUrl);
      if (response.redirect) {
        let loc = response.redirect;
        if (loc.startsWith('/')) {
          const u = new URL(finalUrl);
          loc = `${u.protocol}//${u.host}${loc}`;
        }
        finalUrl = loc;
      } else {
        break;
      }
    }

    const ct = response.contentType || 'text/html';
    let body = response.body;

    if (ct.includes('text/html')) {
      const u = new URL(finalUrl);
      const base = `${u.protocol}//${u.host}`;
      const basePath = u.pathname.replace(/\/[^/]*$/, '/') || '/';

      // Inject base tag
      body = body.replace(/<head([^>]*)>/i, `<head$1><base href="${base}${basePath}">`);

      // Kill frame busting
      body = body.replace(/if\s*\(\s*(?:top|parent|window\.top)\s*!==?\s*(?:self|window)\s*\)/gi, 'if(false)');
      body = body.replace(/top\.location(\.href)?\s*=/gi, '//__=');
      body = body.replace(/window\.top\.location(\.href)?\s*=/gi, '//__=');
      body = body.replace(/parent\.location(\.href)?\s*=/gi, '//__=');

      // Rewrite all absolute URLs to go through this proxy
      const proxyBase = `${req.protocol}://${req.get('host')}/proxy?url=`;
      body = body.replace(/(href|src|action)=["'](https?:\/\/[^"'> ]+)["']/gi, (match, attr, url) => {
        return `${attr}="${proxyBase}${encodeURIComponent(url)}"`;
      });

      // Rewrite inline style url()
      body = body.replace(/url\(["']?(https?:\/\/[^)"']+)["']?\)/gi, (match, url) => {
        return `url("${proxyBase}${encodeURIComponent(url)}")`;
      });
    }

    // Strip headers that break embedding
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy');
    res.removeHeader('X-Content-Type-Options');

    res.setHeader('Content-Type', ct);
    res.setHeader('X-Proxied-By', 'RailProxy');
    res.status(200).send(body);

  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

function makeRequest(urlStr) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(urlStr); } catch (e) { return reject(e); }

    const lib = parsed.protocol === 'https:' ? https : http;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: (parsed.pathname || '/') + (parsed.search || ''),
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'identity',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'Upgrade-Insecure-Requests': '1',
      },
      rejectUnauthorized: false,
      timeout: 20000,
    };

    const req = lib.request(opts, (res) => {
      // Redirect
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
        return resolve({ redirect: res.headers.location });
      }

      const chunks = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('end', () => resolve({
        body: Buffer.concat(chunks).toString('utf8'),
        contentType: res.headers['content-type'] || 'text/html',
        status: res.statusCode,
      }));
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

app.listen(PORT, () => console.log(`RailProxy running on port ${PORT}`));
