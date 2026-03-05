const express = require('express');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

app.get('/health', (req, res) => res.json({ status: 'online' }));

app.get('/proxy', async (req, res) => {
  let target = req.query.url;
  if (!target) return res.status(400).json({ error: 'Missing ?url=' });

  try {
    target = decodeURIComponent(target);
    if (!/^https?:\/\//i.test(target)) target = 'https://' + target;

    const targetUrl = new URL(target);
    const blocked = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];
    const blockedPfx = ['10.', '192.168.', '172.'];
    if (blocked.includes(targetUrl.hostname) || blockedPfx.some(p => targetUrl.hostname.startsWith(p))) {
      return res.status(403).send('Blocked');
    }

    // Follow redirects up to 5 hops
    let finalUrl = target;
    let response;
    for (let i = 0; i < 5; i++) {
      response = await makeRequest(finalUrl);
      if (response.redirect) {
        let loc = response.redirect;
        const base = new URL(finalUrl);
        if (loc.startsWith('//')) loc = base.protocol + loc;
        else if (loc.startsWith('/')) loc = `${base.protocol}//${base.host}${loc}`;
        else if (!loc.startsWith('http')) loc = `${base.protocol}//${base.host}/${loc}`;
        finalUrl = loc;
      } else {
        break;
      }
    }

    const ct = response.contentType || 'text/html';
    res.removeHeader('X-Frame-Options');
    res.removeHeader('Content-Security-Policy');
    res.removeHeader('X-Content-Type-Options');
    res.setHeader('Content-Type', ct);
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Non-HTML assets — send raw buffer so images/css/js load correctly
    if (!ct.includes('text/html')) {
      return res.status(200).send(response.rawBuffer);
    }

    // HTML — rewrite everything so it stays proxied
    const u = new URL(finalUrl);
    const origin = `${u.protocol}//${u.host}`;
    const proxyBase = `/proxy?url=`;
    let body = response.body;

    // Inject base + kill frame busting + kill service workers via script
    const inject = `
<script>
// Kill all redirect attempts
Object.defineProperty(window, 'top', { get: () => window });
Object.defineProperty(window, 'parent', { get: () => window });
Object.defineProperty(window, 'frameElement', { get: () => null });
const _open = window.open; window.open = (u,...a) => { if(u) location.href='/proxy?url='+encodeURIComponent(u); };
// Kill service workers
if(navigator.serviceWorker){ navigator.serviceWorker.getRegistrations().then(r=>r.forEach(s=>s.unregister())); }
</script>`;

    // Add base tag and inject script right after <head>
    body = body.replace(/<head([^>]*)>/i, `<head$1><base href="${origin}${u.pathname.replace(/\/[^/]*$/,'/')||'/'}">` + inject);

    // Rewrite href, src, action, srcset to go through proxy
    body = body.replace(/\b(href|src|action)=["'](https?:\/\/[^"'> ]+)["']/gi, (m, attr, url) =>
      `${attr}="${proxyBase}${encodeURIComponent(url)}"`);
    body = body.replace(/\b(href|src|action)=["'](\/[^"'> ]+)["']/gi, (m, attr, path) =>
      `${attr}="${proxyBase}${encodeURIComponent(origin + path)}"`);
    body = body.replace(/srcset=["']([^"']+)["']/gi, (m, set) => {
      const rewritten = set.replace(/(https?:\/\/[^\s,]+)/g, url => `/proxy?url=${encodeURIComponent(url)}`);
      return `srcset="${rewritten}"`;
    });

    // Rewrite CSS url()
    body = body.replace(/url\(["']?(https?:\/\/[^)"']+)["']?\)/gi, (m, url) =>
      `url("${proxyBase}${encodeURIComponent(url)}")`);
    body = body.replace(/url\(["']?(\/[^)"']+)["']?\)/gi, (m, path) =>
      `url("${proxyBase}${encodeURIComponent(origin + path)}")`);

    // Kill JS redirects
    body = body.replace(/location\.href\s*=/g, '//__loc=');
    body = body.replace(/location\.replace\s*\(/g, '//__replace(');
    body = body.replace(/location\.assign\s*\(/g, '//__assign(');
    body = body.replace(/window\.location\s*=/g, '//__wloc=');
    body = body.replace(/top\.location/g, 'window.location');
    body = body.replace(/parent\.location/g, 'window.location');

    // Remove CSP meta tags
    body = body.replace(/<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi, '');

    res.status(200).send(body);

  } catch (err) {
    console.error('Proxy error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

function makeRequest(urlStr) {
  return new Promise((resolve, reject) => {
    let parsed;
    try { parsed = new URL(urlStr); } catch(e) { return reject(e); }

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
      if ([301,302,303,307,308].includes(res.statusCode) && res.headers.location) {
        return resolve({ redirect: res.headers.location });
      }
      const chunks = [];
      res.on('data', chunk => chunks.push(Buffer.from(chunk)));
      res.on('end', () => {
        const rawBuffer = Buffer.concat(chunks);
        resolve({
          body: rawBuffer.toString('utf8'),
          rawBuffer,
          contentType: res.headers['content-type'] || 'text/html',
          status: res.statusCode,
        });
      });
    });

    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

app.listen(PORT, () => console.log(`RailProxy online — port ${PORT}`));
