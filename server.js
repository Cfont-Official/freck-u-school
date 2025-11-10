// server.js - Render-ready DDG reverse proxy for iframe embedding
import express from "express";
import fetch from "node-fetch";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import * as cheerio from "cheerio";
import sanitizeHtml from "sanitize-html";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;

// Config
const DEFAULT_SAFE = (process.env.DEFAULT_SAFE || "moderate").toLowerCase(); // off|moderate|strict
const FETCH_TIMEOUT_MS = 10000;
const MAX_RESPONSE_BYTES = 6_000_000;

// Security headers (we will tweak frame policies for the proxied route)
app.use(helmet({ contentSecurityPolicy: false }));
app.use((req, res, next) => {
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN"); // keep defaults for app pages
  next();
});

// static UI
app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));

// basic rate limiting
app.use(rateLimit({
  windowMs: 60_000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false
}));

// helper: map safe string to ddg kp param
function safeToKp(safe) {
  safe = (safe || "").toLowerCase();
  if (safe === "strict") return "1";
  if (safe === "off") return "-2"; // ddg: -2 = off
  // moderate
  return "-1";
}

// normalize safe param with default
function validateSafe(s) {
  if (!s) return DEFAULT_SAFE;
  s = s.toLowerCase();
  if (["off", "moderate", "strict"].includes(s)) return s;
  return DEFAULT_SAFE;
}

// fetch helper with timeout
async function fetchWithTimeout(url, options = {}, timeoutMs = FETCH_TIMEOUT_MS) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// Build DuckDuckGo URL from incoming path/query
function buildDuckUrl(reqPath, query) {
  // If client directly requested /ddg with a full URL param, we could handle, but here we'll map search route.
  // We'll fetch main ddg pages under 'https://duckduckgo.com' + reqPath (preserving path)
  const base = new URL("https://duckduckgo.com");
  // append requested path (e.g., /?q=..., /i.js, /html/)
  const pathStr = reqPath || "/";
  // Build url by resolving path relative to root
  const full = new URL(pathStr, base);
  // Copy query params
  for (const [k, v] of Object.entries(query || {})) {
    // skip internal safe param (we'll set kp)
    if (k === "safe") continue;
    full.searchParams.set(k, v);
  }
  return full;
}

// Proxy route: use /ddg/* to fetch duckduckgo resources and rewrite
app.get("/ddg/*", async (req, res) => {
  // Extract path after /ddg
  const reqPath = req.originalUrl.replace(/^\/ddg/, "") || "/";
  const safe = validateSafe(req.query.safe);
  const kp = safeToKp(safe);

  // Build upstream DDG URL and enforce kp parameter for SafeSearch (unless off)
  const upstream = buildDuckUrl(reqPath, req.query);
  // if user requested search via /ddg/?q=... ensure kp present
  if (kp !== "-2") upstream.searchParams.set("kp", kp);
  upstream.searchParams.set("kl", "us-en");

  try {
    const upstreamRes = await fetchWithTimeout(upstream.toString(), {
      headers: {
        "User-Agent": "ddg-iframe-proxy/1.0 (+privacy)",
        "Accept": "*/*"
      }
    });

    const contentType = upstreamRes.headers.get("content-type") || "";

    // For HTML responses - rewrite links and sanitize
    if (contentType.includes("text/html")) {
      let html = await upstreamRes.text();

      // Sanitize: remove inline event handlers and script tags (we disallow scripts)
      html = sanitizeHtml(html, {
        allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img','header','footer','main','section','div','span','a','p','form','input','button','link']),
        allowedAttributes: {
          a: ['href','title','rel','target'],
          img: ['src','alt','width','height'],
          form: ['action','method'],
          input: ['type','name','value','placeholder'],
          '*': ['class','id','style']
        },
        allowedSchemes: ['http','https','data'],
        transformTags: {
          'a': function(tagName, attribs) {
            const href = attribs.href || '';
            // avoid javascript: URIs
            if (/^\s*javascript:/i.test(href)) {
              return { tagName: 'a', attribs: { href: '#', rel: 'nofollow', target: '_blank' } };
            }
            // proxify internal DDG links so they go through /ddg/
            try {
              const url = new URL(href, "https://duckduckgo.com");
              if (url.hostname && url.hostname.endsWith("duckduckgo.com")) {
                // convert absolute ddg URL to our /ddg/<path>?<params>
                const path = url.pathname + (url.search || "");
                return { tagName: 'a', attribs: { href: `/ddg${path}`, rel: 'noopener noreferrer', target: '_self' } };
              }
              // external links open in new tab
              return { tagName: 'a', attribs: { href: url.toString(), rel: 'noopener noreferrer', target: '_blank' } };
            } catch (e) {
              return { tagName: 'a', attribs: { href: '#', rel: 'nofollow', target: '_blank' } };
            }
          }
        }
      });

      // Use cheerio to further adjust resources (images, links, forms)
      const $ = cheerio.load(html, { decodeEntities: false });

      // Remove script tags explicitly (sanity)
      $('script').remove();

      // Rewrite form actions to route through /ddg and enforce safe param
      $('form').each((i, el) => {
        try {
          const $f = $(el);
          const action = $f.attr('action') || '/';
          const resolved = new URL(action, "https://duckduckgo.com");
          // ensure kp set
          if (kp !== "-2") resolved.searchParams.set('kp', kp);
          // route through proxy
          $f.attr('action', '/ddg' + resolved.pathname + resolved.search);
          $f.attr('method', 'GET');
        } catch {
          $f.attr('action', '/ddg/');
          $f.attr('method', 'GET');
        }
      });

      // Rewrite images to route through /ddg
      $('img').each((i, el) => {
        const $img = $(el);
        const src = $img.attr('src');
        if (!src) return;
        try {
          const u = new URL(src, "https://duckduckgo.com");
          if (u.hostname && u.hostname.endsWith("duckduckgo.com")) {
            $img.attr('src', '/ddg' + u.pathname + (u.search || ''));
          } else {
            // leave external images absolute
            $img.attr('src', u.toString());
          }
        } catch {
          // leave as-is
        }
      });

      // Add small banner to indicate proxied page
      $('body').prepend('<div style="font-family:system-ui,Arial,sans-serif;padding:6px;background:#f3f4f6;border-bottom:1px solid #e5e7eb;text-align:center;font-size:13px;">Proxied DuckDuckGo — SafeSearch: ' + safe + '</div>');

      let out = $.html();

      if (Buffer.byteLength(out, 'utf8') > MAX_RESPONSE_BYTES) {
        return res.status(413).send("Proxied response too large");
      }

      // Remove upstream frame-blocking headers by setting our own
      res.removeHeader('X-Frame-Options');
      // Allow framing of this proxied page by our domain
      res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline' data: https:; frame-ancestors 'self'");

      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(out);
    }

    // Non-HTML (images, css, js) - stream through but enforce size limit
    const buf = await upstreamRes.arrayBuffer();
    const b = Buffer.from(buf);
    if (b.length > MAX_RESPONSE_BYTES) return res.status(413).send("Resource too large");
    // pass content-type
    const ct = upstreamRes.headers.get("content-type");
    if (ct) res.setHeader("Content-Type", ct);
    // Allow framing for resources
    res.setHeader('Content-Security-Policy', "default-src 'self' data: https:; frame-ancestors 'self'");
    return res.send(b);

  } catch (err) {
    console.error("Upstream fetch error:", err && err.stack ? err.stack : err);
    // if fetch abort or network error
    if (err.name === 'AbortError') return res.status(504).send("Upstream timeout");
    return res.status(502).send("Bad gateway fetching upstream");
  }
});

// convenience route: /ddg (root) -> fetch root ddg page
app.get("/ddg", (req, res) => {
  // redirect to /ddg/ to keep path resolution consistent
  res.redirect(302, "/ddg/");
});

// start server
app.listen(PORT, () => {
  console.log(`ddg-iframe-proxy listening on port ${PORT}`);
});
