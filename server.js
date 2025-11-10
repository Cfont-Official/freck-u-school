import express from "express";
import fetch from "node-fetch";

const app = express();

// allow embedding in an iframe
app.use((req, res, next) => {
  res.removeHeader("X-Frame-Options");
  res.setHeader("Content-Security-Policy", "frame-ancestors *");
  next();
});

// simple homepage
app.get("/", (req, res) => {
  res.send(`
    <h2>Proxy server running</h2>
    <p>Example routes:</p>
    <ul>
      <li><a href="/proxy" target="_blank">/proxy</a> – fetches example.com</li>
      <li><a href="/search?q=cats" target="_blank">/search?q=cats</a> – demo safe search</li>
    </ul>
  `);
});

// proxy example
app.get("/proxy", async (req, res) => {
  const target = "https://example.com";
  try {
    const resp = await fetch(target);
    const text = await resp.text();
    res.type("html").send(text);
  } catch (err) {
    res.status(500).send("Proxy error: " + err.message);
  }
});

// basic search passthrough (to a *public*, safe search endpoint)
app.get("/search", async (req, res) => {
  const q = encodeURIComponent(req.query.q || "");
  if (!q) return res.status(400).send("Missing search query ?q=");

  // we’ll use DuckDuckGo’s *instant answer API*, which is safe and JSON-based
  const api = `https://api.duckduckgo.com/?q=${q}&format=json&safe=active`;

  try {
    const r = await fetch(api);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).send("Search error: " + e.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
