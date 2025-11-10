/**
 * Minimal Express proxy skeleton for Render
 * Allows embedding in an iframe
 */

import express from "express";
import fetch from "node-fetch"; // make sure node-fetch is installed

const app = express();

// Allow being framed anywhere
app.use((req, res, next) => {
  res.removeHeader("X-Frame-Options");
  res.setHeader("Content-Security-Policy", "frame-ancestors *");
  next();
});

// Example route: proxy a harmless public site (example.com)
app.get("/proxy", async (req, res) => {
  const target = "https://example.com"; // placeholder target
  try {
    const resp = await fetch(target);
    const text = await resp.text();
    res.type("html").send(text);
  } catch (err) {
    res.status(500).send("Proxy error: " + err.message);
  }
});

// Root route
app.get("/", (req, res) => {
  res.send(`
    <h2>Proxy server running</h2>
    <p>Try loading <a href="/proxy" target="_blank">/proxy</a></p>
  `);
});

// Use Render's provided port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
