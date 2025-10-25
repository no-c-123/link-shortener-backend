require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 8080;

// ─────────────────────────────
// ✅ Global CORS + Preflight Handler
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});
// ─────────────────────────────

// ✅ JSON Parser
app.use(express.json());

// ✅ Supabase Setup
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ─────────────────────────────
// ✅ ROUTES

// 1️⃣ Create short link
app.post('/shorten', async (req, res) => {
  const { originalUrl, customCode } = req.body;
  const code = (customCode || Math.random().toString(36).substring(2, 7)).toLowerCase();

  if (!originalUrl) {
    return res.status(400).json({ error: 'Missing URL' });
  }

  try {
    const { data, error } = await supabase
      .from('links')
      .insert([{ code, original: originalUrl }])
      .select()
      .single();

    if (error) {
      return res.status(500).json({
        error: 'Database error',
        details: error.message,
      });
    }

    res.json({
      shortUrl: `https://link-shortener-backend-production.up.railway.app/${code}`,
      linkData: data,
    });
  } catch (err) {
    res.status(500).json({
      error: 'Unexpected server error',
      details: err.message,
    });
  }
});

// 2️⃣ Info endpoint (must be before redirect)
app.get('/info/:code', async (req, res) => {
  const { code } = req.params;
  const { data, error } = await supabase
    .from('links')
    .select('*')
    .eq('code', code)
    .maybeSingle();

  if (error || !data) {
    return res.status(404).json({ error: 'Link not found' });
  }

  res.json(data);
});

// 3️⃣ Redirect (must be last)
app.get('/:code', async (req, res) => {
  const { code } = req.params;
  console.log("Redirect request for:", code);

  const { data, error } = await supabase
    .from('links')
    .select('original, click_count')
    .eq('code', code)
    .maybeSingle();

  if (error) {
    console.error("Supabase error:", error);
    return res.status(500).send('Database error');
  }

  if (!data) {
    console.warn("No record found for:", code);
    return res.status(404).send('Link not found');
  }

  await supabase
    .from('links')
    .update({ click_count: (data.click_count ?? 0) + 1 })
    .eq('code', code);

  console.log("Redirecting to:", data.original);
  return res.redirect(data.original);
});

// ─────────────────────────────
// ✅ Explicit OPTIONS route for safety (fixes any lingering 502s)
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  return res.sendStatus(200);
});

// ─────────────────────────────
// ✅ Start server
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});