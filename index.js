require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;

// ─────────────────────────────
// ✅ Global CORS + Preflight Handler
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  // Allow Stripe-Signature so webhook verification works behind proxies/CDNs
  res.header('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});
// ─────────────────────────────

// ⚠️ Important: We will mount express.raw() ONLY on /webhook for signature verification.
// For all other routes, use JSON parser normally.
// ✅ JSON Parser (non-webhook routes)
app.use((req, res, next) => {
  if (req.path === '/webhook') return next(); // skip here; handled per-route
  express.json()(req, res, next);
});

// ✅ Supabase Setup
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ✅ Stripe Setup
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// ─────────────────────────────
// 🔐 AES-256-GCM helpers for encrypting names
// ENCRYPTION_KEY must be a 32-byte key in base64 (generate with:
//   node -e "console.log(require('crypto').randomBytes(32).toString('base64'))" )
function encrypt(text) {
  if (!text) return null;
  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
  if (key.length !== 32) {
    console.warn('ENCRYPTION_KEY is not 32 bytes; encryption will fail.');
    return null;
  }
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Return base64(iv || tag || ciphertext)
  return Buffer.concat([iv, tag, ciphertext]).toString('base64');
}

function decrypt(b64) {
  if (!b64) return null;
  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
  if (key.length !== 32) return null;
  const data = Buffer.from(b64, 'base64');
  const iv = data.slice(0, 12);
  const tag = data.slice(12, 28);
  const ciphertext = data.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plain.toString('utf8');
}

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

// 3️⃣ Stripe: Create Payment Intent (adds metadata for plan & user)
// Frontend should POST: { amount, currency?, plan?, firstName?, lastName?, email? }
app.post('/create-payment-intent', async (req, res) => {
  try {
    const { amount, currency = 'usd', plan = 'starter', firstName = '', lastName = '', email = '' } = req.body;

    if (!amount) {
      return res.status(400).json({ error: 'Missing payment amount' });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount, // in cents (e.g., 500 = $5.00)
      currency,
      automatic_payment_methods: { enabled: true },
      metadata: {
        plan,
        firstName,
        lastName,
        email
      },
    });

    res.json({
      clientSecret: paymentIntent.client_secret,
      id: paymentIntent.id,
    });
  } catch (err) {
    console.error('Stripe error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 4️⃣ Stripe: Create Checkout Session (optional subscription flow)
app.post('/create-checkout-session', async (req, res) => {
  try {
    const { priceId } = req.body;
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: 'https://your-frontend-domain.com/success',
      cancel_url: 'https://your-frontend-domain.com/cancel',
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('Stripe session error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// 5️⃣ Stripe Webhook: verify, then store successful payment in Supabase
// Use express.raw() ONLY for this route (to validate Stripe signature)
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('⚠️  Webhook signature verification failed.', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const pi = event.data.object;

    try {
      // Attempt to retrieve payment method details
      let pm = null;
      if (pi.payment_method) {
        try {
          pm = await stripe.paymentMethods.retrieve(pi.payment_method);
        } catch {}
      }

      // Fallback to charge data if available
      if (!pm && pi.charges && pi.charges.data && pi.charges.data[0]) {
        const charge = pi.charges.data[0];
        if (charge.payment_method_details && charge.payment_method_details.card) {
          pm = { card: charge.payment_method_details.card };
        }
      }

      const amount = pi.amount;
      const currency = pi.currency;
      const stripe_payment_intent = pi.id;
      const plan = pi.metadata?.plan || null;
      const firstName = pi.metadata?.firstName || null;
      const lastName = pi.metadata?.lastName || null;
      const payer_email = pi.metadata?.email || null;

      const last4 = pm?.card?.last4 || null;
      const brand = pm?.card?.brand || null;

      // Encrypt PII (names only)
      const encFirst = firstName ? encrypt(firstName) : null;
      const encLast = lastName ? encrypt(lastName) : null;

      const { data, error } = await supabase
        .from('payments')
        .insert([
          {
            stripe_payment_intent,
            amount,
            currency,
            plan,
            payer_first_name_encrypted: encFirst,
            payer_last_name_encrypted: encLast,
            payer_email,
            card_last4: last4,
            card_brand: brand,
            raw_metadata: pi.metadata || {},
          },
        ])
        .select();

      if (error) {
        console.error('Supabase insert error:', error);
      } else {
        console.log('Payment saved to Supabase:', data?.[0]?.id || 'ok');
      }
    } catch (err) {
      console.error('Error handling payment_intent.succeeded:', err);
    }
  }

  // Acknowledge receipt
  res.json({ received: true });
});

// 6️⃣ Payments history: return decrypted names for a user by email
app.get('/payments/:email', async (req, res) => {
  const { email } = req.params;
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const { data, error } = await supabase
    .from('payments')
    .select('*')
    .eq('payer_email', email)
    .order('created_at', { ascending: false });

  if (error) {
    return res.status(500).json({ error: 'Database error', details: error.message });
  }

  const result = (data || []).map((row) => ({
    id: row.id,
    stripe_payment_intent: row.stripe_payment_intent,
    amount: row.amount,
    currency: row.currency,
    plan: row.plan,
    payer_first_name: decrypt(row.payer_first_name_encrypted),
    payer_last_name: decrypt(row.payer_last_name_encrypted),
    payer_email: row.payer_email,
    card_last4: row.card_last4,
    card_brand: row.card_brand,
    created_at: row.created_at,
  }));

  res.json(result);
});

// 7️⃣ Redirect (must be last non-catchall before fallback)
app.get('/:code', async (req, res) => {
  const { code } = req.params;
  console.log('Redirect request for:', code);

  const { data, error } = await supabase
    .from('links')
    .select('original, click_count')
    .eq('code', code)
    .maybeSingle();

  if (error) {
    console.error('Supabase error:', error);
    return res.status(500).send('Database error');
  }

  if (!data) {
    console.warn('No record found for:', code);
    return res.status(404).send('Link not found');
  }

  await supabase
    .from('links')
    .update({ click_count: (data.click_count ?? 0) + 1 })
    .eq('code', code);

  console.log('Redirecting to:', data.original);
  return res.redirect(data.original);
});

// ─────────────────────────────
// ✅ Explicit OPTIONS route for safety
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature');
  return res.sendStatus(200);
});

// ─────────────────────────────
// ✅ Start server
app.listen(PORT, () => {
  console.log(`Backend running on port ${PORT}`);
});