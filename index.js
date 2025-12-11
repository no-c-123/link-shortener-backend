require('dotenv').config();
const express = require('express');
const { createClient } = require('@supabase/supabase-js');
const Stripe = require('stripe');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { body, param, validationResult } = require('express-validator');

const app = express();
const PORT = process.env.PORT || 8080;

// ─────────────────────────────
// 🔒 SECURITY MIDDLEWARE
// ─────────────────────────────

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP for API (can be configured per route if needed)
  crossOriginEmbedderPolicy: false,
}));

// ─────────────────────────────
// ✅ Global CORS + Preflight Handler
// ─────────────────────────────
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',')
  : ['http://localhost:4321', 'http://localhost:3000'];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || !origin) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature, X-Requested-With, Authorization, x-api-key');
  res.header('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ─────────────────────────────
// ⚠️ Important: We will mount express.raw() ONLY on /webhook for signature verification.
// For all other routes, use JSON parser normally.
// ✅ JSON Parser (non-webhook routes)
// ─────────────────────────────
app.use((req, res, next) => {
  if (req.path === '/webhook') return next(); // skip here; handled per-route
  express.json({ limit: '10mb' })(req, res, next);
});

// ─────────────────────────────
// 🛡️ RATE LIMITING
// ─────────────────────────────
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
});

const paymentLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // limit each IP to 10 payment requests per hour
  message: 'Too many payment requests from this IP, please try again later.',
});

// Apply general rate limiting to all routes
app.use(generalLimiter);

// ─────────────────────────────
// ✅ VALIDATION MIDDLEWARE
// ─────────────────────────────
const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

// ─────────────────────────────
// ✅ URL VALIDATION & SANITIZATION
// ─────────────────────────────
function isValidUrl(string) {
  try {
    const url = new URL(string);
    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      return false;
    }
    // Block localhost and private IPs (unless in development)
    if (process.env.NODE_ENV === 'production') {
      const hostname = url.hostname.toLowerCase();
      if (hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname.startsWith('192.168.') ||
        hostname.startsWith('10.') ||
        hostname.startsWith('172.16.') ||
        hostname.startsWith('172.17.') ||
        hostname.startsWith('172.18.') ||
        hostname.startsWith('172.19.') ||
        hostname.startsWith('172.20.') ||
        hostname.startsWith('172.21.') ||
        hostname.startsWith('172.22.') ||
        hostname.startsWith('172.23.') ||
        hostname.startsWith('172.24.') ||
        hostname.startsWith('172.25.') ||
        hostname.startsWith('172.26.') ||
        hostname.startsWith('172.27.') ||
        hostname.startsWith('172.28.') ||
        hostname.startsWith('172.29.') ||
        hostname.startsWith('172.30.') ||
        hostname.startsWith('172.31.')) {
        return false;
      }
    }
    return true;
  } catch (_) {
    return false;
  }
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  // Remove null bytes and trim whitespace
  return input.replace(/\0/g, '').trim();
}

function sanitizeCode(code) {
  if (typeof code !== 'string') return null;
  // Only allow alphanumeric characters and hyphens, max 20 chars
  const sanitized = code.replace(/[^a-zA-Z0-9-]/g, '').substring(0, 20);
  return sanitized.length > 0 ? sanitized.toLowerCase() : null;
}

// ─────────────────────────────
// ✅ ENVIRONMENT VALIDATION
// ─────────────────────────────
function validateEnvironment() {
  const required = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SECRET_STRIPE_PUBLISHABLE_KEY', 'ENCRYPTION_KEY'];
  const missing = required.filter(key => !process.env[key]);

  if (missing.length > 0) {
    console.error('❌ Missing required environment variables:', missing.join(', '));
    process.exit(1);
  }

  // Validate encryption key
  try {
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) {
      console.error('❌ ENCRYPTION_KEY must be exactly 32 bytes (base64 encoded)');
      console.error('   Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"');
      process.exit(1);
    }
  } catch (err) {
    console.error('❌ ENCRYPTION_KEY is not valid base64');
    process.exit(1);
  }
}

validateEnvironment();

// ─────────────────────────────
// ✅ Supabase Setup
// ─────────────────────────────
// Use service role key for backend operations to bypass RLS
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
);

// ─────────────────────────────
// ✅ Stripe Setup
// ─────────────────────────────
const stripe = Stripe(process.env.SECRET_STRIPE_PUBLISHABLE_KEY);

// ─────────────────────────────
// 🔐 AES-256-GCM helpers for encrypting names
// ─────────────────────────────
function encrypt(text) {
  if (!text || typeof text !== 'string') return null;

  try {
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) {
      console.error('ENCRYPTION_KEY is not 32 bytes; encryption failed.');
      return null;
    }
    const iv = crypto.randomBytes(12); // 96-bit IV for GCM
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    // Return base64(iv || tag || ciphertext)
    return Buffer.concat([iv, tag, ciphertext]).toString('base64');
  } catch (err) {
    console.error('Encryption error:', err.message);
    return null;
  }
}

function decrypt(b64) {
  if (!b64 || typeof b64 !== 'string') return null;

  try {
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) return null;
    const data = Buffer.from(b64, 'base64');
    if (data.length < 28) return null; // Minimum size check
    const iv = data.slice(0, 12);
    const tag = data.slice(12, 28);
    const ciphertext = data.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plain.toString('utf8');
  } catch (err) {
    console.error('Decryption error:', err.message);
    return null;
  }
}

// ─────────────────────────────
// 🎯 PREMIUM FEATURE HELPERS
// ─────────────────────────────
async function getUserSubscription(userId) {
  if (!userId) return { plan: 'free', status: 'active' };
  
  const { data, error } = await supabase
    .from('user_subscriptions')
    .select('*')
    .eq('user_id', userId)
    .eq('status', 'active')
    .maybeSingle();
  
  if (error) {
    console.error('Error fetching subscription:', error);
    return { plan: 'free', status: 'active' };
  }
  
  // Check if subscription is expired
  if (data?.expires_at && new Date(data.expires_at) < new Date()) {
    // Update status to expired
    await supabase
      .from('user_subscriptions')
      .update({ status: 'expired' })
      .eq('id', data.id);
    return { plan: 'free', status: 'expired' };
  }
  
  return data || { plan: 'free', status: 'active' };
}

async function requiresPremium(req, res, next) {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];
  let userId = null;

  // Get user ID from auth token or API key
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const { data: { user } } = await supabase.auth.getUser(token);
    userId = user?.id || null;
  } else if (apiKey) {
    const hash = crypto.createHash('sha256').update(apiKey).digest('hex');
    const { data: keyData } = await supabase
      .from('api_keys')
      .select('user_id')
      .eq('key_hash', hash)
      .maybeSingle();
    userId = keyData?.user_id || null;
  }

  if (!userId) {
    return res.status(401).json({ 
      error: 'Authentication required',
      message: 'Please log in to access premium features'
    });
  }

  const subscription = await getUserSubscription(userId);
  
  if (subscription.plan === 'free') {
    return res.status(403).json({ 
      error: 'Premium feature',
      message: 'This feature requires a premium subscription. Please upgrade your plan.',
      currentPlan: 'free'
    });
  }

  req.userSubscription = subscription;
  req.userId = userId;
  next();
}

function decrypt(b64) {
  if (!b64 || typeof b64 !== 'string') return null;

  try {
    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'base64');
    if (key.length !== 32) return null;
    const data = Buffer.from(b64, 'base64');
    if (data.length < 28) return null; // Minimum size check
    const iv = data.slice(0, 12);
    const tag = data.slice(12, 28);
    const ciphertext = data.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plain.toString('utf8');
  } catch (err) {
    console.error('Decryption error:', err.message);
    return null;
  }
}

// ─────────────────────────────
// ✅ ROUTES
// ─────────────────────────────

// 1️⃣ Create short link
app.post('/shorten',
  strictLimiter,
  [
    body('originalUrl')
      .notEmpty()
      .withMessage('URL is required')
      .isLength({ max: 2048 })
      .withMessage('URL is too long (max 2048 characters)')
      .custom((value) => {
        const sanitized = sanitizeInput(value);
        if (!isValidUrl(sanitized)) {
          throw new Error('Invalid URL format. Only http and https URLs are allowed.');
        }
        return true;
      }),
    body('customCode')
      .optional()
      .isLength({ min: 1, max: 20 })
      .withMessage('Custom code must be between 1 and 20 characters')
      .matches(/^[a-zA-Z0-9-]+$/)
      .withMessage('Custom code can only contain letters, numbers, and hyphens'),
    body('expiresAt')
      .optional()
      .isISO8601()
      .withMessage('Invalid expiration date format'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      let { originalUrl, customCode, expiresAt } = req.body;

      // Sanitize inputs
      originalUrl = sanitizeInput(originalUrl);

      // Validate URL again after sanitization
      if (!isValidUrl(originalUrl)) {
        return res.status(400).json({
          error: 'Invalid URL format. Only http and https URLs are allowed.'
        });
      }

      // Generate or sanitize code
      let code;
      if (customCode) {
        code = sanitizeCode(customCode);
        if (!code) {
          return res.status(400).json({
            error: 'Invalid custom code format'
          });
        }
      } else {
        code = Math.random().toString(36).substring(2, 7).toLowerCase();
      }

      // Check if code already exists
      const { data: existing } = await supabase
        .from('links')
        .select('code')
        .eq('code', code)
        .maybeSingle();

      if (existing) {
        if (customCode) {
          return res.status(409).json({
            error: 'Custom code already exists'
          });
        }
        // Regenerate if random code exists (very unlikely)
        code = Math.random().toString(36).substring(2, 7).toLowerCase();
      }

      // Authentication & User Association
      let userId = null;
      const authHeader = req.headers.authorization;
      const apiKey = req.headers['x-api-key'];

      if (authHeader?.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const { data: { user } } = await supabase.auth.getUser(token);
        userId = user?.id || null;
      } else if (apiKey) {
        // Validate API Key
        // Note: In a real production app, you'd hash the incoming key and compare with stored hash
        // For this implementation, we'll assume the key is stored directly or we have a way to lookup
        // Since we defined key_hash in migration, let's assume we are receiving the raw key and need to hash it
        // BUT for simplicity in this immediate fix, we will check if we can find the key. 
        // Ideally, we should use a secure hash comparison.

        // Let's assume for now we just look it up directly if we stored it directly, 
        // or if we stored a hash, we hash this input.
        // Given the migration said 'key_hash', let's implement a simple hash check.
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256').update(apiKey).digest('hex');

        const { data: keyData } = await supabase
          .from('api_keys')
          .select('user_id')
          .eq('key_hash', hash)
          .single();

        if (keyData) {
          userId = keyData.user_id;
          // Update last_used_at
          await supabase.from('api_keys').update({ last_used_at: new Date() }).eq('key_hash', hash);
        }
      }

      // Check if expiration is requested (premium only)
      if (expiresAt) {
        if (!userId) {
          return res.status(401).json({
            error: 'Authentication required',
            message: 'Link expiration requires authentication'
          });
        }
        
        const subscription = await getUserSubscription(userId);
        if (subscription.plan === 'free') {
          return res.status(403).json({
            error: 'Premium feature',
            message: 'Link expiration is a premium feature. Please upgrade your plan.',
            currentPlan: 'free'
          });
        }
      }

      const insertData = { code, original: originalUrl };
      if (userId) {
        insertData.user_id = userId;
      }
      if (expiresAt) {
        insertData.expires_at = expiresAt;
      }

      const { data, error } = await supabase
        .from('links')
        .insert([insertData])
        .select()
        .single();

      if (error) {
        console.error('Database error:', error);
        return res.status(500).json({
          error: 'Database error',
          details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
        });
      }

      const baseUrl = process.env.BACKEND_URL || 'https://link-shortener-backend-production.up.railway.app';
      res.json({
        shortUrl: `${baseUrl}/${code}`,
        linkData: data,
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({
        error: 'Unexpected server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 1.5️⃣ Generate API Key
app.post('/api-key',
  strictLimiter,
  async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.substring(7);
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const crypto = require('crypto');
    const rawKey = 'sk_' + crypto.randomBytes(24).toString('hex');
    const hash = crypto.createHash('sha256').update(rawKey).digest('hex');

    const { data, error } = await supabase
      .from('api_keys')
      .insert([{
        user_id: user.id,
        key_hash: hash,
        name: req.body.name || 'Default Key'
      }])
      .select()
      .single();

    if (error) {
      console.error('Error creating API key:', error);
      return res.status(500).json({ error: 'Failed to create API key' });
    }

    // Return the raw key ONLY ONCE
    res.json({ apiKey: rawKey, id: data.id, name: data.name });
  }
);

// 1.6️⃣ List API Keys
app.get('/api-keys',
  async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.substring(7);
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { data, error } = await supabase
      .from('api_keys')
      .select('id, name, created_at, last_used_at')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false });

    if (error) {
      console.error('Error fetching API keys:', error);
      return res.status(500).json({ 
        error: 'Failed to fetch API keys',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }

    res.json(data || []);
  }
);

// 1.7️⃣ Delete API Key
app.delete('/api-keys/:id',
  [
    param('id').isUUID().withMessage('Invalid API key ID'),
  ],
  validateRequest,
  async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    const token = authHeader.substring(7);
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);

    if (authError || !user) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    const { id } = req.params;

    // Verify the key belongs to the user before deleting
    const { data: keyData, error: fetchError } = await supabase
      .from('api_keys')
      .select('user_id')
      .eq('id', id)
      .single();

    if (fetchError || !keyData) {
      return res.status(404).json({ error: 'API key not found' });
    }

    if (keyData.user_id !== user.id) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const { error } = await supabase
      .from('api_keys')
      .delete()
      .eq('id', id);

    if (error) {
      console.error('Error deleting API key:', error);
      return res.status(500).json({ error: 'Failed to delete API key' });
    }

    res.json({ success: true, message: 'API key deleted successfully' });
  }
);

// 2️⃣ Info endpoint (must be before redirect)
app.get('/info/:code',
  [
    param('code')
      .isLength({ min: 1, max: 20 })
      .withMessage('Code must be between 1 and 20 characters')
      .matches(/^[a-zA-Z0-9-]+$/)
      .withMessage('Code can only contain letters, numbers, and hyphens'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { code } = req.params;
      const sanitizedCode = sanitizeCode(code);

      if (!sanitizedCode) {
        return res.status(400).json({ error: 'Invalid code format' });
      }

      const { data, error } = await supabase
        .from('links')
        .select('*')
        .eq('code', sanitizedCode)
        .maybeSingle();

      if (error) {
        console.error('Database error:', error);
        return res.status(500).json({
          error: 'Database error',
          details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
        });
      }

      if (!data) {
        return res.status(404).json({ error: 'Link not found' });
      }

      res.json(data);
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({
        error: 'Unexpected server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 3️⃣ Stripe: Create Payment Intent
app.post('/create-payment-intent',
  paymentLimiter,
  [
    body('amount')
      .notEmpty()
      .withMessage('Amount is required')
      .isInt({ min: 50, max: 99999999 })
      .withMessage('Amount must be between 50 and 99999999 cents'),
    body('currency')
      .optional()
      .isLength({ min: 3, max: 3 })
      .withMessage('Currency must be 3 characters')
      .isUppercase()
      .withMessage('Currency must be uppercase'),
    body('plan')
      .optional()
      .isLength({ max: 50 })
      .withMessage('Plan name is too long'),
    body('firstName')
      .optional()
      .isLength({ max: 100 })
      .withMessage('First name is too long')
      .matches(/^[a-zA-Z\s'-]+$/)
      .withMessage('First name contains invalid characters'),
    body('lastName')
      .optional()
      .isLength({ max: 100 })
      .withMessage('Last name is too long')
      .matches(/^[a-zA-Z\s'-]+$/)
      .withMessage('Last name contains invalid characters'),
    body('email')
      .optional()
      .isEmail()
      .withMessage('Invalid email format')
      .isLength({ max: 255 })
      .withMessage('Email is too long'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const {
        amount,
        currency = 'usd',
        plan = 'starter',
        firstName = '',
        lastName = '',
        email = ''
      } = req.body;

      // Sanitize inputs
      const sanitizedPlan = sanitizeInput(plan).substring(0, 50);
      const sanitizedFirstName = sanitizeInput(firstName).substring(0, 100);
      const sanitizedLastName = sanitizeInput(lastName).substring(0, 100);
      const sanitizedEmail = email ? sanitizeInput(email).toLowerCase().substring(0, 255) : '';

      const paymentIntent = await stripe.paymentIntents.create({
        amount, // in cents (e.g., 500 = $5.00)
        currency: currency.toLowerCase(),
        automatic_payment_methods: { enabled: true },
        metadata: {
          plan: sanitizedPlan,
          firstName: sanitizedFirstName,
          lastName: sanitizedLastName,
          email: sanitizedEmail,
        },
      });

      res.json({
        clientSecret: paymentIntent.client_secret,
        id: paymentIntent.id,
      });
    } catch (err) {
      console.error('Stripe error:', err.message);
      res.status(500).json({
        error: 'Payment processing error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 4️⃣ Stripe: Create Checkout Session (optional subscription flow)
app.post('/create-checkout-session',
  paymentLimiter,
  [
    body('priceId')
      .notEmpty()
      .withMessage('Price ID is required')
      .isLength({ max: 255 })
      .withMessage('Price ID is too long'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { priceId } = req.body;
      const sanitizedPriceId = sanitizeInput(priceId).substring(0, 255);

      const session = await stripe.checkout.sessions.create({
        mode: 'subscription',
        line_items: [{ price: sanitizedPriceId, quantity: 1 }],
        success_url: process.env.STRIPE_SUCCESS_URL || 'https://your-frontend-domain.com/success',
        cancel_url: process.env.STRIPE_CANCEL_URL || 'https://your-frontend-domain.com/cancel',
      });

      res.json({ url: session.url });
    } catch (err) {
      console.error('Stripe session error:', err.message);
      res.status(500).json({
        error: 'Session creation error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 5️⃣ Stripe Webhook: verify, then store successful payment in Supabase
// Use express.raw() ONLY for this route (to validate Stripe signature)
app.post('/webhook',
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error('⚠️  STRIPE_WEBHOOK_SECRET is not set');
      return res.status(500).send('Webhook secret not configured');
    }

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
          } catch { }
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
        const plan = sanitizeInput(pi.metadata?.plan || '').substring(0, 50) || null;
        const firstName = sanitizeInput(pi.metadata?.firstName || '').substring(0, 100) || null;
        const lastName = sanitizeInput(pi.metadata?.lastName || '').substring(0, 100) || null;
        const payer_email = pi.metadata?.email ? sanitizeInput(pi.metadata.email).toLowerCase().substring(0, 255) : null;

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

        // 🎯 Grant premium access to the user
        if (payer_email && plan) {
          try {
            // Get user ID from email
            const { data: userData, error: userError } = await supabase.auth.admin.listUsers();
            const user = userData?.users?.find(u => u.email === payer_email);
            
            if (user) {
              // Calculate expiration (30 days for pro plan, 365 for enterprise)
              const daysToAdd = plan.toLowerCase() === 'enterprise' ? 365 : 30;
              const expiresAt = new Date();
              expiresAt.setDate(expiresAt.getDate() + daysToAdd);

              // Upsert subscription
              const { error: subError } = await supabase
                .from('user_subscriptions')
                .upsert({
                  user_id: user.id,
                  plan: plan.toLowerCase(),
                  status: 'active',
                  stripe_payment_intent: pi.id,
                  expires_at: expiresAt.toISOString(),
                  updated_at: new Date().toISOString()
                }, {
                  onConflict: 'user_id'
                });

              if (subError) {
                console.error('Error creating subscription:', subError);
              } else {
                console.log(`✅ Premium access granted to ${payer_email} (${plan}) until ${expiresAt.toISOString()}`);
              }
            } else {
              console.warn(`User with email ${payer_email} not found in auth system`);
            }
          } catch (subErr) {
            console.error('Error granting premium access:', subErr);
          }
        }
      } catch (err) {
        console.error('Error handling payment_intent.succeeded:', err);
      }
    }

    // Acknowledge receipt
    res.json({ received: true });
  }
);

// 6️⃣ Payments history: return decrypted names for a user by email
app.get('/payments/:email',
  [
    param('email')
      .isEmail()
      .withMessage('Invalid email format')
      .isLength({ max: 255 })
      .withMessage('Email is too long'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { email } = req.params;
      const sanitizedEmail = sanitizeInput(email).toLowerCase().substring(0, 255);

      const { data, error } = await supabase
        .from('payments')
        .select('*')
        .eq('payer_email', sanitizedEmail)
        .order('created_at', { ascending: false });

      if (error) {
        console.error('Database error:', error);
        return res.status(500).json({
          error: 'Database error',
          details: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error',
        });
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
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({
        error: 'Unexpected server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 6.5️⃣ Update Link
app.patch('/links/:id',
  requiresPremium, // 🎯 PREMIUM FEATURE
  [
    param('id').isUUID().withMessage('Invalid link ID'),
    body('original')
      .optional()
      .isLength({ max: 2048 })
      .withMessage('URL is too long')
      .custom((value) => {
        if (value) {
          const sanitized = sanitizeInput(value);
          if (!isValidUrl(sanitized)) {
            throw new Error('Invalid URL format');
          }
        }
        return true;
      }),
    body('expires_at')
      .optional()
      .isISO8601()
      .withMessage('Invalid date format'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const token = authHeader.substring(7);
      const { data: { user }, error: authError } = await supabase.auth.getUser(token);

      if (authError || !user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { id } = req.params;
      const updates = {};

      if (req.body.original) {
        updates.original = sanitizeInput(req.body.original);
      }
      if (req.body.expires_at) {
        updates.expires_at = req.body.expires_at;
      }

      if (Object.keys(updates).length === 0) {
        return res.status(400).json({ error: 'No updates provided' });
      }

      // Verify link belongs to user
      const { data: linkData, error: fetchError } = await supabase
        .from('links')
        .select('user_id')
        .eq('id', id)
        .single();

      if (fetchError || !linkData) {
        return res.status(404).json({ error: 'Link not found' });
      }

      if (linkData.user_id !== user.id) {
        return res.status(403).json({ error: 'Forbidden' });
      }

      const { data, error } = await supabase
        .from('links')
        .update(updates)
        .eq('id', id)
        .select()
        .single();

      if (error) {
        console.error('Error updating link:', error);
        return res.status(500).json({ error: 'Failed to update link' });
      }

      res.json(data);
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({
        error: 'Unexpected server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 6.7️⃣ Delete Link
app.delete('/links/:id',
  [
    param('id').isUUID().withMessage('Invalid link ID'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      const token = authHeader.substring(7);
      const { data: { user }, error: authError } = await supabase.auth.getUser(token);

      if (authError || !user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const { id } = req.params;

      // Verify link belongs to user
      const { data: linkData, error: fetchError } = await supabase
        .from('links')
        .select('user_id, code')
        .eq('id', id)
        .single();

      if (fetchError || !linkData) {
        return res.status(404).json({ error: 'Link not found' });
      }

      if (linkData.user_id !== user.id) {
        return res.status(403).json({ error: 'Forbidden: You can only delete your own links' });
      }

      // Delete the link
      console.log('Attempting to delete link from database:', id);
      const { data: deletedData, error } = await supabase
        .from('links')
        .delete()
        .eq('id', id)
        .select();

      console.log('Delete result:', { deletedData, error });

      if (error) {
        console.error('Error deleting link:', error);
        return res.status(500).json({ error: 'Failed to delete link', details: error.message });
      }

      if (!deletedData || deletedData.length === 0) {
        console.error('No rows were deleted');
        return res.status(500).json({ error: 'Delete operation did not affect any rows' });
      }

      console.log('Successfully deleted link:', deletedData);
      res.json({ 
        success: true, 
        message: 'Link deleted successfully',
        code: linkData.code,
        deleted: deletedData[0]
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({
        error: 'Unexpected server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 6.8️⃣ Bulk Shorten
app.post('/shorten/bulk',
  requiresPremium, // 🎯 PREMIUM FEATURE
  strictLimiter,
  [
    body('urls')
      .isArray({ min: 1, max: 100 })
      .withMessage('Must provide 1-100 URLs'),
    body('urls.*.originalUrl')
      .notEmpty()
      .withMessage('URL is required')
      .isLength({ max: 2048 })
      .withMessage('URL is too long'),
    body('urls.*.customCode')
      .optional()
      .isLength({ min: 1, max: 20 })
      .withMessage('Custom code must be 1-20 characters')
      .matches(/^[a-zA-Z0-9-]+$/)
      .withMessage('Custom code can only contain letters, numbers, and hyphens'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const userId = req.userId; // Set by requiresPremium middleware

      const { urls } = req.body;
      const results = [];
      const errors = [];

      for (let i = 0; i < urls.length; i++) {
        const { originalUrl, customCode } = urls[i];
        
        try {
          // Sanitize and validate URL
          const sanitizedUrl = sanitizeInput(originalUrl);
          if (!isValidUrl(sanitizedUrl)) {
            errors.push({ index: i, error: 'Invalid URL format', url: originalUrl });
            continue;
          }

          // Generate or sanitize code
          let code;
          if (customCode) {
            code = sanitizeCode(customCode);
            if (!code) {
              errors.push({ index: i, error: 'Invalid custom code', url: originalUrl });
              continue;
            }
          } else {
            code = Math.random().toString(36).substring(2, 7).toLowerCase();
          }

          // Check if code exists
          const { data: existing } = await supabase
            .from('links')
            .select('code')
            .eq('code', code)
            .maybeSingle();

          if (existing) {
            if (customCode) {
              errors.push({ index: i, error: 'Custom code already exists', url: originalUrl });
              continue;
            }
            code = Math.random().toString(36).substring(2, 7).toLowerCase();
          }

          const insertData = { code, original: sanitizedUrl };
          if (userId) {
            insertData.user_id = userId;
          }

          const { data, error } = await supabase
            .from('links')
            .insert([insertData])
            .select()
            .single();

          if (error) {
            errors.push({ index: i, error: 'Database error', url: originalUrl });
            continue;
          }

          const baseUrl = process.env.BACKEND_URL || 'https://link-shortener-backend-production.up.railway.app';
          results.push({
            index: i,
            shortUrl: `${baseUrl}/${code}`,
            linkData: data
          });
        } catch (err) {
          errors.push({ index: i, error: err.message, url: originalUrl });
        }
      }

      res.json({
        success: results.length,
        failed: errors.length,
        results,
        errors
      });
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).json({
        error: 'Unexpected server error',
        details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      });
    }
  }
);

// 6.7️⃣ Health Check Endpoint
// 6.8️⃣ Get User Subscription Status
app.get('/subscription/status',
  async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const token = authHeader.substring(7);
      const { data: { user }, error: authError } = await supabase.auth.getUser(token);

      if (authError || !user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const subscription = await getUserSubscription(user.id);

      res.json({
        plan: subscription.plan,
        status: subscription.status,
        expiresAt: subscription.expires_at || null,
        features: {
          linkExpiration: subscription.plan !== 'free',
          bulkShortening: subscription.plan !== 'free',
          linkEditing: subscription.plan !== 'free',
          advancedAnalytics: subscription.plan !== 'free',
          customBranding: subscription.plan === 'enterprise',
          prioritySupport: subscription.plan !== 'free'
        }
      });
    } catch (err) {
      console.error('Error fetching subscription:', err);
      res.status(500).json({ error: 'Failed to fetch subscription status' });
    }
  }
);

// 6.9️⃣ Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development'
  });
});

// 7️⃣ Redirect (must be last non-catchall before fallback)
app.get('/:code',
  [
    param('code')
      .isLength({ min: 1, max: 20 })
      .withMessage('Code must be between 1 and 20 characters')
      .matches(/^[a-zA-Z0-9-]+$/)
      .withMessage('Code can only contain letters, numbers, and hyphens'),
  ],
  validateRequest,
  async (req, res) => {
    try {
      const { code } = req.params;
      const sanitizedCode = sanitizeCode(code);

      if (!sanitizedCode) {
        return res.status(400).send('Invalid code format');
      }

      console.log('Looking up link with code:', sanitizedCode);

      const { data, error } = await supabase
        .from('links')
        .select('original, click_count, expires_at')
        .eq('code', sanitizedCode)
        .maybeSingle();

      console.log('Query result:', { data, error });

      if (error) {
        console.error('Supabase error:', error);
        return res.status(500).send(`Database error: ${error.message}`);
      }

      if (!data) {
        console.log('Link not found for code:', sanitizedCode);
        return res.status(404).send('Link not found');
      }

      // Check if link has expired
      if (data.expires_at) {
        const expiryDate = new Date(data.expires_at);
        if (expiryDate < new Date()) {
          return res.status(410).send('This link has expired');
        }
      }

      // Validate the original URL before redirecting
      if (!isValidUrl(data.original)) {
        console.error('Invalid original URL in database:', data.original);
        return res.status(500).send('Invalid link data');
      }

      await supabase
        .from('links')
        .update({ click_count: (data.click_count ?? 0) + 1 })
        .eq('code', sanitizedCode);

      return res.redirect(data.original);
    } catch (err) {
      console.error('Unexpected error:', err);
      res.status(500).send('Internal server error');
    }
  }
);

// ─────────────────────────────
// ✅ Explicit OPTIONS route for safety
// ─────────────────────────────
app.options('*', (req, res) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin) || !origin) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  }
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Stripe-Signature, X-Requested-With, Authorization, x-api-key');
  res.header('Access-Control-Allow-Credentials', 'true');
  return res.sendStatus(200);
});

// ─────────────────────────────
// ✅ Error handling middleware
// ─────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

// ─────────────────────────────
// ✅ Start server
// ─────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Backend running on port ${PORT}`);
  console.log(`✅ Security features enabled: Rate limiting, Input validation, Helmet`);
  if (process.env.NODE_ENV === 'production') {
    console.log(`✅ Production mode: Enhanced security enabled`);
  }
});
