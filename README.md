# Link Shortener Backend

A Node.js/Express backend service for URL shortening with automatic port detection and Supabase database integration.

## Features

- ✅ **URL Shortening**: Convert long URLs into short, shareable links
- ✅ **Automatic Port Detection**: Finds available ports automatically to avoid conflicts
- ✅ **Database Storage**: Uses Supabase for reliable data persistence
- ✅ **CORS Support**: Configured for cross-origin requests
- ✅ **Error Handling**: Comprehensive error handling and logging
- ✅ **Environment Configuration**: Secure environment variable management
- 🔒 **Security Features**:
  - Rate limiting on all endpoints
  - Input validation and sanitization
  - URL validation (blocks malicious URLs)
  - Security headers (Helmet)
  - Enhanced encryption with proper key validation

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: Supabase (PostgreSQL)
- **Environment**: dotenv
- **CORS**: cors middleware

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd link-shortener-backend
```

2. Install dependencies:
```bash
npm install
```

3. Set up environment variables:
Create a `.env` file in the root directory with:
```env
PORT=8080
NODE_ENV=production

# Supabase Configuration
SUPABASE_URL=your_supabase_project_url
SUPABASE_ANON_KEY=your_supabase_anon_key

# Stripe Configuration
SECRET_STRIPE_PUBLISHABLE_KEY=sk_test_your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# Encryption Key (32 bytes, base64 encoded)
# Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
ENCRYPTION_KEY=your_32_byte_base64_encryption_key

# Backend URL (for generating short URLs)
BACKEND_URL=https://link-shortener-backend-production.up.railway.app

# CORS Configuration (comma-separated list of allowed origins)
ALLOWED_ORIGINS=http://localhost:4321,http://localhost:3000,https://your-production-domain.com

# Stripe Redirect URLs
STRIPE_SUCCESS_URL=https://your-frontend-domain.com/success
STRIPE_CANCEL_URL=https://your-frontend-domain.com/cancel
```

4. Set up Supabase database:
Create a table named `links` with the following structure:
```sql
CREATE TABLE links (
  id SERIAL PRIMARY KEY,
  code VARCHAR(10) UNIQUE NOT NULL,
  original TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
```

## Usage

### Start the server:
```bash
npm start
```
or
```bash
node index.js
```

The server will automatically find an available port starting from the configured PORT (default: 5000).

### API Endpoints

#### Shorten URL
- **POST** `/shorten`
- **Body**: `{ "originalUrl": "https://example.com" }`
- **Response**: `{ "shortUrl": "http://localhost:PORT/abc12" }`

#### Redirect to Original URL
- **GET** `/:code`
- **Response**: Redirects to the original URL

## Example Usage

### Shorten a URL:
```bash
curl -X POST http://localhost:5000/shorten \
  -H "Content-Type: application/json" \
  -d '{"originalUrl": "https://www.google.com"}'
```

### Access shortened URL:
```bash
curl http://localhost:5000/abc12
# Redirects to https://www.google.com
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `PORT` | Server port (default: 8080) | No |
| `NODE_ENV` | Environment (development/production) | No |
| `SUPABASE_URL` | Supabase project URL | Yes |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Yes |
| `SECRET_STRIPE_PUBLISHABLE_KEY` | Stripe secret key | Yes |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook secret | Yes |
| `ENCRYPTION_KEY` | 32-byte base64 encryption key | Yes |
| `BACKEND_URL` | Backend URL for short links | No |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | No |
| `STRIPE_SUCCESS_URL` | Stripe success redirect URL | No |
| `STRIPE_CANCEL_URL` | Stripe cancel redirect URL | No |

### CORS Configuration

The server is configured to accept requests from:
- `http://localhost:4321` (default frontend)

To modify CORS settings, update the `cors` configuration in `index.js`.

## Automatic Port Detection

This backend includes intelligent port detection that:
- Tries the configured PORT first
- Automatically finds the next available port if the preferred port is busy
- Updates all generated URLs to use the correct port
- Provides clear logging about which port is being used

## Error Handling

The API provides detailed error responses:
- `400`: Bad Request (missing URL)
- `404`: Link not found
- `500`: Server/Database errors

## Development

### Project Structure
```
backend/
├── index.js          # Main server file
├── package.json      # Dependencies and scripts
├── .env             # Environment variables (not in git)
├── .gitignore       # Git ignore rules
└── README.md        # This file
```

### Dependencies
- `express`: Web framework
- `cors`: Cross-origin resource sharing
- `@supabase/supabase-js`: Supabase client
- `dotenv`: Environment variable loading
- `express-rate-limit`: Rate limiting middleware
- `helmet`: Security headers middleware
- `express-validator`: Input validation middleware
- `stripe`: Stripe payment processing

## Admin Scripts

For testing premium features without payment, use these admin scripts:

### Grant Premium Access
```bash
# Grant Pro plan for 30 days
node scripts/grant-premium.js admin@example.com pro 30

# Grant Enterprise plan for 365 days
node scripts/grant-premium.js test@example.com enterprise 365

# Grant "permanent" premium (999999 days)
node scripts/grant-premium.js dev@example.com pro 999999
```

**Parameters:**
- `email` (required): User's registered email address
- `plan` (optional): `pro` or `enterprise` (default: `pro`)
- `days` (optional): Number of days until expiration (default: `30`)

### Check Subscription Status
```bash
node scripts/check-subscription.js admin@example.com
```

Shows current plan, expiration date, days remaining, and available features.

### Revoke Premium Access
```bash
node scripts/revoke-premium.js admin@example.com
```

Downgrades user back to free plan.

### Quick Start for Testing

1. **Register a test account** through the frontend or Supabase Auth
2. **Grant premium access**:
   ```bash
   cd backend
   node scripts/grant-premium.js your-email@example.com pro 365
   ```
3. **Test premium features**:
   - Link expiration: `POST /shorten` with `expiresAt`
   - Bulk shortening: `POST /shorten/bulk`
   - Link editing: `PATCH /links/:id`
4. **Check status anytime**:
   ```bash
   node scripts/check-subscription.js your-email@example.com
   ```

**Note:** These scripts require `SUPABASE_SERVICE_ROLE_KEY` in your `.env` file for admin operations. If not available, they'll fall back to `SUPABASE_ANON_KEY` (may have limited permissions).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).
