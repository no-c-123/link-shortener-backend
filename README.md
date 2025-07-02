# Link Shortener Backend

A Node.js/Express backend service for URL shortening with automatic port detection and Supabase database integration.

## Features

- ✅ **URL Shortening**: Convert long URLs into short, shareable links
- ✅ **Automatic Port Detection**: Finds available ports automatically to avoid conflicts
- ✅ **Database Storage**: Uses Supabase for reliable data persistence
- ✅ **CORS Support**: Configured for cross-origin requests
- ✅ **Error Handling**: Comprehensive error handling and logging
- ✅ **Environment Configuration**: Secure environment variable management

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
PORT=5000
SUPABASE_URL=your_supabase_url_here
SUPABASE_ANON_KEY=your_supabase_anon_key_here
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
| `PORT` | Server port (default: 5000) | No |
| `SUPABASE_URL` | Supabase project URL | Yes |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | Yes |

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

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is open source and available under the [MIT License](LICENSE).
