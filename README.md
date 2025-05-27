# Security Buddy

A comprehensive web security scanning platform that provides instant security analysis for websites and domains.

## Features

- **Real-time Security Scanning**: Check HTTPS, SSL certificates, and security headers
- **User-friendly Interface**: Simple design accessible to non-technical users
- **Premium Analytics**: Advanced reporting and monitoring (for registered users)
- **REST API**: Programmatic access for CI/CD integration
- **PDF Reports**: Professional security reports (premium feature)

## Quick Deploy to Vercel

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-username/security-buddy)

### Environment Variables

Set these environment variables in your Vercel dashboard:

- `DATABASE_URL`: PostgreSQL connection string (required)
- `SESSION_SECRET`: Secret key for sessions (required)
- `SENDGRID_API_KEY`: For email notifications (optional)
- `TWILIO_ACCOUNT_SID`: For SMS alerts (optional)
- `TWILIO_AUTH_TOKEN`: For SMS alerts (optional)
- `TWILIO_PHONE_NUMBER`: For SMS alerts (optional)

### Database Setup

1. Create a PostgreSQL database (recommend: [Neon](https://neon.tech/), [Supabase](https://supabase.com/), or [PlanetScale](https://planetscale.com/))
2. Set the `DATABASE_URL` environment variable
3. The app will automatically create tables on first run

## Local Development

1. Clone the repository
2. Install dependencies: `pip install -r requirements_vercel.txt`
3. Set environment variables (copy `.env.example` to `.env`)
4. Run: `python main.py`

## API Usage

```bash
# Basic scan
curl -X POST https://your-app.vercel.app/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com"}'

# With API key for premium features
curl -X POST https://your-app.vercel.app/api/v1/scan \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"target": "example.com", "advanced": true}'
```

## License

MIT License