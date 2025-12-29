# Getting Started with TenantGuard

This guide will help you set up and run TenantGuard locally for development and testing.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Node.js** 20+ ([Download](https://nodejs.org/))
- **Docker** & **Docker Compose** ([Download](https://www.docker.com/products/docker-desktop))
- **Git** ([Download](https://git-scm.com/))
- **PostgreSQL Client** (optional, for manual database access)
- **Redis CLI** (optional, for manual cache access)

Verify installations:
```bash
node --version  # Should be v20.x or higher
npm --version   # Should be v9.x or higher
docker --version
docker-compose --version
```

## Quick Start (5 minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/dareogunewu/techstack.git
cd techstack
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Start Infrastructure

Start PostgreSQL and Redis using Docker Compose:

```bash
npm run docker:up
```

This starts:
- PostgreSQL on port 5432
- Redis on port 6379

Verify services are running:
```bash
docker ps
```

### 4. Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Generate secure keys:
```bash
# Encryption key (32 bytes)
openssl rand -hex 32

# Session secret
openssl rand -base64 32
```

Edit `.env` and replace:
- `ENCRYPTION_KEY` with the first generated value
- `SESSION_SECRET` with the second generated value

### 5. Run Database Migrations

Create the database schema:

```bash
npm run migrate
```

### 6. Seed Initial Data

Create a test tenant and admin user:

```bash
npm run seed
```

This creates:
- Tenant: `demo-corp` (domain: `demo.auth.localhost`)
- Admin user: `admin@demo.com` / `Admin123!`
- OAuth client for testing

### 7. Start the Server

```bash
npm run dev
```

The server will start on http://localhost:3000

### 8. Test the Setup

Open a new terminal and test the health endpoint:

```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "ok",
  "timestamp": "2025-01-01T00:00:00.000Z",
  "services": {
    "database": "healthy",
    "redis": "healthy"
  }
}
```

## Development Workflow

### Project Structure

```
techstack/
├── docs/                    # Documentation
├── src/                     # Source code (to be created in Phase 2)
│   ├── api/                # API routes and controllers
│   ├── services/           # Business logic
│   ├── repositories/       # Database access layer
│   ├── middleware/         # Express middleware
│   ├── utils/              # Utility functions
│   └── types/              # TypeScript type definitions
├── scripts/                # Utility scripts (migrations, seeds)
├── infrastructure/         # Docker, K8s, Terraform
├── tests/                  # Test files
└── demo-apps/              # Sample integrations
```

### Running in Development

```bash
# Start with auto-reload
npm run dev

# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Lint code
npm run lint

# Format code
npm run format

# Build for production
npm run build

# Run production build
npm start
```

### Database Management

```bash
# Create a new migration
npm run migrate:create -- add_new_feature

# Run migrations
npm run migrate

# Rollback last migration
npm run migrate:rollback

# Seed database
npm run seed

# Reset database (WARNING: deletes all data)
npm run migrate:rollback && npm run migrate && npm run seed
```

### Docker Commands

```bash
# Start services
npm run docker:up

# Start with tools (PgAdmin, Redis Commander)
docker-compose --profile tools up -d

# Stop services
npm run docker:down

# View logs
npm run docker:logs

# Restart a service
docker-compose restart postgres

# Connect to PostgreSQL
docker exec -it tenantguard-postgres psql -U tenantguard

# Connect to Redis
docker exec -it tenantguard-redis redis-cli -a dev_redis_password
```

### Accessing Management UIs

With tools profile enabled (`docker-compose --profile tools up -d`):

- **PgAdmin**: http://localhost:5050
  - Email: `admin@tenantguard.local`
  - Password: `admin`
  - Add server:
    - Host: `postgres`
    - Port: `5432`
    - Database: `tenantguard`
    - Username: `tenantguard`
    - Password: `dev_password_change_in_production`

- **Redis Commander**: http://localhost:8081

## Testing OAuth 2.0 Flows

### Authorization Code Flow (Interactive)

1. **Get Authorization Code**:

   Open in browser:
   ```
   http://localhost:3000/authorize?
     client_id={CLIENT_ID}&
     redirect_uri=http://localhost:3001/callback&
     response_type=code&
     scope=openid profile email&
     state=random_state_value&
     code_challenge={CODE_CHALLENGE}&
     code_challenge_method=S256
   ```

   Generate PKCE challenge:
   ```javascript
   // In browser console or Node.js
   const crypto = require('crypto');

   const codeVerifier = crypto.randomBytes(32).toString('base64url');
   const codeChallenge = crypto
     .createHash('sha256')
     .update(codeVerifier)
     .digest('base64url');

   console.log('Code Verifier:', codeVerifier);
   console.log('Code Challenge:', codeChallenge);
   ```

2. **Exchange Code for Tokens**:

   ```bash
   curl -X POST http://localhost:3000/oauth/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "code={AUTHORIZATION_CODE}" \
     -d "redirect_uri=http://localhost:3001/callback" \
     -d "client_id={CLIENT_ID}" \
     -d "code_verifier={CODE_VERIFIER}"
   ```

### Client Credentials Flow (Server-to-Server)

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "{CLIENT_ID}:{CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=api:read api:write"
```

### Refresh Token Flow

```bash
curl -X POST http://localhost:3000/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token={REFRESH_TOKEN}" \
  -d "client_id={CLIENT_ID}"
```

### Validating Access Tokens

```bash
# Introspect token
curl -X POST http://localhost:3000/oauth/introspect \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "{CLIENT_ID}:{CLIENT_SECRET}" \
  -d "token={ACCESS_TOKEN}"

# Get user info
curl http://localhost:3000/oauth/userinfo \
  -H "Authorization: Bearer {ACCESS_TOKEN}"
```

## OpenID Connect Discovery

```bash
# OIDC configuration
curl http://localhost:3000/.well-known/openid-configuration | jq

# JWKS (public keys)
curl http://localhost:3000/.well-known/jwks.json | jq
```

## Creating Tenants and Clients

### Create a New Tenant

```bash
curl -X POST http://localhost:3000/admin/tenants \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {ADMIN_TOKEN}" \
  -d '{
    "name": "Acme Corporation",
    "slug": "acme-corp",
    "admin_email": "admin@acme.com",
    "admin_password": "SecurePassword123!"
  }'
```

### Register an OAuth Client

```bash
curl -X POST http://localhost:3000/admin/tenants/{TENANT_ID}/clients \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer {ADMIN_TOKEN}" \
  -d '{
    "client_name": "My Application",
    "redirect_uris": [
      "http://localhost:3001/callback",
      "https://myapp.com/auth/callback"
    ],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_basic",
    "allowed_scopes": ["openid", "profile", "email"]
  }'
```

## Troubleshooting

### Database Connection Issues

```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check logs
docker logs tenantguard-postgres

# Test connection
docker exec -it tenantguard-postgres psql -U tenantguard -c "SELECT 1"
```

### Redis Connection Issues

```bash
# Check if Redis is running
docker ps | grep redis

# Check logs
docker logs tenantguard-redis

# Test connection
docker exec -it tenantguard-redis redis-cli -a dev_redis_password ping
```

### Port Already in Use

```bash
# Find process using port 3000
lsof -i :3000

# Kill the process
kill -9 {PID}

# Or change PORT in .env file
PORT=3001
```

### Clear All Data and Reset

```bash
# Stop and remove all containers
npm run docker:down

# Remove volumes (deletes all data)
docker-compose down -v

# Start fresh
npm run docker:up
npm run migrate
npm run seed
npm run dev
```

## Next Steps

1. **Explore the API**: Import the Postman collection from `docs/postman/`
2. **Try the Demo Apps**: See `demo-apps/` for sample integrations
3. **Read the Docs**: Check out detailed documentation in `docs/`
4. **Contribute**: See `CONTRIBUTING.md` for development guidelines

## Common Development Tasks

### Adding a New Endpoint

1. Create route handler in `src/api/`
2. Add business logic in `src/services/`
3. Add database queries in `src/repositories/`
4. Add tests in `tests/`
5. Update API documentation

### Adding a New Migration

```bash
# Create migration file
npm run migrate:create -- descriptive_name

# Edit the generated file in migrations/
# Run the migration
npm run migrate
```

### Debugging

```bash
# Enable debug logs
LOG_LEVEL=debug npm run dev

# Use Node.js inspector
node --inspect-brk node_modules/.bin/tsx src/index.ts

# Attach debugger in VS Code (F5)
```

## Learning Resources

- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)

## Support

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/dareogunewu/techstack/issues)
- **Discussions**: [GitHub Discussions](https://github.com/dareogunewu/techstack/discussions)

## License

MIT License - see [LICENSE](../LICENSE) for details
