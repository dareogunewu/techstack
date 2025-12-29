# TenantGuard - Multi-Tenant Identity & Access Management Platform

A production-grade, enterprise-ready identity and access management (IAM) platform showcasing advanced OAuth 2.0, OpenID Connect, multi-tenancy, and enterprise federation capabilities.

## Overview

TenantGuard is a comprehensive identity platform designed to demonstrate expertise in:
- Multi-tenant architecture with strict isolation
- OAuth 2.0 and OpenID Connect implementation
- Enterprise identity federation (SAML, SCIM, LDAP)
- Advanced token management and validation
- Claims-based authorization with extensible engine
- Rate limiting and fraud prevention
- Global identity infrastructure patterns

## Target Use Cases

- **SaaS Providers**: Offer identity services to multiple customers
- **Enterprise Organizations**: Manage complex organizational hierarchies
- **API Platforms**: Secure APIs with OAuth 2.0 and custom claims
- **Identity Providers**: Build custom IdP solutions

## Architecture

See [ARCHITECTURE.md](./docs/ARCHITECTURE.md) for detailed system design.

## Project Structure

```
techstack/
├── docs/                           # Architecture and design documentation
│   ├── ARCHITECTURE.md            # System architecture overview
│   ├── MULTI_TENANCY.md           # Multi-tenant design patterns
│   ├── SECURITY.md                # Security considerations
│   └── API_REFERENCE.md           # API documentation
├── services/                       # Microservices
│   ├── auth-server/               # OAuth 2.0/OIDC authorization server
│   ├── admin-api/                 # Tenant management API
│   ├── federation-gateway/        # SAML/SCIM/LDAP integration
│   ├── claims-engine/             # Custom claims processing
│   ├── token-validator/           # Distributed token validation
│   └── rate-limiter/              # Security and rate limiting
├── libraries/                      # Shared libraries
│   ├── crypto/                    # JWT, JWE, JWKS utilities
│   ├── multi-tenant/              # Tenant isolation utilities
│   └── audit/                     # Audit logging
├── demo-apps/                      # Sample integrations
│   ├── spa-client/                # React SPA demo
│   ├── mobile-client/             # React Native demo
│   └── resource-server/           # Protected API demo
├── infrastructure/                 # Deployment configs
│   ├── docker/                    # Docker configurations
│   ├── kubernetes/                # K8s manifests
│   └── terraform/                 # Infrastructure as code
└── scripts/                        # Utility scripts
```

## Key Features

### 1. Advanced OAuth 2.0 & OpenID Connect
- Authorization Code Flow with PKCE
- Client Credentials Flow
- Device Authorization Flow
- Token Exchange (RFC 8693)
- Pushed Authorization Requests (PAR)
- Rich Authorization Requests (RAR)
- Dynamic Client Registration
- Token Introspection and Revocation

### 2. Multi-Tenant Architecture
- Strict tenant isolation at all layers
- Hierarchical organization structures
- Tenant-specific JWKS endpoints
- Custom domain support per tenant
- Cross-tenant security controls
- Tenant-level configuration and branding

### 3. Extensible Claims Engine
- Rule-based claims transformation
- Custom claim pipelines per tenant
- Dynamic attribute mapping
- Integration with external data sources
- Conditional claims logic
- Claims caching and optimization

### 4. Enterprise Federation
- **SAML 2.0**: SP and IdP support, both flows
- **SCIM 2.0**: User provisioning and deprovisioning
- **LDAP/AD**: Directory synchronization
- **Social Providers**: Google, GitHub, Microsoft
- Federation metadata management

### 5. Global Token Infrastructure
- Distributed token validation
- JWT with automatic key rotation
- JWE for sensitive tokens
- HSM integration patterns
- Geo-distributed validation
- Token caching strategies

### 6. Security & Compliance
- Per-tenant rate limiting
- Brute force detection
- Anomaly detection (geolocation, device)
- IP allowlisting/denylisting
- Comprehensive audit logging
- GDPR and SOC2 compliance patterns

## Technology Stack

- **Language**: TypeScript (Node.js) - for rapid development and type safety
- **Runtime**: Node.js 20+
- **Framework**: Express.js with custom middleware
- **Database**: PostgreSQL 15+ (tenant data, configuration)
- **Cache**: Redis 7+ (tokens, sessions, rate limiting)
- **Message Queue**: Redis Streams (async operations)
- **Cryptography**: `node:crypto`, `jose` library
- **Validation**: Zod for schema validation
- **Testing**: Jest, Supertest
- **Documentation**: OpenAPI 3.1
- **Containerization**: Docker, Docker Compose
- **Orchestration**: Kubernetes (optional)

## Quick Start

### Prerequisites
- Node.js 20+
- Docker and Docker Compose
- PostgreSQL 15+
- Redis 7+

### Development Setup

```bash
# Clone the repository
git clone https://github.com/dareogunewu/techstack.git
cd techstack

# Install dependencies
npm install

# Start infrastructure (PostgreSQL, Redis)
docker-compose up -d

# Run database migrations
npm run migrate

# Seed initial data
npm run seed

# Start development servers
npm run dev

# Run tests
npm test
```

### Using the Platform

1. **Create a Tenant**:
   ```bash
   curl -X POST http://localhost:3000/admin/tenants \
     -H "Content-Type: application/json" \
     -d '{"name": "Acme Corp", "domain": "acme.example.com"}'
   ```

2. **Register an OAuth Client**:
   ```bash
   curl -X POST http://localhost:3000/admin/tenants/acme-corp/clients \
     -H "Content-Type: application/json" \
     -d '{
       "client_name": "My App",
       "redirect_uris": ["https://myapp.com/callback"],
       "grant_types": ["authorization_code"],
       "response_types": ["code"]
     }'
   ```

3. **Start Authorization Flow**:
   Navigate to:
   ```
   http://localhost:3000/authorize?
     client_id=<client_id>&
     redirect_uri=https://myapp.com/callback&
     response_type=code&
     scope=openid profile email&
     state=xyz&
     code_challenge=<pkce_challenge>&
     code_challenge_method=S256
   ```

See [docs/GETTING_STARTED.md](./docs/GETTING_STARTED.md) for detailed tutorials.

## Documentation

- [Architecture Overview](./docs/ARCHITECTURE.md)
- [Multi-Tenancy Design](./docs/MULTI_TENANCY.md)
- [Security Model](./docs/SECURITY.md)
- [API Reference](./docs/API_REFERENCE.md)
- [Deployment Guide](./docs/DEPLOYMENT.md)
- [Performance Tuning](./docs/PERFORMANCE.md)

## Roadmap

- [x] Project architecture and documentation
- [ ] Core OAuth 2.0/OIDC server
- [ ] Multi-tenant data model
- [ ] Admin API for tenant management
- [ ] Claims engine implementation
- [ ] SAML 2.0 federation
- [ ] SCIM 2.0 provisioning
- [ ] Rate limiting and security
- [ ] Demo applications
- [ ] Performance benchmarks
- [ ] Production deployment guides

## Contributing

This is a portfolio/demonstration project. Feedback and suggestions are welcome via issues.

## License

MIT License - See [LICENSE](./LICENSE) for details.

## Author

Dare Ogunewu - [LinkedIn](https://linkedin.com/in/dareogunewu) | [GitHub](https://github.com/dareogunewu)

## Acknowledgments

Built to demonstrate advanced IAM concepts for enterprise-grade identity platforms, inspired by modern identity providers like Auth0, Okta, and Kong.
