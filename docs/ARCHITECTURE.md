# TenantGuard Architecture

## Table of Contents
1. [System Overview](#system-overview)
2. [Core Components](#core-components)
3. [Multi-Tenant Architecture](#multi-tenant-architecture)
4. [Data Flow](#data-flow)
5. [Security Architecture](#security-architecture)
6. [Scalability & Performance](#scalability--performance)
7. [Technology Decisions](#technology-decisions)

## System Overview

TenantGuard is designed as a microservices-based identity platform with strict separation of concerns and multi-tenant isolation at every layer.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Applications                       │
│  (SPAs, Mobile Apps, Backend Services, Third-party Apps)        │
└─────────────────┬───────────────────────────┬───────────────────┘
                  │                           │
                  ▼                           ▼
┌─────────────────────────────┐  ┌───────────────────────────────┐
│     API Gateway / LB        │  │   Federation Gateway          │
│  - Rate Limiting            │  │  - SAML 2.0 SP/IdP           │
│  - DDoS Protection          │  │  - SCIM 2.0 Provisioning     │
│  - SSL Termination          │  │  - LDAP/AD Connector         │
└─────────────┬───────────────┘  └───────────┬───────────────────┘
              │                              │
              ▼                              │
┌─────────────────────────────────────────────┼───────────────────┐
│                                             │                   │
│  ┌──────────────────┐  ┌──────────────────┐│┌─────────────────┐│
│  │  Auth Server     │  │   Admin API      │││ Claims Engine   ││
│  │  - OAuth 2.0     │  │  - Tenant Mgmt   │││ - Rules Engine  ││
│  │  - OIDC Provider │  │  - Client Mgmt   │││ - Transformers  ││
│  │  - Token Issuer  │  │  - User Mgmt     │││ - Mappers       ││
│  └────────┬─────────┘  └────────┬─────────┘│└────────┬────────┘│
│           │                     │          ││         │         │
│           └─────────────────────┼──────────┘└─────────┘         │
│                                 │                               │
│  ┌──────────────────────────────┼──────────────────────────┐   │
│  │         Shared Services      │                          │   │
│  │  ┌──────────────┐  ┌─────────▼────────┐  ┌───────────┐ │   │
│  │  │Token Validator│ │  Rate Limiter   │  │Audit Log  │ │   │
│  │  └──────────────┘  └──────────────────┘  └───────────┘ │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────┬───────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Data Layer                                │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐    │
│  │  PostgreSQL    │  │     Redis      │  │  Redis Streams │    │
│  │  - Tenant Data │  │  - Sessions    │  │  - Event Queue │    │
│  │  - Users       │  │  - Tokens      │  │  - Async Jobs  │    │
│  │  - Clients     │  │  - Rate Limits │  │                │    │
│  │  - Audit Logs  │  │  - Cache       │  │                │    │
│  └────────────────┘  └────────────────┘  └────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Authorization Server

**Purpose**: Core OAuth 2.0 and OpenID Connect provider

**Responsibilities**:
- Handle OAuth 2.0 authorization flows
- Issue access tokens, refresh tokens, and ID tokens
- Validate authorization requests
- Manage user authentication sessions
- Serve OIDC discovery documents and JWKS endpoints

**Key Endpoints**:
```
GET  /.well-known/openid-configuration
GET  /.well-known/jwks.json
GET  /authorize
POST /token
POST /introspect
POST /revoke
GET  /userinfo
POST /device/authorize
POST /par (Pushed Authorization Requests)
```

**OAuth 2.0 Flows Supported**:
- Authorization Code Flow + PKCE
- Client Credentials Flow
- Device Authorization Flow
- Refresh Token Flow
- Token Exchange (RFC 8693)

**Design Patterns**:
- Tenant-scoped endpoints: `https://{tenant}.auth.example.com`
- Stateless token validation via JWT
- Session management with Redis
- PKCE required for public clients
- Dynamic client registration per RFC 7591

### 2. Admin API

**Purpose**: Tenant and resource management interface

**Responsibilities**:
- Create and manage tenants
- Configure OAuth clients per tenant
- Manage users and groups
- Configure claims pipelines
- Set up federation connections
- View audit logs and analytics

**Key Endpoints**:
```
POST   /admin/tenants
GET    /admin/tenants/:tenantId
PUT    /admin/tenants/:tenantId
DELETE /admin/tenants/:tenantId

POST   /admin/tenants/:tenantId/clients
GET    /admin/tenants/:tenantId/clients/:clientId
PUT    /admin/tenants/:tenantId/clients/:clientId
DELETE /admin/tenants/:tenantId/clients/:clientId

POST   /admin/tenants/:tenantId/users
GET    /admin/tenants/:tenantId/users
PUT    /admin/tenants/:tenantId/users/:userId

POST   /admin/tenants/:tenantId/claims-pipelines
GET    /admin/tenants/:tenantId/claims-pipelines/:pipelineId
```

**Authentication**: OAuth 2.0 with admin scopes

### 3. Claims Engine

**Purpose**: Extensible claims transformation and enrichment

**Responsibilities**:
- Transform identity data into JWT claims
- Execute tenant-specific claim rules
- Integrate with external data sources
- Apply conditional logic
- Cache computed claims

**Architecture**:
```typescript
interface ClaimsPipeline {
  tenant_id: string;
  pipeline_id: string;
  stages: ClaimStage[];
}

interface ClaimStage {
  type: 'static' | 'ldap' | 'api' | 'script' | 'conditional';
  config: Record<string, any>;
  output_mapping: Record<string, string>;
}

// Example pipeline
{
  "pipeline_id": "employee-claims",
  "stages": [
    {
      "type": "ldap",
      "config": {
        "server": "ldap://ad.company.com",
        "base_dn": "dc=company,dc=com",
        "attributes": ["department", "title", "manager"]
      },
      "output_mapping": {
        "department": "dept",
        "title": "job_title"
      }
    },
    {
      "type": "conditional",
      "config": {
        "rules": [
          {
            "if": "dept === 'Engineering'",
            "then": {"role": "developer"}
          }
        ]
      }
    },
    {
      "type": "api",
      "config": {
        "url": "https://api.company.com/permissions",
        "method": "GET"
      },
      "output_mapping": {
        "permissions": "custom:permissions"
      }
    }
  ]
}
```

**Performance**:
- Parallel stage execution where possible
- Redis caching of computed claims (TTL-based)
- Async processing for non-blocking claims

### 4. Federation Gateway

**Purpose**: Enterprise identity integration

**Responsibilities**:
- SAML 2.0 Service Provider (SP) and Identity Provider (IdP)
- SCIM 2.0 user provisioning
- LDAP/Active Directory synchronization
- Social provider integration

**SAML 2.0 Support**:
```
# SP Endpoints (TenantGuard as Service Provider)
GET  /saml/:tenantId/metadata
POST /saml/:tenantId/acs (Assertion Consumer Service)
GET  /saml/:tenantId/sls (Single Logout Service)

# IdP Endpoints (TenantGuard as Identity Provider)
GET  /saml/:tenantId/idp/metadata
POST /saml/:tenantId/idp/sso
GET  /saml/:tenantId/idp/slo
```

**SCIM 2.0 Support**:
```
GET    /scim/v2/:tenantId/Users
GET    /scim/v2/:tenantId/Users/:id
POST   /scim/v2/:tenantId/Users
PUT    /scim/v2/:tenantId/Users/:id
PATCH  /scim/v2/:tenantId/Users/:id
DELETE /scim/v2/:tenantId/Users/:id

GET    /scim/v2/:tenantId/Groups
POST   /scim/v2/:tenantId/Groups
```

**LDAP Connector**:
- Read-only or read-write mode
- Scheduled sync jobs
- Incremental sync support
- Group membership mapping

### 5. Token Validator

**Purpose**: Distributed, high-performance token validation

**Responsibilities**:
- Validate JWT signatures
- Check token expiration and not-before
- Verify issuer and audience claims
- Check revocation status
- Cache validation results

**Architecture**:
```
┌──────────────┐
│ Resource     │
│ Server       │
└──────┬───────┘
       │ 1. Validate token
       ▼
┌──────────────────┐
│ Token Validator  │
│                  │
│ 2. Check cache   │◄─────────┐
│ 3. Verify JWT    │          │
│ 4. Check revoke  │          │
└──────┬───────────┘          │
       │                      │
       ▼                      │
┌──────────────────┐    ┌─────────────┐
│ Redis Cache      │    │ PostgreSQL  │
│ - JWKS cache     │    │ - Revoked   │
│ - Validation     │    │   tokens    │
│   results        │    └─────────────┘
└──────────────────┘
```

**Performance Optimizations**:
- JWKS caching with TTL
- Validation result caching (short TTL)
- Bloom filters for revocation check
- Async revocation list updates

### 6. Rate Limiter

**Purpose**: Protect against abuse and ensure fair use

**Responsibilities**:
- Per-tenant rate limiting
- Per-user rate limiting
- Per-IP rate limiting
- Adaptive rate limiting
- Brute force detection

**Rate Limiting Strategy**:
```typescript
interface RateLimitConfig {
  tenant_id: string;
  limits: {
    // Global tenant limits
    requests_per_minute: number;
    requests_per_hour: number;

    // Per-endpoint limits
    endpoints: {
      '/token': { rpm: 60, burst: 10 },
      '/authorize': { rpm: 120, burst: 20 },
      '/userinfo': { rpm: 300, burst: 50 }
    };

    // Per-user limits
    per_user: {
      login_attempts: { count: 5, window: 300 }, // 5 in 5 min
      token_requests: { count: 10, window: 60 }
    };

    // Per-IP limits (brute force protection)
    per_ip: {
      login_attempts: { count: 20, window: 300 }
    };
  };
}
```

**Implementation**:
- Redis with sliding window counters
- Token bucket algorithm
- Distributed rate limiting across instances

## Multi-Tenant Architecture

### Tenant Isolation Strategy

**1. Data Isolation**:
```sql
-- Every table has tenant_id for row-level security
CREATE TABLE users (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email VARCHAR(255) NOT NULL,
  -- ...
  UNIQUE(tenant_id, email)
);

-- PostgreSQL Row-Level Security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON users
  USING (tenant_id = current_setting('app.current_tenant')::UUID);
```

**2. Configuration Isolation**:
- Per-tenant JWKS (different signing keys)
- Per-tenant branding and UI
- Per-tenant OAuth client configurations
- Per-tenant claims pipelines

**3. Domain Isolation**:
```
Tenant A: tenant-a.auth.example.com
Tenant B: tenant-b.auth.example.com
Custom: auth.clientcompany.com (CNAME)
```

**4. Hierarchical Organizations**:
```typescript
interface Tenant {
  id: string;
  parent_tenant_id?: string; // For hierarchical structures
  name: string;
  domain: string;
  config: TenantConfig;
}

// Example hierarchy
Acme Corp (parent)
  ├── Acme Engineering (child)
  ├── Acme Sales (child)
  └── Acme EMEA (child)
      └── Acme UK (grandchild)
```

**Cross-Tenant Features**:
- Shared users across child tenants
- Inherited policies from parent
- Aggregated reporting for parent tenant

### Database Schema Design

```sql
-- Core tenant table
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  parent_tenant_id UUID REFERENCES tenants(id),
  name VARCHAR(255) NOT NULL,
  domain VARCHAR(255) UNIQUE NOT NULL,
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  config JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- OAuth clients (per tenant)
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  client_id VARCHAR(255) UNIQUE NOT NULL,
  client_secret_hash VARCHAR(255),
  client_name VARCHAR(255) NOT NULL,
  grant_types TEXT[] NOT NULL,
  redirect_uris TEXT[] NOT NULL,
  allowed_scopes TEXT[] NOT NULL,
  token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, client_id)
);

-- Users (per tenant)
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  email VARCHAR(255) NOT NULL,
  password_hash VARCHAR(255),
  email_verified BOOLEAN DEFAULT FALSE,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret VARCHAR(255),
  status VARCHAR(50) NOT NULL DEFAULT 'active',
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, email)
);

-- Authorization codes
CREATE TABLE authorization_codes (
  code VARCHAR(255) PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  client_id VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge VARCHAR(255),
  code_challenge_method VARCHAR(50),
  expires_at TIMESTAMP NOT NULL,
  used BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Refresh tokens
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  token_hash VARCHAR(255) UNIQUE NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id),
  scope TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Token revocation list
CREATE TABLE revoked_tokens (
  jti VARCHAR(255) PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  revoked_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);
CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens(expires_at);

-- Audit logs
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  event_type VARCHAR(100) NOT NULL,
  actor_id UUID,
  actor_type VARCHAR(50),
  resource_type VARCHAR(100),
  resource_id VARCHAR(255),
  ip_address INET,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);

-- Claims pipelines
CREATE TABLE claims_pipelines (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  stages JSONB NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, name)
);

-- Federation connections
CREATE TABLE federation_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  type VARCHAR(50) NOT NULL, -- 'saml', 'oidc', 'ldap'
  name VARCHAR(255) NOT NULL,
  config JSONB NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  UNIQUE(tenant_id, name)
);

-- JWKS (per tenant)
CREATE TABLE jwks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  kid VARCHAR(255) NOT NULL,
  key_type VARCHAR(50) NOT NULL, -- 'RSA', 'EC'
  algorithm VARCHAR(50) NOT NULL, -- 'RS256', 'ES256'
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL, -- Encrypted at rest
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP,
  UNIQUE(tenant_id, kid)
);
```

## Data Flow

### OAuth 2.0 Authorization Code Flow with PKCE

```
┌──────────┐                                           ┌──────────────┐
│  Client  │                                           │ Auth Server  │
│   App    │                                           │              │
└────┬─────┘                                           └──────┬───────┘
     │                                                         │
     │ 1. Generate code_verifier & code_challenge            │
     │    (PKCE)                                              │
     │                                                         │
     │ 2. GET /authorize?                                     │
     │    response_type=code&                                 │
     │    client_id=xxx&                                      │
     │    redirect_uri=...&                                   │
     │    scope=openid profile&                               │
     │    state=xyz&                                          │
     │    code_challenge=...&                                 │
     │    code_challenge_method=S256                          │
     ├────────────────────────────────────────────────────────►
     │                                                         │
     │                                      3. Validate client│
     │                                      4. Check if user  │
     │                                         authenticated  │
     │                                                         │
     │                              5. Redirect to login page │
     │◄────────────────────────────────────────────────────────┤
     │                                                         │
     │ 6. User enters credentials                             │
     ├────────────────────────────────────────────────────────►
     │                                                         │
     │                                      7. Authenticate    │
     │                                      8. Check consent   │
     │                                      9. Generate code   │
     │                                     10. Store code      │
     │                                         + challenge     │
     │                                                         │
     │ 11. Redirect to callback with code                     │
     │◄────────────────────────────────────────────────────────┤
     │    https://app.com/callback?code=abc&state=xyz         │
     │                                                         │
     │ 12. POST /token                                        │
     │     grant_type=authorization_code&                     │
     │     code=abc&                                          │
     │     redirect_uri=...&                                  │
     │     client_id=xxx&                                     │
     │     code_verifier=... (PKCE)                          │
     ├────────────────────────────────────────────────────────►
     │                                                         │
     │                                     13. Validate code   │
     │                                     14. Verify PKCE     │
     │                                     15. Generate tokens │
     │                                     16. Run claims      │
     │                                         pipeline        │
     │                                                         │
     │ 17. Return tokens                                      │
     │     {                                                   │
     │       "access_token": "...",                           │
     │       "id_token": "...",                               │
     │       "refresh_token": "...",                          │
     │       "expires_in": 3600                               │
     │     }                                                   │
     │◄────────────────────────────────────────────────────────┤
     │                                                         │
```

### Token Validation Flow

```
┌──────────────┐          ┌──────────────┐          ┌─────────┐
│  Resource    │          │   Token      │          │  Redis  │
│  Server      │          │  Validator   │          │  Cache  │
└──────┬───────┘          └──────┬───────┘          └────┬────┘
       │                         │                       │
       │ 1. Validate token       │                       │
       ├────────────────────────►│                       │
       │                         │                       │
       │                         │ 2. Check cache        │
       │                         ├──────────────────────►│
       │                         │                       │
       │                         │ 3. Cache hit?         │
       │                         │◄──────────────────────┤
       │                         │                       │
       │                         │ [If miss]             │
       │                         │ 4. Fetch JWKS         │
       │                         │    (cached)           │
       │                         │                       │
       │                         │ 5. Verify signature   │
       │                         │                       │
       │                         │ 6. Check expiration   │
       │                         │                       │
       │                         │ 7. Check revocation   │
       │                         │    (Bloom filter)     │
       │                         │                       │
       │                         │ 8. Cache result       │
       │                         ├──────────────────────►│
       │                         │                       │
       │ 9. Return validation    │                       │
       │    result + claims      │                       │
       │◄────────────────────────┤                       │
       │                         │                       │
```

## Security Architecture

### Defense in Depth

**1. Transport Security**:
- TLS 1.3 only
- Certificate pinning for mobile apps
- HSTS headers

**2. Application Security**:
- CSRF protection (state parameter, SameSite cookies)
- XSS prevention (Content Security Policy)
- SQL injection prevention (parameterized queries)
- Input validation (Zod schemas)

**3. Authentication Security**:
- Password hashing (Argon2id)
- MFA support (TOTP, WebAuthn)
- Brute force protection
- Account lockout policies

**4. Authorization Security**:
- Scope-based access control
- Fine-grained permissions
- Claims-based authorization
- Tenant isolation enforcement

**5. Token Security**:
- Short-lived access tokens (15 min)
- Rotating refresh tokens
- Token binding
- Proof-of-Possession tokens (DPoP)

**6. Cryptography**:
- RS256 for JWT signing (RSA 2048-bit minimum)
- Automatic key rotation (90 days)
- Encryption at rest for sensitive data
- HSM integration for production keys

### Threat Modeling

**Threats & Mitigations**:

| Threat | Mitigation |
|--------|-----------|
| Token theft | Short TTL, rotation, DPoP |
| CSRF attacks | State parameter, SameSite cookies |
| Authorization code interception | PKCE required |
| Brute force attacks | Rate limiting, account lockout |
| SQL injection | Parameterized queries, ORM |
| XSS attacks | CSP headers, input sanitization |
| Tenant data leakage | Row-level security, strict isolation |
| Credential stuffing | Password breach detection, MFA |
| Man-in-the-middle | TLS only, certificate pinning |
| Replay attacks | Nonce validation, timestamp checks |

## Scalability & Performance

### Horizontal Scaling

All services are stateless and can scale horizontally:

```
┌─────────────────────────────────────────────────┐
│              Load Balancer (Nginx)              │
└─────────────┬───────────────────────────────────┘
              │
              ├──────────┬──────────┬──────────┐
              ▼          ▼          ▼          ▼
         ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
         │Auth    │ │Auth    │ │Auth    │ │Auth    │
         │Server 1│ │Server 2│ │Server 3│ │Server N│
         └───┬────┘ └───┬────┘ └───┬────┘ └───┬────┘
             │          │          │          │
             └──────────┴──────────┴──────────┘
                        │
                        ▼
              ┌──────────────────┐
              │  Shared Redis    │
              │  (Sessions)      │
              └──────────────────┘
```

### Performance Targets

- **Token issuance**: < 100ms p95
- **Token validation**: < 10ms p95 (cached), < 50ms p95 (uncached)
- **Authorization flow**: < 500ms p95 (end-to-end)
- **Throughput**: 10,000 requests/sec per instance
- **Database queries**: < 20ms p95

### Optimization Strategies

**1. Caching**:
- Redis for sessions (5 min TTL)
- JWKS caching (1 hour TTL)
- Validation results (1 min TTL)
- User profile caching (5 min TTL)

**2. Database**:
- Connection pooling (pgBouncer)
- Read replicas for analytics
- Partitioning for audit logs (by month)
- Indexes on foreign keys and lookups

**3. Async Processing**:
- Audit logs via queue
- Email notifications via queue
- LDAP sync via scheduled jobs
- Claims processing (parallel stages)

**4. CDN**:
- Static assets (login page UI)
- JWKS endpoint
- Discovery documents

## Technology Decisions

### Why TypeScript/Node.js?

**Pros**:
- Excellent for I/O-bound operations (OAuth flows)
- Rich ecosystem for crypto (`jose`, `node:crypto`)
- Easy to demonstrate and iterate
- Strong typing for safety
- Popular in identity space (Auth0, FusionAuth use Node)

**Cons**:
- Not ideal for CPU-intensive operations
- Requires careful async handling

### Why PostgreSQL?

**Pros**:
- JSONB for flexible tenant configs
- Row-level security for tenant isolation
- Strong ACID guarantees
- Excellent performance for OLTP workloads
- Built-in full-text search

### Why Redis?

**Pros**:
- High-performance caching
- Built-in data structures (sorted sets, streams)
- Pub/sub for distributed events
- Lua scripting for atomic operations

### Alternative Considerations

For production at scale, consider:
- **Go** for better performance and concurrency
- **Cassandra/ScyllaDB** for massive scale
- **Kafka** for event streaming
- **Vault** for secrets management
- **Kubernetes** for orchestration

## Next Steps

See the following documents for implementation details:
- [Multi-Tenancy Design](./MULTI_TENANCY.md)
- [Security Model](./SECURITY.md)
- [API Reference](./API_REFERENCE.md)
- [Deployment Guide](./DEPLOYMENT.md)
