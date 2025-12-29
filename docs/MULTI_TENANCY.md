# Multi-Tenancy Design

## Overview

TenantGuard implements a strict multi-tenant architecture where each tenant (organization) operates in complete isolation while sharing the same infrastructure. This document details the multi-tenancy patterns, isolation strategies, and cross-tenant features.

## Table of Contents
1. [Tenancy Models](#tenancy-models)
2. [Data Isolation](#data-isolation)
3. [Tenant Identification](#tenant-identification)
4. [Hierarchical Organizations](#hierarchical-organizations)
5. [Cross-Tenant Capabilities](#cross-tenant-capabilities)
6. [Performance Considerations](#performance-considerations)
7. [Migration & Onboarding](#migration--onboarding)

## Tenancy Models

### Model Comparison

| Aspect | Shared Database | Database per Tenant | Hybrid |
|--------|----------------|-------------------|--------|
| **Data Isolation** | Row-level (tenant_id) | Complete | Mixed |
| **Cost** | Low | High | Medium |
| **Scalability** | Horizontal | Vertical per tenant | Best of both |
| **Performance** | Shared resources | Dedicated | Configurable |
| **Compliance** | Complex | Simple | Flexible |
| **TenantGuard Choice** | ✓ Primary | Future option | - |

**TenantGuard Implementation**: Shared database with row-level security (RLS), with future support for dedicated databases for enterprise customers.

## Data Isolation

### 1. Database-Level Isolation

#### Row-Level Security (RLS)

Every table includes a `tenant_id` column with PostgreSQL RLS policies:

```sql
-- Enable RLS on all tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their tenant's data
CREATE POLICY tenant_isolation ON users
  USING (tenant_id = current_setting('app.current_tenant')::UUID);

CREATE POLICY tenant_isolation ON oauth_clients
  USING (tenant_id = current_setting('app.current_tenant')::UUID);

-- For admin operations, use a separate policy
CREATE POLICY admin_access ON users
  USING (
    current_setting('app.user_role', true) = 'admin' OR
    tenant_id = current_setting('app.current_tenant')::UUID
  );
```

#### Setting Tenant Context

Every database connection sets the tenant context:

```typescript
import { Pool } from 'pg';

class TenantAwarePool {
  private pool: Pool;

  async queryWithTenant<T>(
    tenantId: string,
    query: string,
    params: any[]
  ): Promise<T> {
    const client = await this.pool.connect();

    try {
      // Set tenant context for this transaction
      await client.query(
        'SET LOCAL app.current_tenant = $1',
        [tenantId]
      );

      // Now all queries respect RLS policies
      const result = await client.query(query, params);
      return result.rows;
    } finally {
      client.release();
    }
  }
}
```

#### Unique Constraints with Tenant

```sql
-- Email must be unique per tenant (not globally)
CREATE UNIQUE INDEX idx_users_tenant_email
  ON users(tenant_id, email);

-- Client IDs must be unique per tenant
CREATE UNIQUE INDEX idx_clients_tenant_client_id
  ON oauth_clients(tenant_id, client_id);

-- Custom domains must be globally unique
CREATE UNIQUE INDEX idx_tenants_domain
  ON tenants(domain);
```

### 2. Application-Level Isolation

#### Middleware Enforcement

```typescript
import { Request, Response, NextFunction } from 'express';

interface TenantRequest extends Request {
  tenant?: Tenant;
  tenantId?: string;
}

// Extract tenant from subdomain or header
async function tenantMiddleware(
  req: TenantRequest,
  res: Response,
  next: NextFunction
) {
  try {
    // Strategy 1: Subdomain
    const subdomain = req.hostname.split('.')[0];

    // Strategy 2: Custom domain
    const customDomain = req.hostname;

    // Strategy 3: Header (for API clients)
    const tenantHeader = req.headers['x-tenant-id'] as string;

    let tenant: Tenant | null = null;

    if (subdomain && subdomain !== 'www') {
      tenant = await getTenantBySubdomain(subdomain);
    } else if (customDomain) {
      tenant = await getTenantByDomain(customDomain);
    } else if (tenantHeader) {
      tenant = await getTenantById(tenantHeader);
    }

    if (!tenant) {
      return res.status(404).json({
        error: 'tenant_not_found',
        error_description: 'Unable to identify tenant from request'
      });
    }

    if (tenant.status !== 'active') {
      return res.status(403).json({
        error: 'tenant_suspended',
        error_description: 'This tenant has been suspended'
      });
    }

    req.tenant = tenant;
    req.tenantId = tenant.id;
    next();
  } catch (error) {
    next(error);
  }
}

// Apply to all routes
app.use(tenantMiddleware);
```

#### Repository Pattern with Tenant Scoping

```typescript
class UserRepository {
  constructor(private pool: TenantAwarePool) {}

  async findByEmail(tenantId: string, email: string): Promise<User | null> {
    const result = await this.pool.queryWithTenant(
      tenantId,
      'SELECT * FROM users WHERE email = $1 LIMIT 1',
      [email]
    );
    return result[0] || null;
  }

  async create(tenantId: string, userData: CreateUserInput): Promise<User> {
    const result = await this.pool.queryWithTenant(
      tenantId,
      `INSERT INTO users (tenant_id, email, password_hash, metadata)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [tenantId, userData.email, userData.passwordHash, userData.metadata]
    );
    return result[0];
  }

  // IMPORTANT: This method does NOT take tenantId
  // It's for admin operations across all tenants
  async findById(userId: string): Promise<User | null> {
    const result = await this.pool.query(
      'SELECT * FROM users WHERE id = $1',
      [userId]
    );
    return result[0] || null;
  }
}
```

### 3. Configuration Isolation

Each tenant has isolated configuration:

```typescript
interface TenantConfig {
  // Branding
  branding: {
    logo_url: string;
    primary_color: string;
    company_name: string;
  };

  // OAuth settings
  oauth: {
    access_token_ttl: number;      // seconds
    refresh_token_ttl: number;     // seconds
    authorization_code_ttl: number; // seconds
    require_pkce: boolean;
    allowed_grant_types: string[];
  };

  // Security settings
  security: {
    password_policy: {
      min_length: number;
      require_uppercase: boolean;
      require_lowercase: boolean;
      require_numbers: boolean;
      require_symbols: boolean;
    };
    mfa_required: boolean;
    session_timeout: number;
    max_login_attempts: number;
    lockout_duration: number;
  };

  // Rate limiting (per tenant)
  rate_limits: {
    requests_per_minute: number;
    burst_size: number;
    endpoints: Record<string, { rpm: number; burst: number }>;
  };

  // Federation
  federation: {
    saml_enabled: boolean;
    ldap_enabled: boolean;
    social_providers: string[];
  };

  // Claims
  claims: {
    default_pipeline_id?: string;
    custom_namespace?: string; // e.g., "https://acme.com/claims"
  };
}

// Stored in tenants.config JSONB column
const tenant = await getTenantById(tenantId);
const config = tenant.config as TenantConfig;

// Apply tenant-specific settings
const accessTokenTTL = config.oauth.access_token_ttl || 900; // default 15 min
```

### 4. Cryptographic Isolation

Each tenant has its own signing keys:

```typescript
interface TenantKeyPair {
  tenant_id: string;
  kid: string;
  algorithm: 'RS256' | 'ES256';
  public_key: string;
  private_key: string; // Encrypted at rest
  active: boolean;
  created_at: Date;
  expires_at?: Date;
}

class TenantKeyManager {
  async getSigningKey(tenantId: string): Promise<TenantKeyPair> {
    // Get active signing key for tenant
    const key = await this.pool.queryWithTenant(
      tenantId,
      `SELECT * FROM jwks
       WHERE tenant_id = $1 AND active = true
       ORDER BY created_at DESC LIMIT 1`,
      [tenantId]
    );

    if (!key[0]) {
      // Generate new key pair if none exists
      return await this.generateKeyPair(tenantId);
    }

    return key[0];
  }

  async getPublicKeys(tenantId: string): Promise<JWK[]> {
    // Get all active public keys for JWKS endpoint
    const keys = await this.pool.queryWithTenant(
      tenantId,
      `SELECT kid, key_type, algorithm, public_key
       FROM jwks
       WHERE tenant_id = $1 AND active = true`,
      [tenantId]
    );

    return keys.map(k => this.toJWK(k));
  }

  // Automatic key rotation every 90 days
  async rotateKeys(tenantId: string): Promise<void> {
    const newKey = await this.generateKeyPair(tenantId);

    // Keep old key active for 24 hours to allow token validation
    await this.pool.queryWithTenant(
      tenantId,
      `UPDATE jwks
       SET active = false, expires_at = NOW() + INTERVAL '24 hours'
       WHERE tenant_id = $1 AND active = true`,
      [tenantId]
    );
  }
}

// Tenant-specific JWKS endpoint
app.get('/.well-known/jwks.json', tenantMiddleware, async (req, res) => {
  const keyManager = new TenantKeyManager(pool);
  const jwks = await keyManager.getPublicKeys(req.tenantId!);

  res.json({
    keys: jwks
  });
});
```

## Tenant Identification

### Strategy 1: Subdomain-based (Primary)

```
Format: {tenant-slug}.auth.example.com

Examples:
- acme-corp.auth.example.com
- startup-xyz.auth.example.com
- enterprise.auth.example.com

Pros:
- Clear visual separation
- Easy to implement
- Browser cookie isolation
- DNS-based routing

Cons:
- Requires wildcard SSL certificate
- Limited to DNS-safe characters
```

```typescript
// Extract tenant from subdomain
const subdomain = req.hostname.split('.')[0];
const tenant = await getTenantBySlug(subdomain);
```

### Strategy 2: Custom Domain (Enterprise)

```
Format: auth.{customer-domain.com}

Examples:
- auth.acme.com (CNAME → acme-corp.auth.example.com)
- sso.startup.io (CNAME → startup-xyz.auth.example.com)

Pros:
- White-label branding
- Professional appearance
- SEO benefits

Cons:
- DNS configuration required
- SSL certificate per domain (or wildcard + SNI)
```

```sql
-- Custom domain mapping
CREATE TABLE custom_domains (
  id UUID PRIMARY KEY,
  tenant_id UUID NOT NULL REFERENCES tenants(id),
  domain VARCHAR(255) UNIQUE NOT NULL,
  verified BOOLEAN DEFAULT FALSE,
  ssl_certificate_id VARCHAR(255),
  created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Verification via TXT record
INSERT INTO custom_domains (tenant_id, domain)
VALUES ('acme-uuid', 'auth.acme.com');

-- Customer adds DNS:
-- auth.acme.com CNAME acme-corp.auth.example.com
-- _verification.acme.com TXT "tenant-verification=abc123"
```

### Strategy 3: Header-based (API Clients)

```http
GET /oauth/token
Host: auth.example.com
X-Tenant-ID: acme-corp
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=...
```

```typescript
// For API-to-API auth where subdomain is impractical
const tenantId = req.headers['x-tenant-id'];
if (!tenantId) {
  return res.status(400).json({ error: 'missing_tenant_id' });
}
```

## Hierarchical Organizations

### Parent-Child Relationships

```typescript
interface Tenant {
  id: string;
  parent_tenant_id?: string;
  name: string;
  type: 'root' | 'child';
  depth: number; // 0 for root, 1 for direct child, etc.
}

// Example hierarchy
const hierarchy = {
  id: 'acme-root',
  name: 'Acme Corporation',
  type: 'root',
  children: [
    {
      id: 'acme-eng',
      name: 'Engineering',
      type: 'child',
      parent_tenant_id: 'acme-root'
    },
    {
      id: 'acme-sales',
      name: 'Sales',
      type: 'child',
      parent_tenant_id: 'acme-root'
    },
    {
      id: 'acme-emea',
      name: 'EMEA Region',
      type: 'child',
      parent_tenant_id: 'acme-root',
      children: [
        {
          id: 'acme-uk',
          name: 'UK Office',
          type: 'child',
          parent_tenant_id: 'acme-emea'
        }
      ]
    }
  ]
};
```

### Inheritance Patterns

```typescript
class TenantConfigResolver {
  async resolveConfig(tenantId: string): Promise<TenantConfig> {
    const tenant = await this.getTenantWithAncestors(tenantId);

    // Merge configs from root to leaf (child overrides parent)
    const configs = [
      this.getDefaultConfig(),
      ...tenant.ancestors.map(t => t.config),
      tenant.config
    ];

    return this.mergeConfigs(configs);
  }

  private mergeConfigs(configs: Partial<TenantConfig>[]): TenantConfig {
    // Deep merge with later configs overriding earlier ones
    return configs.reduce(
      (merged, config) => deepMerge(merged, config),
      {} as TenantConfig
    );
  }
}

// Example: Child inherits parent's security settings but overrides MFA
const parent = {
  security: {
    password_policy: { min_length: 12 },
    mfa_required: false
  }
};

const child = {
  security: {
    mfa_required: true // Override parent
  }
};

// Resolved config for child:
{
  security: {
    password_policy: { min_length: 12 }, // Inherited
    mfa_required: true                   // Overridden
  }
}
```

### Cross-Org User Access

```typescript
// User can belong to multiple tenants in hierarchy
interface UserTenantMembership {
  user_id: string;
  tenant_id: string;
  roles: string[];
  inherited: boolean; // True if from parent org
}

// Alice is in parent org (Acme Corp)
// She automatically has access to child orgs (Engineering, Sales)
const memberships = await getUserMemberships('alice@acme.com');
// Returns:
[
  { tenant_id: 'acme-root', roles: ['admin'], inherited: false },
  { tenant_id: 'acme-eng', roles: ['admin'], inherited: true },
  { tenant_id: 'acme-sales', roles: ['admin'], inherited: true },
  { tenant_id: 'acme-uk', roles: ['admin'], inherited: true }
]
```

## Cross-Tenant Capabilities

### 1. Shared User Directory (Enterprise Feature)

```typescript
interface SharedUser {
  id: string;
  email: string;
  primary_tenant_id: string;
  accessible_tenants: string[]; // Explicit grants
}

// User logs in via parent org
// Gets tokens that work across child orgs
const token = await issueToken({
  sub: 'user-id',
  tenant_id: 'acme-root',
  accessible_tenants: ['acme-root', 'acme-eng', 'acme-sales']
});

// Token validation checks if resource tenant is in accessible list
function validateCrossTenantAccess(
  token: DecodedToken,
  resourceTenantId: string
): boolean {
  return token.accessible_tenants?.includes(resourceTenantId) || false;
}
```

### 2. Aggregated Reporting

```typescript
// Parent org can view aggregated metrics from all child orgs
class TenantReporting {
  async getAggregatedMetrics(rootTenantId: string): Promise<Metrics> {
    const descendants = await this.getDescendantTenants(rootTenantId);
    const tenantIds = [rootTenantId, ...descendants.map(t => t.id)];

    // Aggregate audit logs across all orgs
    const metrics = await this.pool.query(
      `SELECT
         event_type,
         COUNT(*) as count,
         tenant_id
       FROM audit_logs
       WHERE tenant_id = ANY($1)
         AND created_at > NOW() - INTERVAL '30 days'
       GROUP BY event_type, tenant_id`,
      [tenantIds]
    );

    return this.aggregateMetrics(metrics);
  }
}
```

### 3. Delegated Administration

```typescript
// Parent org admin can manage child org settings
interface DelegatedPermission {
  admin_user_id: string;
  admin_tenant_id: string;
  target_tenant_id: string;
  permissions: string[];
}

// Alice (Acme Corp admin) can create users in Engineering org
await checkDelegatedPermission({
  admin_user_id: 'alice',
  admin_tenant_id: 'acme-root',
  target_tenant_id: 'acme-eng',
  permission: 'users:create'
}); // Returns true
```

## Performance Considerations

### 1. Tenant Caching

```typescript
import { Redis } from 'ioredis';

class TenantCache {
  constructor(private redis: Redis) {}

  async getTenant(identifier: string): Promise<Tenant | null> {
    // Try cache first
    const cached = await this.redis.get(`tenant:${identifier}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // Cache miss - fetch from database
    const tenant = await this.fetchFromDatabase(identifier);
    if (tenant) {
      // Cache for 5 minutes
      await this.redis.setex(
        `tenant:${identifier}`,
        300,
        JSON.stringify(tenant)
      );
    }

    return tenant;
  }

  async invalidate(tenantId: string): Promise<void> {
    // Invalidate all cache keys for this tenant
    await this.redis.del(
      `tenant:${tenantId}`,
      `tenant:slug:${tenant.slug}`,
      `tenant:domain:${tenant.domain}`
    );
  }
}
```

### 2. Database Partitioning

For very large deployments, partition audit logs by tenant:

```sql
-- Create partitioned table
CREATE TABLE audit_logs (
  id UUID NOT NULL,
  tenant_id UUID NOT NULL,
  event_type VARCHAR(100) NOT NULL,
  -- ... other columns
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, id, created_at)
) PARTITION BY HASH (tenant_id);

-- Create partitions
CREATE TABLE audit_logs_p0 PARTITION OF audit_logs
  FOR VALUES WITH (MODULUS 16, REMAINDER 0);

CREATE TABLE audit_logs_p1 PARTITION OF audit_logs
  FOR VALUES WITH (MODULUS 16, REMAINDER 1);

-- ... create p2 through p15
```

### 3. Connection Pooling

```typescript
import { Pool } from 'pg';

class TenantAwareConnectionPool {
  private pools: Map<string, Pool> = new Map();

  getPool(tenantId: string): Pool {
    // Option 1: Shared pool (our choice)
    if (!this.pools.has('shared')) {
      this.pools.set('shared', new Pool({
        max: 100,
        idleTimeoutMillis: 30000
      }));
    }
    return this.pools.get('shared')!;

    // Option 2: Pool per tenant (for dedicated databases)
    // if (!this.pools.has(tenantId)) {
    //   const tenant = await getTenant(tenantId);
    //   this.pools.set(tenantId, new Pool({
    //     connectionString: tenant.database_url,
    //     max: 10
    //   }));
    // }
    // return this.pools.get(tenantId)!;
  }
}
```

## Migration & Onboarding

### Tenant Provisioning Flow

```typescript
async function provisionNewTenant(input: {
  name: string;
  slug: string;
  admin_email: string;
  admin_password: string;
}): Promise<Tenant> {
  const db = await pool.connect();

  try {
    await db.query('BEGIN');

    // 1. Create tenant
    const tenant = await db.query(
      `INSERT INTO tenants (name, domain, status, config)
       VALUES ($1, $2, 'active', $3)
       RETURNING *`,
      [
        input.name,
        `${input.slug}.auth.example.com`,
        JSON.stringify(getDefaultTenantConfig())
      ]
    );
    const tenantId = tenant.rows[0].id;

    // 2. Generate signing keys
    const keyPair = await generateRSAKeyPair();
    await db.query(
      `INSERT INTO jwks (tenant_id, kid, key_type, algorithm, public_key, private_key, active)
       VALUES ($1, $2, 'RSA', 'RS256', $3, $4, true)`,
      [tenantId, generateKID(), keyPair.publicKey, encrypt(keyPair.privateKey)]
    );

    // 3. Create admin user
    const adminUser = await db.query(
      `INSERT INTO users (tenant_id, email, password_hash, email_verified, metadata)
       VALUES ($1, $2, $3, true, $4)
       RETURNING *`,
      [
        tenantId,
        input.admin_email,
        await hashPassword(input.admin_password),
        JSON.stringify({ role: 'admin', created_by: 'system' })
      ]
    );

    // 4. Create default OAuth client (for tenant's admin panel)
    await db.query(
      `INSERT INTO oauth_clients (
        tenant_id, client_id, client_secret_hash, client_name,
        grant_types, redirect_uris, allowed_scopes
      ) VALUES ($1, $2, $3, 'Admin Panel', $4, $5, $6)`,
      [
        tenantId,
        generateClientId(),
        await hashClientSecret('secret-123'),
        ['authorization_code', 'refresh_token'],
        [`https://${input.slug}.app.example.com/callback`],
        ['openid', 'profile', 'email', 'admin']
      ]
    );

    // 5. Audit log
    await db.query(
      `INSERT INTO audit_logs (tenant_id, event_type, actor_type, metadata)
       VALUES ($1, 'tenant.created', 'system', $2)`,
      [tenantId, JSON.stringify({ name: input.name })]
    );

    await db.query('COMMIT');
    return tenant.rows[0];
  } catch (error) {
    await db.query('ROLLBACK');
    throw error;
  } finally {
    db.release();
  }
}
```

### Tenant Migration (Moving Data Between Tenants)

```typescript
// Export tenant data
async function exportTenantData(tenantId: string): Promise<TenantExport> {
  const users = await pool.queryWithTenant(
    tenantId,
    'SELECT * FROM users WHERE tenant_id = $1',
    [tenantId]
  );

  const clients = await pool.queryWithTenant(
    tenantId,
    'SELECT * FROM oauth_clients WHERE tenant_id = $1',
    [tenantId]
  );

  // ... export other resources

  return {
    version: '1.0',
    tenant_id: tenantId,
    exported_at: new Date(),
    data: {
      users: users.map(sanitizeUser),
      clients: clients.map(sanitizeClient)
    }
  };
}

// Import into new tenant
async function importTenantData(
  targetTenantId: string,
  exportData: TenantExport
): Promise<void> {
  // Validate, transform IDs, and import
  // Useful for tenant merges or environment migrations
}
```

## Best Practices

1. **Always validate tenant context** before any database operation
2. **Use RLS policies** as a safety net, not the primary isolation mechanism
3. **Cache tenant data aggressively** to avoid repeated lookups
4. **Monitor cross-tenant data leakage** with audit logs
5. **Test tenant isolation** regularly with chaos engineering
6. **Document tenant-specific features** clearly in admin UI
7. **Provide tenant analytics** for usage and billing
8. **Plan for tenant data export** (GDPR, migrations)
9. **Implement soft deletes** for tenant data (recovery)
10. **Use feature flags** for per-tenant feature rollout

## Next Steps

- [Security Model](./SECURITY.md)
- [API Reference](./API_REFERENCE.md)
- [Deployment Guide](./DEPLOYMENT.md)
