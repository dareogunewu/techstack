# Security Model

## Overview

Security is paramount in an identity platform. This document outlines TenantGuard's comprehensive security model, threat mitigations, and best practices.

## Table of Contents
1. [Security Principles](#security-principles)
2. [Authentication Security](#authentication-security)
3. [Authorization Security](#authorization-security)
4. [Token Security](#token-security)
5. [Cryptographic Standards](#cryptographic-standards)
6. [Rate Limiting & Abuse Prevention](#rate-limiting--abuse-prevention)
7. [Audit & Compliance](#audit--compliance)
8. [Threat Model](#threat-model)

## Security Principles

### Defense in Depth

TenantGuard implements multiple layers of security:

```
┌─────────────────────────────────────────┐
│ Layer 1: Network & Transport            │
│ - TLS 1.3                               │
│ - DDoS protection                       │
│ - Firewall rules                        │
├─────────────────────────────────────────┤
│ Layer 2: Application Gateway            │
│ - Rate limiting                         │
│ - WAF (Web Application Firewall)        │
│ - Input validation                      │
├─────────────────────────────────────────┤
│ Layer 3: Authentication                 │
│ - Strong password policies              │
│ - Multi-factor authentication           │
│ - Brute force protection                │
├─────────────────────────────────────────┤
│ Layer 4: Authorization                  │
│ - OAuth 2.0 scopes                      │
│ - Fine-grained permissions              │
│ - Tenant isolation                      │
├─────────────────────────────────────────┤
│ Layer 5: Data                           │
│ - Encryption at rest                    │
│ - Encryption in transit                 │
│ - Row-level security                    │
├─────────────────────────────────────────┤
│ Layer 6: Monitoring & Audit             │
│ - Comprehensive logging                 │
│ - Anomaly detection                     │
│ - Security alerts                       │
└─────────────────────────────────────────┘
```

### Zero Trust Architecture

- Never trust, always verify
- Verify every request
- Least privilege access
- Assume breach mentality

## Authentication Security

### Password Security

#### Storage

```typescript
import argon2 from 'argon2';

async function hashPassword(password: string): Promise<string> {
  // Argon2id: Hybrid of Argon2i (side-channel resistant) and Argon2d (GPU resistant)
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,  // 64 MB
    timeCost: 3,        // 3 iterations
    parallelism: 4      // 4 threads
  });
}

async function verifyPassword(
  hash: string,
  password: string
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch (error) {
    return false;
  }
}
```

#### Password Policy

```typescript
interface PasswordPolicy {
  min_length: number;           // Minimum 12
  max_length: number;           // Maximum 128
  require_uppercase: boolean;   // At least one A-Z
  require_lowercase: boolean;   // At least one a-z
  require_numbers: boolean;     // At least one 0-9
  require_symbols: boolean;     // At least one !@#$%^&*
  prevent_common: boolean;      // Check against common password list
  prevent_reuse: number;        // Don't reuse last N passwords
  max_age_days: number;         // Force reset after N days (0 = never)
}

function validatePassword(
  password: string,
  policy: PasswordPolicy,
  userInfo: { email: string; name: string }
): ValidationResult {
  const errors: string[] = [];

  if (password.length < policy.min_length) {
    errors.push(`Password must be at least ${policy.min_length} characters`);
  }

  if (policy.require_uppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain an uppercase letter');
  }

  if (policy.require_lowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain a lowercase letter');
  }

  if (policy.require_numbers && !/[0-9]/.test(password)) {
    errors.push('Password must contain a number');
  }

  if (policy.require_symbols && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain a special character');
  }

  // Check if password contains user info
  const lowerPassword = password.toLowerCase();
  if (lowerPassword.includes(userInfo.email.split('@')[0].toLowerCase())) {
    errors.push('Password cannot contain your email');
  }

  // Check against common passwords (top 10k)
  if (policy.prevent_common && isCommonPassword(password)) {
    errors.push('This password is too common');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}
```

### Multi-Factor Authentication

#### TOTP (Time-based One-Time Password)

```typescript
import * as speakeasy from 'speakeasy';
import * as QRCode from 'qrcode';

async function enableTOTP(userId: string, tenantId: string) {
  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `TenantGuard (${tenantId})`,
    issuer: 'TenantGuard',
    length: 32
  });

  // Store encrypted secret
  await pool.queryWithTenant(
    tenantId,
    `UPDATE users SET mfa_secret = $1, mfa_enabled = false
     WHERE id = $2`,
    [encrypt(secret.base32), userId]
  );

  // Generate QR code for authenticator apps
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!);

  return {
    secret: secret.base32,
    qr_code: qrCodeUrl,
    backup_codes: generateBackupCodes(8) // 8 single-use codes
  };
}

async function verifyTOTP(
  userId: string,
  tenantId: string,
  token: string
): Promise<boolean> {
  const user = await getUserById(tenantId, userId);

  if (!user.mfa_secret) {
    throw new Error('MFA not enabled for this user');
  }

  const secret = decrypt(user.mfa_secret);

  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token,
    window: 2 // Allow 1 step before/after (30s * 2 = ±1 min)
  });

  if (verified && !user.mfa_enabled) {
    // First successful verification, enable MFA
    await pool.queryWithTenant(
      tenantId,
      'UPDATE users SET mfa_enabled = true WHERE id = $1',
      [userId]
    );
  }

  return verified;
}
```

#### WebAuthn / FIDO2

```typescript
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';

async function registerWebAuthnDevice(userId: string, tenantId: string) {
  const user = await getUserById(tenantId, userId);

  const options = generateRegistrationOptions({
    rpName: 'TenantGuard',
    rpID: 'auth.example.com',
    userID: userId,
    userName: user.email,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // or 'cross-platform'
      requireResidentKey: false,
      userVerification: 'preferred'
    }
  });

  // Store challenge temporarily
  await storeChallenge(userId, options.challenge);

  return options;
}

async function verifyWebAuthnRegistration(
  userId: string,
  tenantId: string,
  response: any
) {
  const challenge = await getChallenge(userId);

  const verification = await verifyRegistrationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: 'https://auth.example.com',
    expectedRPID: 'auth.example.com'
  });

  if (verification.verified) {
    // Store credential
    await pool.queryWithTenant(
      tenantId,
      `INSERT INTO webauthn_credentials (user_id, credential_id, public_key, counter)
       VALUES ($1, $2, $3, $4)`,
      [
        userId,
        verification.registrationInfo!.credentialID,
        verification.registrationInfo!.credentialPublicKey,
        verification.registrationInfo!.counter
      ]
    );
  }

  return verification.verified;
}
```

### Session Management

```typescript
interface SessionData {
  session_id: string;
  user_id: string;
  tenant_id: string;
  ip_address: string;
  user_agent: string;
  created_at: Date;
  last_activity: Date;
  expires_at: Date;
  mfa_verified: boolean;
}

class SessionManager {
  async createSession(
    userId: string,
    tenantId: string,
    req: Request
  ): Promise<string> {
    const sessionId = generateSecureToken(32);

    const sessionData: SessionData = {
      session_id: sessionId,
      user_id: userId,
      tenant_id: tenantId,
      ip_address: req.ip,
      user_agent: req.headers['user-agent'] || '',
      created_at: new Date(),
      last_activity: new Date(),
      expires_at: new Date(Date.now() + 30 * 60 * 1000), // 30 min
      mfa_verified: false
    };

    // Store in Redis
    await redis.setex(
      `session:${sessionId}`,
      30 * 60, // 30 minutes
      JSON.stringify(sessionData)
    );

    return sessionId;
  }

  async validateSession(sessionId: string): Promise<SessionData | null> {
    const data = await redis.get(`session:${sessionId}`);
    if (!data) return null;

    const session: SessionData = JSON.parse(data);

    // Check expiration
    if (new Date() > session.expires_at) {
      await this.destroySession(sessionId);
      return null;
    }

    // Update last activity
    session.last_activity = new Date();
    await redis.setex(
      `session:${sessionId}`,
      30 * 60,
      JSON.stringify(session)
    );

    return session;
  }

  async destroySession(sessionId: string): Promise<void> {
    await redis.del(`session:${sessionId}`);

    // Audit log
    await logEvent({
      event_type: 'session.destroyed',
      session_id: sessionId
    });
  }

  // Destroy all sessions for a user (force logout everywhere)
  async destroyAllUserSessions(userId: string): Promise<void> {
    const pattern = `session:*`;
    const keys = await redis.keys(pattern);

    for (const key of keys) {
      const data = await redis.get(key);
      if (data) {
        const session: SessionData = JSON.parse(data);
        if (session.user_id === userId) {
          await redis.del(key);
        }
      }
    }
  }
}
```

### Brute Force Protection

```typescript
class BruteForceProtection {
  // Track failed login attempts per user
  async recordFailedLogin(
    tenantId: string,
    identifier: string, // email or username
    ip: string
  ): Promise<void> {
    const userKey = `failed_login:${tenantId}:${identifier}`;
    const ipKey = `failed_login_ip:${ip}`;

    // Increment counters with 15-minute expiry
    await redis.incr(userKey);
    await redis.expire(userKey, 15 * 60);

    await redis.incr(ipKey);
    await redis.expire(ipKey, 15 * 60);

    const userAttempts = await redis.get(userKey);
    const ipAttempts = await redis.get(ipKey);

    // Lock account after 5 attempts
    if (parseInt(userAttempts || '0') >= 5) {
      await this.lockAccount(tenantId, identifier, 30 * 60); // 30 min
    }

    // Block IP after 20 attempts (across all accounts)
    if (parseInt(ipAttempts || '0') >= 20) {
      await this.blockIP(ip, 60 * 60); // 1 hour
    }
  }

  async checkIfBlocked(
    tenantId: string,
    identifier: string,
    ip: string
  ): Promise<{ blocked: boolean; reason?: string; retry_after?: number }> {
    // Check account lock
    const accountLocked = await redis.get(`account_locked:${tenantId}:${identifier}`);
    if (accountLocked) {
      const ttl = await redis.ttl(`account_locked:${tenantId}:${identifier}`);
      return {
        blocked: true,
        reason: 'account_locked',
        retry_after: ttl
      };
    }

    // Check IP block
    const ipBlocked = await redis.get(`ip_blocked:${ip}`);
    if (ipBlocked) {
      const ttl = await redis.ttl(`ip_blocked:${ip}`);
      return {
        blocked: true,
        reason: 'ip_blocked',
        retry_after: ttl
      };
    }

    return { blocked: false };
  }

  async recordSuccessfulLogin(tenantId: string, identifier: string): Promise<void> {
    // Clear failed attempts
    await redis.del(`failed_login:${tenantId}:${identifier}`);
  }

  private async lockAccount(
    tenantId: string,
    identifier: string,
    duration: number
  ): Promise<void> {
    await redis.setex(`account_locked:${tenantId}:${identifier}`, duration, '1');

    // Send notification
    await sendSecurityAlert({
      tenant_id: tenantId,
      type: 'account_locked',
      identifier,
      message: 'Account locked due to multiple failed login attempts'
    });
  }

  private async blockIP(ip: string, duration: number): Promise<void> {
    await redis.setex(`ip_blocked:${ip}`, duration, '1');

    // Log for security monitoring
    await logSecurityEvent({
      event_type: 'ip_blocked',
      ip_address: ip,
      reason: 'excessive_failed_logins'
    });
  }
}
```

## Authorization Security

### OAuth 2.0 Security Best Practices

#### PKCE (Proof Key for Code Exchange)

Required for all public clients (SPAs, mobile apps):

```typescript
// Authorization request MUST include PKCE
interface AuthorizationRequest {
  response_type: 'code';
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge: string;        // Base64URL(SHA256(code_verifier))
  code_challenge_method: 'S256'; // REQUIRED
}

async function validateAuthorizationRequest(
  req: AuthorizationRequest,
  client: OAuthClient
): Promise<ValidationResult> {
  // Public clients MUST use PKCE
  if (client.client_type === 'public') {
    if (!req.code_challenge || !req.code_challenge_method) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'PKCE is required for public clients'
      };
    }

    if (req.code_challenge_method !== 'S256') {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'Only S256 code challenge method is supported'
      };
    }
  }

  // Validate code_challenge format
  if (req.code_challenge) {
    if (!/^[A-Za-z0-9_-]{43,128}$/.test(req.code_challenge)) {
      return {
        valid: false,
        error: 'invalid_request',
        error_description: 'Invalid code_challenge format'
      };
    }
  }

  return { valid: true };
}

// Token request MUST include code_verifier
async function exchangeCodeForToken(
  code: string,
  codeVerifier: string,
  clientId: string
): Promise<TokenResponse> {
  const authCode = await getAuthorizationCode(code);

  if (!authCode || authCode.used) {
    throw new OAuth2Error('invalid_grant', 'Invalid authorization code');
  }

  // Verify PKCE
  if (authCode.code_challenge) {
    const computedChallenge = base64UrlEncode(
      sha256(codeVerifier)
    );

    if (computedChallenge !== authCode.code_challenge) {
      throw new OAuth2Error('invalid_grant', 'Invalid code_verifier');
    }
  }

  // Mark code as used (single use only)
  await markCodeAsUsed(code);

  // Issue tokens
  return await issueTokens(authCode);
}
```

#### State Parameter (CSRF Protection)

```typescript
// Always validate state parameter
function generateAuthorizationUrl(config: {
  client_id: string;
  redirect_uri: string;
  scope: string;
}): string {
  // Generate cryptographically secure state
  const state = generateSecureToken(32);

  // Store state in session
  storeStateInSession(state);

  return `https://auth.example.com/authorize?` +
    `response_type=code&` +
    `client_id=${config.client_id}&` +
    `redirect_uri=${encodeURIComponent(config.redirect_uri)}&` +
    `scope=${encodeURIComponent(config.scope)}&` +
    `state=${state}`;
}

// Validate state in callback
async function handleCallback(req: Request): Promise<void> {
  const { code, state } = req.query;

  const expectedState = getStateFromSession();

  if (!state || state !== expectedState) {
    throw new Error('Invalid state parameter - possible CSRF attack');
  }

  // Clear state from session
  clearStateFromSession();

  // Exchange code for tokens
  const tokens = await exchangeCodeForTokens(code);
}
```

### Scope-Based Access Control

```typescript
interface Scope {
  name: string;
  description: string;
  sensitive: boolean; // Requires explicit consent
}

const AVAILABLE_SCOPES: Scope[] = [
  {
    name: 'openid',
    description: 'Required for OpenID Connect',
    sensitive: false
  },
  {
    name: 'profile',
    description: 'Access to basic profile information (name, picture)',
    sensitive: false
  },
  {
    name: 'email',
    description: 'Access to email address',
    sensitive: true
  },
  {
    name: 'phone',
    description: 'Access to phone number',
    sensitive: true
  },
  {
    name: 'admin',
    description: 'Administrative access to tenant resources',
    sensitive: true
  },
  {
    name: 'users:read',
    description: 'Read access to user directory',
    sensitive: true
  },
  {
    name: 'users:write',
    description: 'Modify users',
    sensitive: true
  }
];

async function validateScopes(
  requestedScopes: string[],
  client: OAuthClient,
  user: User
): Promise<string[]> {
  const allowedScopes: string[] = [];

  for (const scope of requestedScopes) {
    // Check if client is allowed to request this scope
    if (!client.allowed_scopes.includes(scope)) {
      continue; // Skip unauthorized scopes
    }

    // Check if user has permission for this scope
    if (!await userHasPermission(user, scope)) {
      continue;
    }

    allowedScopes.push(scope);
  }

  // openid is always required for OIDC
  if (requestedScopes.includes('openid') && !allowedScopes.includes('openid')) {
    throw new OAuth2Error(
      'invalid_scope',
      'User not authorized for OpenID Connect'
    );
  }

  return allowedScopes;
}

// Enforce scopes in token validation
function validateTokenScopes(token: DecodedToken, requiredScopes: string[]): boolean {
  const tokenScopes = token.scope?.split(' ') || [];

  return requiredScopes.every(scope => tokenScopes.includes(scope));
}

// Middleware for protected routes
function requireScopes(...requiredScopes: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const token = extractBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: 'unauthorized',
        error_description: 'No access token provided'
      });
    }

    const decoded = await validateToken(token);

    if (!validateTokenScopes(decoded, requiredScopes)) {
      return res.status(403).json({
        error: 'insufficient_scope',
        error_description: `Required scopes: ${requiredScopes.join(', ')}`,
        required_scopes: requiredScopes
      });
    }

    req.user = decoded;
    next();
  };
}

// Usage
app.get('/admin/users',
  requireScopes('admin', 'users:read'),
  async (req, res) => {
    // User has both 'admin' and 'users:read' scopes
  }
);
```

## Token Security

### Access Token Security

```typescript
interface AccessTokenClaims {
  // Standard claims
  iss: string;           // Issuer
  sub: string;           // Subject (user ID)
  aud: string | string[]; // Audience (client ID or resource server)
  exp: number;           // Expiration (Unix timestamp)
  nbf: number;           // Not Before
  iat: number;           // Issued At
  jti: string;           // JWT ID (unique identifier)

  // OAuth 2.0 claims
  scope: string;         // Space-separated scopes
  client_id: string;     // OAuth client ID

  // Custom claims
  tenant_id: string;
  email?: string;
  role?: string;
  [key: string]: any;    // Custom tenant claims
}

async function issueAccessToken(
  userId: string,
  tenantId: string,
  clientId: string,
  scope: string
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const ttl = 15 * 60; // 15 minutes

  const claims: AccessTokenClaims = {
    iss: `https://${tenantId}.auth.example.com`,
    sub: userId,
    aud: clientId,
    exp: now + ttl,
    nbf: now,
    iat: now,
    jti: generateJTI(),
    scope,
    client_id: clientId,
    tenant_id: tenantId
  };

  // Run claims pipeline
  const customClaims = await runClaimsPipeline(tenantId, userId);
  Object.assign(claims, customClaims);

  // Sign with tenant's private key
  const signingKey = await getSigningKey(tenantId);

  return await signJWT(claims, signingKey);
}

// Short TTL to limit exposure
const ACCESS_TOKEN_TTL = 15 * 60; // 15 minutes (recommended)

// For high-security applications
const SHORT_LIVED_TOKEN_TTL = 5 * 60; // 5 minutes
```

### Refresh Token Security

```typescript
async function issueRefreshToken(
  userId: string,
  tenantId: string,
  clientId: string,
  scope: string
): Promise<string> {
  const token = generateSecureToken(32);
  const tokenHash = await hashToken(token);

  const ttl = 30 * 24 * 60 * 60; // 30 days

  await pool.queryWithTenant(
    tenantId,
    `INSERT INTO refresh_tokens (
      tenant_id, token_hash, client_id, user_id, scope, expires_at
    ) VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '${ttl} seconds')`,
    [tenantId, tokenHash, clientId, userId, scope]
  );

  return token;
}

async function rotateRefreshToken(
  oldToken: string,
  tenantId: string
): Promise<{ access_token: string; refresh_token: string }> {
  const tokenHash = await hashToken(oldToken);

  // Find and revoke old token
  const result = await pool.queryWithTenant(
    tenantId,
    `UPDATE refresh_tokens
     SET revoked = true
     WHERE token_hash = $1 AND revoked = false AND expires_at > NOW()
     RETURNING user_id, client_id, scope`,
    [tokenHash]
  );

  if (!result[0]) {
    throw new OAuth2Error('invalid_grant', 'Invalid refresh token');
  }

  const { user_id, client_id, scope } = result[0];

  // Check for replay attack
  const reusedTokens = await pool.queryWithTenant(
    tenantId,
    `SELECT id FROM refresh_tokens
     WHERE token_hash = $1 AND revoked = true`,
    [tokenHash]
  );

  if (reusedTokens.length > 0) {
    // Refresh token reuse detected - revoke all tokens for this user
    await revokeAllUserTokens(tenantId, user_id);

    await logSecurityEvent({
      event_type: 'refresh_token_reuse_detected',
      tenant_id: tenantId,
      user_id,
      severity: 'critical'
    });

    throw new OAuth2Error(
      'invalid_grant',
      'Token reuse detected - all tokens revoked'
    );
  }

  // Issue new tokens
  const accessToken = await issueAccessToken(user_id, tenantId, client_id, scope);
  const refreshToken = await issueRefreshToken(user_id, tenantId, client_id, scope);

  return {
    access_token: accessToken,
    refresh_token: refreshToken
  };
}
```

### Token Revocation

```typescript
async function revokeToken(
  token: string,
  tokenTypeHint?: 'access_token' | 'refresh_token'
): Promise<void> {
  if (tokenTypeHint === 'refresh_token' || !tokenTypeHint) {
    // Try revoking as refresh token
    const tokenHash = await hashToken(token);

    await pool.query(
      `UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1`,
      [tokenHash]
    );
  }

  if (tokenTypeHint === 'access_token' || !tokenTypeHint) {
    // For access tokens (JWT), add to revocation list
    try {
      const decoded = decodeJWT(token);

      if (decoded.exp && decoded.exp > Date.now() / 1000) {
        // Only add to revocation list if not yet expired
        await pool.query(
          `INSERT INTO revoked_tokens (jti, tenant_id, expires_at)
           VALUES ($1, $2, to_timestamp($3))
           ON CONFLICT (jti) DO NOTHING`,
          [decoded.jti, decoded.tenant_id, decoded.exp]
        );

        // Cache in Redis for fast lookup
        await redis.setex(
          `revoked:${decoded.jti}`,
          decoded.exp - Math.floor(Date.now() / 1000),
          '1'
        );
      }
    } catch (error) {
      // Invalid JWT, ignore
    }
  }

  await logEvent({
    event_type: 'token.revoked',
    token_hint: tokenTypeHint
  });
}

// Periodic cleanup of expired revocation records
async function cleanupRevokedTokens(): Promise<void> {
  await pool.query(
    'DELETE FROM revoked_tokens WHERE expires_at < NOW()'
  );
}
```

### DPoP (Demonstrating Proof-of-Possession)

For enhanced token security, bind tokens to specific clients:

```typescript
// Future enhancement: DPoP support per RFC 9449
interface DPoPProof {
  typ: 'dpop+jwt';
  alg: 'ES256';
  jwk: JsonWebKey;
}

async function validateDPoP(
  req: Request,
  accessToken: string
): Promise<boolean> {
  const dpopProof = req.headers['dpop'] as string;

  if (!dpopProof) {
    return false;
  }

  // Verify DPoP proof JWT
  const proof = await verifyDPoPProof(dpopProof);

  // Check that access token is bound to this public key
  const tokenClaims = decodeJWT(accessToken);
  const thumbprint = await calculateJWKThumbprint(proof.jwk);

  return tokenClaims.cnf?.jkt === thumbprint;
}
```

## Cryptographic Standards

### Key Management

```typescript
interface KeyRotationPolicy {
  algorithm: 'RS256' | 'ES256';
  key_size: number;
  rotation_period_days: number;
  overlap_period_hours: number; // Keep old key valid during transition
}

const KEY_ROTATION_POLICY: KeyRotationPolicy = {
  algorithm: 'RS256',
  key_size: 2048,        // RSA 2048-bit minimum
  rotation_period_days: 90,
  overlap_period_hours: 24
};

async function rotateSigningKeys(tenantId: string): Promise<void> {
  // Generate new key pair
  const newKey = await generateKeyPair(KEY_ROTATION_POLICY);

  // Add new key as active
  await pool.queryWithTenant(
    tenantId,
    `INSERT INTO jwks (tenant_id, kid, key_type, algorithm, public_key, private_key, active)
     VALUES ($1, $2, $3, $4, $5, $6, true)`,
    [
      tenantId,
      newKey.kid,
      'RSA',
      'RS256',
      newKey.publicKey,
      encrypt(newKey.privateKey)
    ]
  );

  // Mark old keys for expiration (but keep them valid for overlap period)
  await pool.queryWithTenant(
    tenantId,
    `UPDATE jwks
     SET expires_at = NOW() + INTERVAL '${KEY_ROTATION_POLICY.overlap_period_hours} hours'
     WHERE tenant_id = $1 AND kid != $2 AND active = true`,
    [tenantId, newKey.kid]
  );

  // After overlap period, deactivate old keys
  setTimeout(async () => {
    await pool.queryWithTenant(
      tenantId,
      `UPDATE jwks SET active = false WHERE tenant_id = $1 AND kid != $2`,
      [tenantId, newKey.kid]
    );
  }, KEY_ROTATION_POLICY.overlap_period_hours * 60 * 60 * 1000);

  // Invalidate JWKS cache
  await redis.del(`jwks:${tenantId}`);
}

// Automated key rotation (scheduled job)
cron.schedule('0 0 * * *', async () => {
  const tenants = await getAllTenants();

  for (const tenant of tenants) {
    const oldestKey = await getOldestActiveKey(tenant.id);

    const keyAgeDays = daysSince(oldestKey.created_at);

    if (keyAgeDays >= KEY_ROTATION_POLICY.rotation_period_days) {
      await rotateSigningKeys(tenant.id);
      console.log(`Rotated keys for tenant ${tenant.id}`);
    }
  }
});
```

### Encryption at Rest

```typescript
import crypto from 'crypto';

const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY!; // 32-byte key from secure storage

function encrypt(plaintext: string): string {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    ENCRYPTION_ALGORITHM,
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv
  );

  let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
  ciphertext += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  // Return IV + AuthTag + Ciphertext (all hex-encoded)
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + ciphertext;
}

function decrypt(encrypted: string): string {
  const parts = encrypted.split(':');
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const ciphertext = parts[2];

  const decipher = crypto.createDecipheriv(
    ENCRYPTION_ALGORITHM,
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv
  );

  decipher.setAuthTag(authTag);

  let plaintext = decipher.update(ciphertext, 'hex', 'utf8');
  plaintext += decipher.final('utf8');

  return plaintext;
}

// What to encrypt:
// - Private keys (JWKS)
// - Client secrets
// - MFA secrets (TOTP)
// - Refresh tokens
// - API keys
// - Sensitive user data (if required by compliance)
```

## Rate Limiting & Abuse Prevention

See detailed implementation in [ARCHITECTURE.md](./ARCHITECTURE.md#rate-limiter).

Key points:
- Per-tenant rate limits
- Per-user rate limits
- Per-IP rate limits
- Endpoint-specific limits
- Brute force detection
- Account lockout policies

## Audit & Compliance

### Comprehensive Audit Logging

```typescript
interface AuditLog {
  id: string;
  tenant_id?: string;
  timestamp: Date;
  event_type: string;
  actor_id?: string;
  actor_type: 'user' | 'client' | 'system' | 'admin';
  resource_type?: string;
  resource_id?: string;
  action: string;
  result: 'success' | 'failure';
  ip_address?: string;
  user_agent?: string;
  metadata: Record<string, any>;
}

// Events to log
const AUDIT_EVENTS = [
  // Authentication
  'user.login.success',
  'user.login.failure',
  'user.logout',
  'user.password_reset',
  'user.mfa_enabled',
  'user.mfa_disabled',

  // Authorization
  'oauth.authorize.success',
  'oauth.authorize.failure',
  'oauth.token.issued',
  'oauth.token.refreshed',
  'oauth.token.revoked',

  // User management
  'user.created',
  'user.updated',
  'user.deleted',
  'user.suspended',

  // Tenant management
  'tenant.created',
  'tenant.updated',
  'tenant.deleted',
  'tenant.suspended',

  // Client management
  'client.created',
  'client.updated',
  'client.deleted',
  'client.secret_rotated',

  // Security events
  'account.locked',
  'ip.blocked',
  'suspicious_activity.detected',
  'token_reuse.detected',

  // Configuration changes
  'config.updated',
  'keys.rotated',
  'federation.configured'
];

async function logAuditEvent(event: Partial<AuditLog>): Promise<void> {
  // Log to database
  await pool.query(
    `INSERT INTO audit_logs (
      tenant_id, event_type, actor_id, actor_type,
      resource_type, resource_id, ip_address, user_agent, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [
      event.tenant_id,
      event.event_type,
      event.actor_id,
      event.actor_type,
      event.resource_type,
      event.resource_id,
      event.ip_address,
      event.user_agent,
      JSON.stringify(event.metadata || {})
    ]
  );

  // Also stream to external SIEM if configured
  await streamToSIEM(event);
}
```

### Data Retention

```sql
-- Partition audit logs by month for efficient retention management
CREATE TABLE audit_logs_2025_01 PARTITION OF audit_logs
  FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

-- Automated retention policy (keep 2 years, then archive)
CREATE OR REPLACE FUNCTION archive_old_audit_logs()
RETURNS void AS $$
BEGIN
  -- Move logs older than 2 years to archive table
  INSERT INTO audit_logs_archive
  SELECT * FROM audit_logs
  WHERE created_at < NOW() - INTERVAL '2 years';

  -- Delete from main table
  DELETE FROM audit_logs
  WHERE created_at < NOW() - INTERVAL '2 years';
END;
$$ LANGUAGE plpgsql;
```

## Threat Model

See [ARCHITECTURE.md](./ARCHITECTURE.md#threat-modeling) for comprehensive threat analysis.

## Security Checklist

**Pre-Production**:
- [ ] Enable TLS 1.3 only
- [ ] Configure HSTS headers
- [ ] Enable CSRF protection
- [ ] Implement CSP headers
- [ ] Enable rate limiting
- [ ] Configure WAF rules
- [ ] Set up DDoS protection
- [ ] Enable audit logging
- [ ] Rotate default keys
- [ ] Review password policies
- [ ] Test MFA enrollment
- [ ] Verify PKCE enforcement
- [ ] Test token revocation
- [ ] Configure session timeouts
- [ ] Set up monitoring alerts
- [ ] Perform penetration testing
- [ ] Security code review

**Ongoing**:
- [ ] Monitor security logs daily
- [ ] Rotate keys every 90 days
- [ ] Review access controls monthly
- [ ] Update dependencies weekly
- [ ] Conduct security audits quarterly
- [ ] Test disaster recovery annually

## Next Steps

- [API Reference](./API_REFERENCE.md)
- [Deployment Guide](./DEPLOYMENT.md)
- [Performance Tuning](./PERFORMANCE.md)
