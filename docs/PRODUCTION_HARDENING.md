# Production Hardening Guide

Security considerations for deploying WICAP in production environments.

## SQL Server Configuration

| Setting | Development | Production |
|---------|-------------|------------|
| `TrustServerCertificate` | `yes` | `no` (require valid cert) |
| `Encrypt` | `yes` | `yes` |
| Connection Timeout | 30s | 15s |

### Required Environment Variables

```bash
# Database (required)
WICAP_SQL_PASSWORD=<min 12 chars>
WICAP_SQL_HOST=<host>,<port>
WICAP_SQL_DATABASE=WifiInsanityDB
WICAP_SQL_USER=<username>

# Security (required in production)
WICAP_SQL_TRUST_CERT=no
WICAP_INTERNAL_SECRET=<secret for UI↔Core auth>
WICAP_INTERNAL_SECRET_REQUIRED=true
```

## Internal API Security

The internal API (`/internal/*`) is protected by:

1. **IP Allowlist:** `WICAP_INTERNAL_ALLOWLIST` (default: `127.0.0.1,::1`)
2. **Shared Secret:** `WICAP_INTERNAL_SECRET` header validation

### Multi-Node Deployments

For distributed deployments, consider:

| Approach | Use Case |
|----------|----------|
| IP Allowlist | Single-host or trusted VPC |
| mTLS | Zero-trust networks |
| Secret Manager | Dynamic secret rotation |

Example with HashiCorp Vault:
```bash
export WICAP_SQL_PASSWORD=$(vault kv get -field=password wicap/sql)
export WICAP_INTERNAL_SECRET=$(vault kv get -field=secret wicap/internal)
```

## Redis Configuration

For Redis-backed queues in production:

```bash
WICAP_REDIS_URL=rediss://:password@host:6379/0  # TLS enabled
```

## Logging

Enable structured JSON logging for log aggregation:

```bash
WICAP_LOG_FORMAT=json
WICAP_LOG_LEVEL=INFO
```

## Checklist

- [ ] SQL password is 12+ characters
- [ ] `TrustServerCertificate=no`
- [ ] Internal secret is set and required
- [ ] IP allowlist is configured
- [ ] Redis uses TLS (`rediss://`)
- [ ] Firewall rules restrict SQL/Redis ports
