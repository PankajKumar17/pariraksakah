# Access Control Service

Zero Trust Authentication & Post-Quantum Cryptography service for CyberShield-X.

## Features
- OIDC/OAuth2 identity provider with PKCE
- FIDO2/WebAuthn passwordless auth
- Post-Quantum Cryptography (CRYSTALS-Kyber-1024 + Dilithium3)
- OPA-based Zero Trust policy engine
- Just-in-Time privilege provisioning
- Ed25519 JWT signing via SoftHSM2

## Run locally
```bash
go run ./cmd/main.go
```
