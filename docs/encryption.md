# Encryption & Signing

SMB3 provides message signing and encryption for integrity and confidentiality.

## Signing

The library implements SMB3 **AES-128-CMAC** signing, the algorithm mandated
for dialects 3.0 and above. (The SMB 2.0.2/2.1 HMAC-SHA256 signing path is not
implemented — signing is keyed and computed the SMB3 way regardless of the
negotiated dialect, so use 3.0+ when you need integrity.)

| Dialect | Protocol algorithm | Implemented |
|---------|--------------------|-------------|
| 2.0.2, 2.1 | HMAC-SHA256 | — |
| 3.0, 3.0.2, 3.1.1 | AES-128-CMAC | ✅ SP800-108 KDF from session key |

### Signer type (cached, per-session)

```go
import "github.com/sonroyaalmerol/go-smb-server/smb/signing"

signer, err := signing.NewSigner(signing.DeriveSigningKey(sessionKey))
signer.Sign(msg)   // in-place, 4 allocs
signer.Verify(msg) // in-place
```

`NewSigner(key)` takes the 16-byte signing key directly. The `Signer` caches
the AES block cipher and CMAC subkeys at construction, so the per-message
hot path allocates nothing beyond the HMAC computation. The server holds one
`*Signer` per session and uses it for both inbound verification and outbound
signing.

### Key derivation

```
SigningKey = HMAC-SHA256(sessionKey,
    0x00000001 || "SMB2AESCMAC\0" || 0x00 || "SmbSign\0" || 0x00000080
)[:16]
```

## Encryption

SMB 3.x AES-128-CCM. When enabled, entire SMB2 messages are encrypted in a
`TRANSFORM_HEADER`.

### Enabling encryption

```go
server.WithEncryptionRequired()
```

### Key derivation (per direction)

```
EncryptionKey (server→client) = KDF(sessionKey, "SMB2AESCCM\0", "ServerOut\0")
DecryptionKey (client→server) = KDF(sessionKey, "SMB2AESCCM\0", "ServerIn \0")
```

### CCM implementation

From-scratch AES-128-CCM, validated against RFC 3610 test vectors. In-place
encryption/decryption with stack-allocated CTR blocks. The `AESCCM` struct is
cached per session via `encCCM`/`decCCM` fields.

| Operation | Throughput | Allocs |
|-----------|-----------|--------|
| Seal (4KB) | 203 MB/s | 8 |
| Open (4KB) | 235 MB/s | 7 |

### Encrypted messages are not signed

Per MS-SMB2 §3.3.4.1.1, encrypted messages MUST NOT be signed. SESSION_SETUP
responses (never encrypted) are still signed.
