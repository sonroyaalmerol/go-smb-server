# Encryption & Signing

SMB3 provides message signing and encryption for integrity and confidentiality.

## Signing

| Dialect | Algorithm | Key derivation |
|---------|-----------|---------------|
| 2.0.2, 2.1 | HMAC-SHA256 | Raw NTLM session key |
| 3.0, 3.0.2, 3.1.1 | AES-128-CMAC | SP800-108 KDF from session key |

### Signer type (cached cipher)

```go
import "github.com/sonroyaalmerol/go-smb-server/smb/signing"

signer, _ := signing.NewSigner(key, signing.AlgoAESCMAC)
signer.Sign(msg)   // in-place, 4 allocs
signer.Verify(msg) // in-place, 4 allocs
```

The `Signer` caches the AES block cipher and CMAC subkeys. Create one per
session. The legacy `Sign`/`Verify` package-level functions still work but
allocate more (they create a cipher per call).

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
