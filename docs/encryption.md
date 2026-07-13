# Encryption & Signing

SMB3 provides message signing and encryption to protect the integrity and confidentiality of data in transit.

## Signing

All SMB2/3 messages (after SESSION_SETUP) can be signed. The signing algorithm is negotiated per dialect:

| Dialect | Algorithm | Key derivation |
|---------|-----------|---------------|
| 2.0.2, 2.1 | HMAC-SHA256 | Raw NTLM session key |
| 3.0, 3.0.2, 3.1.1 | AES-128-CMAC | SP800-108 KDF(Counters) from session key |

### How signing works

1. The NTLM session key is established during authentication.
2. For SMB 3.x, the signing key is derived via SP800-108 KDF in Counter Mode:
   ```
   SigningKey = HMAC-SHA256(sessionKey,
       Counter(0x00000001) || Label("SMB2AESCMAC\0") || Separator(0x00) ||
       Context("SmbSign\0") || OutputLength(0x00000080)
   )[:16]
   ```
3. Each response is signed by computing the CMAC over the entire SMB2 message with the signature field zeroed, then writing the result into the field.
4. Each request is verified by re-computing the CMAC and comparing with the signature field.
5. Signed messages set `SMB2_FLAGS_SIGNED` in the header.

### API

```go
import "github.com/sonroyaalmerol/go-smb-server/smb/signing"

key := signing.DeriveSigningKey(sessionKey)
err := signing.Sign(msg, key, signing.AlgoAESCMAC)
ok, err := signing.Verify(msg, key, signing.AlgoAESCMAC)
```

## Encryption

SMB 3.x supports AES-128-CCM message encryption. When enabled, entire SMB2 messages are encrypted and wrapped in a `SMB2 TRANSFORM_HEADER`.

### How encryption works

1. During SESSION_SETUP, the server sets `SessionFlagEncryptData` and derives two keys from the NTLM session key:
   ```
   EncryptionKey (server→client) = KDF(sessionKey, "SMB2AESCCM\0", "ServerOut\0")
   DecryptionKey (client→server) = KDF(sessionKey, "SMB2AESCCM\0", "ServerIn \0")
   ```
2. Outgoing messages are sealed:
   - A random 11-byte nonce is generated
   - A 52-byte TRANSFORM_HEADER is constructed (ProtocolId + Nonce + OriginalMessageSize + SessionId)
   - AES-128-CCM encrypts the SMB2 message with the header (excluding signature) as AAD
   - The 16-byte CCM tag is placed in the header's Signature field
   - The sealed frame = TRANSFORM_HEADER + ciphertext
3. Incoming messages are opened:
   - The TRANSFORM_HEADER is parsed
   - AES-128-CCM decrypts the ciphertext
   - The CCM tag is verified (tamper detection)
   - The inner SMB2 message is extracted
4. Encryption provides both confidentiality and integrity — encrypted messages do not need additional signing.

### Enabling encryption

```go
srv, _ := server.New(
    server.WithEncryptionRequired(),
    // ... other options
)
```

With `WithEncryptionRequired()`:
- The negotiate response advertises `CapEncryption` and includes an `SMB2_ENCRYPTION_CAPABILITIES` context (CipherId: AES-128-CCM).
- The SESSION_SETUP response sets `SessionFlagEncryptData`.
- All subsequent traffic is encrypted.
- Plaintext messages on encrypted sessions are dropped.

### CCM implementation

The AES-128-CCM implementation is from-scratch, validated against RFC 3610 test vectors:

- **CBC-MAC** for authentication tag
- **CTR mode** for data encryption
- **B0 flags** encode tag size M-field per RFC 3610 §2.2
- **11-byte nonce** per MS-SMB2 §2.2.41
- **AAD** = TRANSFORM_HEADER bytes [20:52] (Nonce + OriginalMessageSize + Reserved + EncryptionAlgorithm + SessionId)

### API

```go
import "github.com/sonroyaalmerol/go-smb-server/smb/encryption"

// Derive keys
encKey := encryption.DeriveServerEncryptionKey(sessionKey)
decKey := encryption.DeriveServerDecryptionKey(sessionKey)

// Seal a message
ccm, _ := encryption.NewAESCCM(encKey)
sealed, _ := ccm.Seal(msg, sessionID)

// Open a message
ccm, _ := encryption.NewAESCCM(decKey)
msg, err := ccm.Open(transformFrame)
```

## Key derivation

All SMB3 keys derive from the NTLM session key via the same SP800-108 KDF (Counter Mode, HMAC-SHA256):

```
K_i = HMAC-SHA256(KI, i || Label || 0x00 || Context || L)
```

Where `i` is a 32-bit big-endian counter (0x00000001), `L` is the output length in bits (0x00000080 for 128-bit keys), and the result is truncated to L/8 bytes.

| Key | Label | Context |
|-----|-------|---------|
| Signing | `SMB2AESCMAC\0` | `SmbSign\0` |
| Encryption (server) | `SMB2AESCCM\0` | `ServerOut\0` |
| Decryption (server) | `SMB2AESCCM\0` | `ServerIn \0` |

Note: `ServerIn` has a trailing space before the null terminator.
