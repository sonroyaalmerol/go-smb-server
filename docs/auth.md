# Authentication

Authentication is the primary pluggable boundary. Implement `auth.Authenticator` to integrate with any credential store: LDAP, database, OAuth, PAM.

## Interface

```go
// smb/auth/auth.go

type Identity struct {
    Username string
    Domain   string
    SID      string
    Groups   []string
}

type AcceptResult struct {
    OutputToken []byte   // GSS-API token for the client
    Identity    *Identity // nil until authentication completes
    SessionKey  []byte   // 16-byte NTLM session key for signing/encryption
}

type Authenticator interface {
    Accept(ctx context.Context, input []byte) (AcceptResult, error)
}

type Factory func() Authenticator
```

The server calls `Factory()` once per connection to create a fresh `Authenticator` instance. The `Accept` method is called for each SESSION_SETUP request:

- **First call**: The client sends a SPNEGO `NegTokenInit` containing an NTLMSSP NEGOTIATE message. Return a SPNEGO `NegTokenResp` with the NTLMSSP CHALLENGE.
- **Second call**: The client sends a SPNEGO `NegTokenResp` containing the NTLMSSP AUTHENTICATE message. Verify the credentials and return the final identity with the session key.

A non-nil `Identity` in the result signals that authentication is complete. A nil `Identity` with no error means the handshake continues (`STATUS_MORE_PROCESSING_REQUIRED`).

## Built-in NTLMSSP provider

The `smb/ntlmssp` package provides a complete NTLMv2 server implementation.

### Memory-backed credentials

```go
import "github.com/sonroyaalmerol/go-smb-server/smb/ntlmssp"

creds := ntlmssp.NewMemoryCredentials()
creds.Add("WORKGROUP", "alice", "password123")
creds.AddKey("WORKGROUP", "bob", precomputedNTOWFv2Hash)

srv, _ := server.New(
    server.WithAuth(ntlmssp.NewServer(creds, "MYSERVER")),
)
```

`Add(domain, user, password)` stores the cleartext password and computes `NTOWFv2` on lookup. `AddKey(domain, user, key)` stores a pre-computed key directly.

### LDAP-backed credentials

Implement `ntlmssp.CredentialLookup` to fetch credentials from any store:

```go
type CredentialLookup interface {
    LookupNTOWFv2(ctx context.Context, domain, user string) ([]byte, error)
}
```

Example LDAP adapter:

```go
type LDAPLookup struct {
    conn *ldap.Conn
}

func (l *LDAPLookup) LookupNTOWFv2(ctx context.Context, domain, user string) ([]byte, error) {
    // Bind and search LDAP for the user's sambaNTPassword or userPassword attribute
    // Return the 16-byte NTOWFv2 hash (MD4 of UTF-16LE password)
    // Per MS-NLMP, NTLMv2 requires MD4 — this deprecation is unavoidable.
}
```

### NTLM protocol details

- **NTLMv2 only**: NTLMv1 is intentionally not supported.
- **Key exchange**: When the client sends `NTLMSSP_NEGOTIATE_KEY_EXCH`, the server RC4-decrypts the encrypted session key using the session base key. The decrypted key is used for SMB2 signing and encryption key derivation.
- **Target info**: The server includes `MsvAvNbComputerName` and `MsvAvEOL` AV pairs in the challenge so clients can build conformant NTLMv2 responses.
- **SPNEGO**: Tokens are wrapped as `NegTokenInit` / `NegTokenResp` per MS-SPNG. Both `[APPLICATION 0]` GSS `InitialContextToken` and bare `[1]` NegTokenResp formats are accepted on input.

## Guest / anonymous access

Use `AlwaysAllowAuthenticator` for open shares:

```go
server.WithAuth(auth.AlwaysAllowFactory())
```

This accepts any SESSION_SETUP and assigns a `guest` identity with no session key. Signing and encryption are unavailable.

## Custom authenticator

Implement `Authenticator` directly for non-NTLM protocols:

```go
type MyAuthenticator struct {
    stage int
}

func (a *MyAuthenticator) Accept(ctx context.Context, token []byte) (auth.AcceptResult, error) {
    // Parse token, validate credentials
    // Return Identity + SessionKey on success
    // Return empty Identity on continue
    // Return ErrLogonFailed on failure
}
```

Return `auth.ErrLogonFailed` to trigger `STATUS_LOGON_FAILURE` — the client will see an authentication error. Any other error returns `STATUS_ACCESS_DENIED`.

## Relay authentication (no plaintext password)

When the identity provider doesn't expose plaintext passwords or NT hashes — for example Authentik LDAP outposts, OAuth providers, or hosted directories — use `auth.NewRelayAuthenticator` to forward the SPNEGO/NTLMSSP exchange to an external validation service.

NTLMv2 is a challenge-response protocol: the server generates a random challenge and the client proves it knows the password by computing a response. Validating that response requires the NT hash (`MD4(UTF-16LE(password))`). If your identity store can't provide it, validation must be delegated to a service that can.

### How relay auth works

1. The SMB client sends a SPNEGO token containing the NTLMSSP NEGOTIATE.
2. The `RelayAuthenticator` forwards it to the external service.
3. The external service returns a CHALLENGE token.
4. The challenge is sent to the client.
5. The client sends the AUTHENTICATE token.
6. The relay forwards it to the external service.
7. The external service validates the response and returns the session key.
8. The SMB server uses the session key for signing and encryption.

### Usage

```go
relay := func(ctx context.Context, spnegoToken []byte) ([]byte, []byte, *auth.Identity, error) {
    // Forward spnegoToken to your identity provider.
    // Return: response token, session key (16 bytes), identity, error.
    // On intermediate exchanges: return response token, nil key, nil identity.
    // On final exchange: return all three.
    // On failure: return auth.ErrLogonFailed.
    return respToken, sessionKey, &auth.Identity{Username: user}, nil
}

server.WithAuth(auth.NewRelayAuthenticator(relay))
```

### External service options

| Service | How to relay |
|---------|-------------|
| **Active Directory** | LDAP SASL GSS-SPNEGO bind (go-ldap `BindSASL`) |
| **Another SMB server** | Forward raw SMB2 SESSION_SETUP tokens |
| **Custom HTTP API** | POST base64-encoded tokens, receive JSON response |
| **Authentik / OAuth** | Requires a bridge service that can complete the NTLM exchange |

### Why Authentik LDAP outposts need a bridge

Authentik LDAP outposts validate passwords via LDAP simple bind, but don't store NT hashes. NTLMv2 validation requires the NT hash to verify the challenge-response. Since the LDAP outpost can't provide it, a bridge service must either:

1. Have access to the plaintext password at bind time to compute the NT hash
2. Relay the NTLM exchange to Active Directory
3. Store NT hashes alongside Authentik's password store

Option 1 is typically not available. Option 2 requires AD. Option 3 requires a custom Authentik outpost that writes `sambaNTPassword` on user creation/update.

If your identity provider can store NT hashes (even computed from the password at provisioning time), use the standard `ntlmssp.CredentialLookup` interface instead of relay — it's simpler and doesn't require a relay service.
