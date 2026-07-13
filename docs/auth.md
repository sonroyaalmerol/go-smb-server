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
