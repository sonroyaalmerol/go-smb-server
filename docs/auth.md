# Authentication

Authentication is the primary pluggable boundary. Implement `auth.Authenticator`
to integrate with any credential store.

## Interface

```go
type Identity struct {
    Username string
    Domain   string
    SID      string
    Groups   []string
}

type AcceptResult struct {
    OutputToken []byte
    Identity    *Identity  // nil until authentication completes
    SessionKey  []byte     // 16-byte NTLM session key
}

type Authenticator interface {
    Accept(ctx context.Context, input []byte) (AcceptResult, error)
}

type Factory func() Authenticator
```

The server calls `Factory()` once per connection to create a fresh
`Authenticator`. `Accept` is called for each SESSION_SETUP request:

- **First call**: client sends SPNEGO NegTokenInit with NTLMSSP NEGOTIATE.
  Return a NegTokenResp with the NTLMSSP CHALLENGE.
- **Second call**: client sends NTLMSSP AUTHENTICATE. Validate credentials,
  return identity + session key.

A non-nil `Identity` signals authentication complete. Nil with no error means
the handshake continues (`STATUS_MORE_PROCESSING_REQUIRED`).

## Built-in NTLMSSP

```go
creds := ntlmssp.NewMemoryCredentials()
creds.Add("WORKGROUP", "alice", "password123")

server.WithAuth(ntlmssp.NewServer(creds, "MYSERVER"))
```

`ntlmssp.CredentialLookup` interface for custom stores:

```go
type CredentialLookup interface {
    LookupNTOWFv2(ctx context.Context, domain, user string) ([]byte, error)
}
```

## Relay authentication (no plaintext password)

When the identity provider doesn't expose plaintext passwords or NT hashes —
for example Authentik LDAP outposts — use `auth.NewRelayAuthenticator` to
forward the SPNEGO/NTLMSSP exchange to an external service.

NTLMv2 is a challenge-response protocol: validating requires the NT hash. If
your store can't provide it, validation must be delegated.

```go
relayFactory := func() auth.RelayFunc {
    upstream := ntlmssp.NewServer(creds, "FILESRV")()
    return func(_ context.Context, spnegoToken []byte) ([]byte, []byte, *auth.Identity, error) {
        result, err := upstream.Accept(context.Background(), spnegoToken)
        if err != nil {
            return nil, nil, nil, err
        }
        if result.Identity == nil {
            return result.OutputToken, nil, nil, nil
        }
        return result.OutputToken, result.SessionKey, result.Identity, nil
    }
}

server.WithAuth(auth.NewRelayAuthenticator(relayFactory))
```

`RelayFactory` creates a fresh `RelayFunc` per connection so multi-round NTLM
state is tracked via closures.

## Guest access

```go
server.WithAuth(auth.AlwaysAllowFactory())
```

Accepts any SESSION_SETUP, assigns a `guest` identity, no session key. Signing
and encryption unavailable. Note: smbclient requires valid SPNEGO tokens, so
use NTLMSSP with a guest account instead for real client compatibility.

## Custom authenticator

Implement `Authenticator` directly for non-NTLM protocols. Return
`auth.ErrLogonFailed` to trigger `STATUS_LOGON_FAILURE`.
