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
    SessionKey  []byte     // GSS session key (16-byte NTLM, or Kerberos key)
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

## Built-in Kerberos v5

For domain (Active Directory / MIT) authentication use `smb/kerberos`, a
GSS-SPNEGO acceptor backed by [gokrb5](https://github.com/jcmturner/gokrb5).
It validates the client's Kerberos AP-REQ against a service keytab and exports
the GSS session key, which SMB3 signing and encryption derive from through
the standard MS-SMB2 KDF. No SMB-specific crypto lives in the package.

```go
kt, err := keytab.Load("/etc/krb5.keytab")
if err != nil { /* ... */ }

server.WithAuth(kerberos.NewServer(kt))
```

The keytab must hold the service principal's long-term key: the entry the
KDC issued a service ticket for, typically `cifs/<host>@REALM`. By default the
principal is taken from the ticket itself; override it with an option:

```go
kerberos.NewServer(kt,
    kerberos.WithKeytabPrincipal("cifs/fileserver.example.com"),
    kerberos.WithMaxClockSkew(5*time.Minute),
    kerberos.WithoutPAC(),          // skip PAC decode / group SID extraction
    kerberos.WithLogger(logger),
)
```

**Session key selection (RFC 4121 §2):** the exported key is the
initiator-asserted authenticator subkey when present, otherwise the
service-ticket session key. SMB does not negotiate Kerberos mutual auth, so
no AP-REP is produced and authentication completes in a single round trip
(NegTokenInit in, NegTokenResp accept-completed out). On success the resulting
`auth.Identity` carries the client's user and realm, plus group membership SIDs
when the ticket carries a decodable (AD-style) PAC.

**PAC handling:** the accept/reject decision never depends on the PAC. PAC
decoding is best-effort attribute extraction, so a ticket that carries a PAC
which gokrb5 cannot fully decode (notably MIT-KDC PACs that omit the
AD-specific KerbValidationInfo buffer) still authenticates successfully; it
simply yields no group SIDs. This was verified end-to-end against a real MIT
`krb5kdc`.

**Single mechanism per server:** `WithAuth` takes one factory, so a server is
configured for either NTLMSSP or Kerberos, not both. A client must then offer
the matching mechanism in its SPNEGO mech list.

### Authenticating against an existing Samba / Active Directory domain

There is no Kerberos equivalent of the NTLM relay authenticator, and there
cannot be: a Kerberos service ticket is encrypted for one service principal's
long-term key, and the SMB session key lives inside it. Only the holder of that
key can recover it, so a client's token can't be forwarded to a separate Samba
server and validated there. That binding is exactly how Kerberos defeats relay
attacks.

The idiomatic path is to **share the service key**: export the `cifs/`
principal from the domain into a keytab and load it here. This server then
validates client tickets directly against the same KDC, with full SMB3 signing
and encryption, no Samba process required at runtime.

```sh
# On a Samba AD DC (as domain admin):
samba-tool domain exportkeytab /etc/krb5.smb.keytab \
  --principal=cifs/fs.corp.example.com
# Or on a domain-joined member:
net ads keytab add cifs/fs.corp.example.com -U admin
```

```go
kt, err := keytab.Load("/etc/krb5.smb.keytab")
if err != nil { /* ... */ }
server.WithAuth(kerberos.NewServer(kt))
```

Clients must request a ticket for the same principal. See
`examples/samba-kerberos-auth` for a runnable end-to-end sample, including the
`--spn` (explicit keytab lookup) and `--no-pac` (MIT/non-AD KDC) flags.

## Relay authentication (no plaintext password)

When the identity provider doesn't expose plaintext passwords or NT hashes
(for example, Authentik LDAP outposts), use `auth.NewRelayAuthenticator` to
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
