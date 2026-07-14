package kerberos

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	goforkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/sonroyaalmerol/go-smb-server/smb/auth"
)

type Option func(*config)

type config struct {
	settings []func(*service.Settings)
	noPAC    bool
}

func WithMaxClockSkew(d time.Duration) Option {
	return func(c *config) { c.settings = append(c.settings, service.MaxClockSkew(d)) }
}

func WithKeytabPrincipal(spn string) Option {
	return func(c *config) { c.settings = append(c.settings, service.KeytabPrincipal(spn)) }
}

func WithLogger(l *log.Logger) Option {
	return func(c *config) { c.settings = append(c.settings, service.Logger(l)) }
}

func WithoutPAC() Option {
	return func(c *config) { c.noPAC = true }
}

func NewServer(kt *keytab.Keytab, opts ...Option) auth.Factory {
	cfg := &config{}
	for _, o := range opts {
		o(cfg)
	}
	return func() auth.Authenticator {
		return &Authenticator{keytab: kt, opts: cfg.settings, wantPAC: !cfg.noPAC}
	}
}

type Authenticator struct {
	keytab  *keytab.Keytab
	opts    []func(*service.Settings)
	wantPAC bool
	done    bool
}

func (a *Authenticator) verifySettings() *service.Settings {
	opts := make([]func(*service.Settings), 0, len(a.opts)+1)
	opts = append(opts, a.opts...)
	opts = append(opts, service.DecodePAC(false))
	return service.NewSettings(a.keytab, opts...)
}

func (a *Authenticator) Accept(_ context.Context, token []byte) (auth.AcceptResult, error) {
	if a.done {
		return auth.AcceptResult{}, errors.New("kerberos: security context already established")
	}
	if a.keytab == nil {
		return auth.AcceptResult{}, fmt.Errorf("kerberos: no service keytab configured")
	}
	settings := a.verifySettings()

	mech, err := extractMechToken(token)
	if err != nil {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	var mt spnego.KRB5Token
	if err := mt.Unmarshal(mech); err != nil {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}
	if !mt.IsAPReq() {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	ok, creds, err := service.VerifyAPREQ(&mt.APReq, settings)
	if err != nil || !ok {
		return auth.AcceptResult{}, auth.ErrLogonFailed
	}

	key := mt.APReq.Ticket.DecryptedEncPart.Key
	if sub := mt.APReq.Authenticator.SubKey; len(sub.KeyValue) > 0 {
		key = sub
	}

	ident := &auth.Identity{
		Username: creds.UserName(),
		Domain:   creds.Domain(),
	}
	if groups := extractGroups(&mt.APReq, settings, a.wantPAC); len(groups) > 0 {
		ident.Groups = groups
	}

	out, err := acceptCompletedToken()
	if err != nil {
		return auth.AcceptResult{}, fmt.Errorf("kerberos: marshal response token: %w", err)
	}

	a.done = true
	return auth.AcceptResult{
		OutputToken: out,
		Identity:    ident,
		SessionKey:  append([]byte(nil), key.KeyValue...),
	}, nil
}

func extractMechToken(token []byte) ([]byte, error) {
	if len(token) == 0 {
		return nil, errors.New("kerberos: empty security buffer")
	}
	var st spnego.SPNEGOToken
	if err := st.Unmarshal(token); err == nil {
		if st.Init && len(st.NegTokenInit.MechTokenBytes) > 0 {
			return st.NegTokenInit.MechTokenBytes, nil
		}
		if st.Resp && len(st.NegTokenResp.ResponseToken) > 0 {
			return st.NegTokenResp.ResponseToken, nil
		}
		return nil, errors.New("kerberos: SPNEGO token carries no mechanism token")
	}
	var mt spnego.KRB5Token
	if err := mt.Unmarshal(token); err != nil {
		return nil, errors.New("kerberos: token is neither SPNEGO nor KRB5")
	}
	return token, nil
}

func acceptCompletedToken() ([]byte, error) {
	resp := spnego.NegTokenResp{
		NegState:      goforkasn1.Enumerated(spnego.NegStateAcceptCompleted),
		SupportedMech: gssapi.OIDKRB5.OID(),
	}
	return resp.Marshal()
}

func extractGroups(apreq *messages.APReq, settings *service.Settings, wantPAC bool) []string {
	if !wantPAC || settings.Keytab == nil {
		return nil
	}
	isPAC, pac, err := apreq.Ticket.GetPACType(settings.Keytab, settings.KeytabPrincipal(), settings.Logger())
	if !isPAC || err != nil {
		return nil
	}
	if sids := pac.KerbValidationInfo.GetGroupMembershipSIDs(); len(sids) > 0 {
		return append([]string(nil), sids...)
	}
	return nil
}
