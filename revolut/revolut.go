package revolut

import (
	"context"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
	"golang.org/x/oauth2/internal"
	"golang.org/x/oauth2/jws"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

var endpoint = map[bool]oauth2.Endpoint{
	false: endpoints.Revolut,
	true:  endpoints.RevolutSanbox,
}

func getToken(ctx context.Context, clientID string, v url.Values, sandbox bool) (*oauth2.Token, error) {
	ep := endpoint[sandbox]

	ep.AuthStyle = oauth2.AuthStylePrivateKeyJWT

	tk, err := internal.RetrieveToken(ctx, clientID, "", ep.TokenURL, v, internal.AuthStyle(ep.AuthStyle))
	if err != nil {
		if rErr, ok := err.(*internal.RetrieveError); ok {
			return nil, (*oauth2.RetrieveError)(rErr)
		}
		return nil, err
	}

	t := &oauth2.Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
	}

	return t.WithExtra(tk.Raw), nil
}

type tokenSource struct {
	ctx          context.Context
	conf         *Config
	refreshToken string
}

func (c *tokenSource) Token() (*oauth2.Token, error) {
	v, err := c.conf.urlValues("refresh_token", c.refreshToken)
	if err != nil {
		return nil, err
	}

	token, err := getToken(c.ctx, c.conf.ClientID, v, c.conf.Sandbox)
	if err != nil {
		return nil, err
	}

	return token, nil
}

type Config struct {
	// ClientID is the application's ID.
	ClientID string

	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL string

	// JWTTokenExpirationDuration optionally specifies how long the jwt token is valid for.
	// Default value is 40 minutes.
	JWTTokenExpirationDuration time.Duration

	// PrivateKey contains the contents of an RSA private key or the
	// contents of a PEM file that contains a private key. The provided
	// private key is used to sign JWT payloads.
	// PEM containers with a passphrase are not supported.
	// Use the following command to convert a PKCS 12 file into a PEM.
	//
	//    $ openssl pkcs12 -in key.p12 -out key.pem -nodes
	//
	PrivateKey []byte

	// Sandbox indicates whether or not to use the Revolut sandbox environment.
	Sandbox bool
}

// TokenSource returns a TokenSource that returns t until t expires,
// automatically refreshing it as necessary using the provided context and the
// client ID and client secret.
//
// Most users will use Config.Client instead.
func (c *Config) TokenSource(ctx context.Context, t *oauth2.Token) oauth2.TokenSource {
	source := &tokenSource{
		ctx:          ctx,
		conf:         c,
		refreshToken: t.RefreshToken,
	}

	return oauth2.ReuseTokenSource(nil, source)
}

func (c *Config) urlValues(grantType, grantValue string) (url.Values, error) {
	grantTypeKey := grantType
	if grantType == "authorization_code" {
		grantTypeKey = "code"
	}

	v := url.Values{
		"grant_type":            {grantType},
		grantTypeKey:            {grantValue},
		"client_id":             {c.ClientID},
		"client_assertion_type": {clientAssertionType},
	}

	redirectURL, err := url.Parse(c.RedirectURL)
	if err != nil {
		return nil, err
	}

	pk, err := internal.ParseKey(c.PrivateKey)
	if err != nil {
		return nil, err
	}

	exp := time.Now().Add(4 * time.Minute).Unix()
	if c.JWTTokenExpirationDuration > 0 {
		exp = time.Now().Add(c.JWTTokenExpirationDuration).Unix()
	}

	claimSet := &jws.ClaimSet{
		Iss: redirectURL.Hostname(),
		Sub: c.ClientID,
		Aud: "https://revolut.com",
		Exp: exp,
	}

	h := jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
	}

	payload, err := jws.Encode(&h, claimSet, pk)
	if err != nil {
		return nil, err
	}

	v.Set("client_assertion", payload)

	return v, nil
}

func (c *Config) Exchange(ctx context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
	v, err := c.urlValues("authorization_code", code)
	if err != nil {
		return nil, err
	}

	token, err := getToken(ctx, c.ClientID, v, c.Sandbox)
	if err != nil {
		return nil, err
	}

	return token, nil
}
