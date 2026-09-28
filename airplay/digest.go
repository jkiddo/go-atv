package airplay

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// digestAuth contains the legacy HTTP Digest state used by password-protected
// AirPlay 1 receivers. The on-screen AirPlay code is the password; it is
// separate from the long-term credentials produced by pair-setup.
type digestAuth struct {
	username string
	realm    string
	password string
	nonce    string
}

func parseDigestChallenge(challenge, username, password string) (*digestAuth, error) {
	scheme, fields, found := strings.Cut(strings.TrimSpace(challenge), " ")
	if !found || !strings.EqualFold(scheme, "Digest") {
		return nil, fmt.Errorf("airplay: unsupported authentication challenge %q", challenge)
	}
	values := make(map[string]string)
	for len(fields) > 0 {
		fields = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(fields), ","))
		if fields == "" {
			break
		}
		key, rest, ok := strings.Cut(fields, "=")
		if !ok {
			return nil, fmt.Errorf("airplay: malformed Digest challenge %q", challenge)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		rest = strings.TrimSpace(rest)
		var value string
		if strings.HasPrefix(rest, "\"") {
			rest = rest[1:]
			end := strings.IndexByte(rest, '"')
			if end < 0 {
				return nil, fmt.Errorf("airplay: malformed Digest challenge %q", challenge)
			}
			value, fields = rest[:end], rest[end+1:]
		} else {
			value, fields, _ = strings.Cut(rest, ",")
			value = strings.TrimSpace(value)
		}
		values[key] = value
	}
	if values["realm"] == "" || values["nonce"] == "" {
		return nil, fmt.Errorf("airplay: Digest challenge is missing realm or nonce")
	}
	return &digestAuth{username: username, realm: values["realm"], password: password, nonce: values["nonce"]}, nil
}

func (d *digestAuth) authorization(method, uri string) string {
	ha1 := md5Hex(d.username + ":" + d.realm + ":" + d.password)
	ha2 := md5Hex(method + ":" + uri)
	response := md5Hex(ha1 + ":" + d.nonce + ":" + ha2)
	return fmt.Sprintf(
		`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		d.username, d.realm, d.nonce, uri, response,
	)
}

func md5Hex(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

// exchangeWithDigestRetry handles a challenge on the endpoint being used,
// including a nonce that changed since an earlier status request. Retry only
// once: a rejected saved code needs user input, not an authentication loop.
// Pair setup and interactive code submission use exchange directly.
func (c *connection) exchangeWithDigestRetry(ctx context.Context, req request) (*response, error) {
	stage := "control"
	switch req.URI {
	case "/play":
		stage = "play"
	case "/stop":
		stage = "stop"
	case "/playback-info":
		stage = "playback-info"
	}
	resp, err := c.exchange(ctx, req)
	if c.diagnosticHandler != nil && err == nil {
		c.diagnosticHandler(DiagnosticEvent{Stage: stage, Result: "response", StatusCode: resp.Code, Challenge: resp.Headers["www-authenticate"] != ""})
	}
	if err != nil || resp.Code != 401 || resp.Headers["www-authenticate"] == "" || requestHasHeader(req, "Authorization") {
		return resp, err
	}
	password := c.legacyPassword
	if password == "" && c.digest != nil {
		password = c.digest.password
	}
	if password == "" {
		return resp, nil
	}
	digest, err := parseDigestChallenge(resp.Headers["www-authenticate"], "AirPlay", password)
	if err != nil {
		return nil, err
	}
	c.digest = digest
	resp, err = c.exchange(ctx, req)
	if c.diagnosticHandler != nil && err == nil {
		c.diagnosticHandler(DiagnosticEvent{Stage: stage, Result: "digest-retry", StatusCode: resp.Code, Challenge: resp.Headers["www-authenticate"] != ""})
	}
	return resp, err
}
