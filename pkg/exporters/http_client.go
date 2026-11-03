package exporters

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kubescape/storage/pkg/apiauth"
)

// maxRedirects matches the limit of Go's default redirect policy.
const maxRedirects = 10

// NewHTTPClient returns the client for every post to the exporter URL: runtime
// alerts, node profiles and network streams. The timeout is cfg.TimeoutSeconds,
// or fallbackTimeout when that is unset. A nil cfg gives a plain client.
//
// When cfg.TokenFile is set, requests to the exporter URL host carry the token
// read from that file as a bearer token, and redirects from https to any other
// scheme are refused so the token cannot leave over plaintext.
func NewHTTPClient(cfg *HTTPExporterConfig, fallbackTimeout time.Duration) (*http.Client, error) {
	return newHTTPClient(cfg, fallbackTimeout, nil)
}

// newHTTPClient is NewHTTPClient with the base RoundTripper the bearer
// transport wraps; nil means http.DefaultTransport. Tests use it to trust
// httptest TLS certificates.
func newHTTPClient(cfg *HTTPExporterConfig, fallbackTimeout time.Duration, base http.RoundTripper) (*http.Client, error) {
	timeout := fallbackTimeout
	if cfg != nil && cfg.TimeoutSeconds > 0 {
		timeout = time.Duration(cfg.TimeoutSeconds) * time.Second
	}
	client := &http.Client{Timeout: timeout}
	if cfg == nil || cfg.TokenFile == "" {
		if base != nil {
			client.Transport = base
		}
		return client, nil
	}

	parsedURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}
	if parsedURL.Host == "" {
		return nil, fmt.Errorf("url %q has no host to send the bearer token to", cfg.URL)
	}
	client.Transport = apiauth.NewTransport(base, apiauth.NewFileTokenSource(cfg.TokenFile), parsedURL.Host)
	client.CheckRedirect = refuseHTTPSDowngrade
	return client, nil
}

// refuseHTTPSDowngrade keeps Go's default 10-redirect limit and refuses a
// redirect that leaves https, since the bearer transport matches on host:port
// regardless of scheme.
func refuseHTTPSDowngrade(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("refusing redirect from https to " + req.URL.Scheme + " while a bearer token is configured")
	}
	return nil
}
