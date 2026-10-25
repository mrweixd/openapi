package oauth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"golang.org/x/net/http2"
)

// NewMTLSClient builds an HTTP/2 token client using the supplied client identity
// and trusted server CA bundle. It always verifies the server certificate and
// hostname. Configure it once before requests; do not mutate it after use.
func NewMTLSClient(certFile, keyFile, caFile string,
	clientTimeout, readIdleTimeout, pingTimeout time.Duration,
) (*http.Client, error) {
	if clientTimeout <= 0 || readIdleTimeout < 0 || pingTimeout < 0 {
		return nil, fmt.Errorf("invalid mTLS client timeouts")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load OAuth client identity: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read OAuth server CA bundle: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("OAuth server CA bundle contains no certificates")
	}
	return &http.Client{
		Timeout: clientTimeout,
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS12,
				RootCAs:      roots,
				Certificates: []tls.Certificate{cert},
			},
			ReadIdleTimeout: readIdleTimeout,
			PingTimeout:     pingTimeout,
		},
	}, nil
}
