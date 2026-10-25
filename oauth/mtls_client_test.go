package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"golang.org/x/oauth2"
)

func TestTokenRequestMTLS(t *testing.T) {
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPath := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600))
	issue := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string, tls.Certificate) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, e)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		der, e := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
		require.NoError(t, e)
		keyDER, e := x509.MarshalECPrivateKey(key)
		require.NoError(t, e)
		cp, kp := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".key")
		require.NoError(t, os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
		require.NoError(t, os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600))
		pair, e := tls.LoadX509KeyPair(cp, kp)
		require.NoError(t, e)
		return cp, kp, pair
	}
	_, _, serverCert := issue("server", 2, x509.ExtKeyUsageServerAuth)
	certPath, keyPath, _ := issue("client", 3, x509.ExtKeyUsageClientAuth)
	// Parse the signed CA so its public key is available for verification.
	parsedCA, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsedCA)
	var hits atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, 2, r.ProtoMajor)
		assert.Equal(t, "/oauth2/token", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.Form.Get("grant_type"))
		assert.Equal(t, "consumer", r.Form.Get("nfInstanceId"))
		assert.Equal(t, "scope", r.Form.Get("scope"))
		assert.NotEmpty(t, r.TLS.VerifiedChains)
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"mtls-token","token_type":"Bearer","expires_in":3600,"scope":"scope"}`))
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	client, err := NewMTLSClient(certPath, keyPath, caPath, 5*time.Second, 7*time.Second, 2*time.Second)
	require.NoError(t, err)
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http2.Transport)
	require.Equal(t, 7*time.Second, transport.ReadIdleTimeout)
	require.Equal(t, 2*time.Second, transport.PingTimeout)
	require.False(t, transport.TLSClientConfig.InsecureSkipVerify)
	request := TokenRequest{ConsumerNFType: models.Nrf_NFMgmt_NFType_CHF, ConsumerNFInstanceID: "consumer", TargetNFType: models.Nrf_NFMgmt_NFType_PCF, NRFURI: server.URL, Scope: "scope", HTTPClient: client}
	for range 2 {
		ctx, pd, e := GetTokenCtx(request)
		require.NoError(t, e)
		require.Nil(t, pd)
		token, e := ctx.Value(openapi.ContextOAuth2).(oauth2.TokenSource).Token()
		require.NoError(t, e)
		require.Equal(t, "mtls-token", token.AccessToken)
	}
	require.EqualValues(t, 1, hits.Load(), "second request should use cache")
	// Same consumer/NRF/scope with another client must not use the first token.
	missingCert := &http.Client{Timeout: 5 * time.Second, Transport: &http2.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	defer missingCert.CloseIdleConnections()
	request.HTTPClient = missingCert
	_, _, err = GetTokenCtx(request)
	require.Error(t, err)
	wrongCA, err := NewMTLSClient(certPath, keyPath, caPath, 5*time.Second, 0, 0)
	require.NoError(t, err)
	wrongCA.Transport.(*http2.Transport).TLSClientConfig.RootCAs = x509.NewCertPool()
	defer wrongCA.CloseIdleConnections()
	request.HTTPClient = wrongCA
	_, _, err = GetTokenCtx(request)
	require.Error(t, err)
	require.EqualValues(t, 1, hits.Load())
	request.HTTPClient = nil
	_, _, err = GetTokenCtx(request)
	require.Error(t, err)
	require.EqualValues(t, 1, hits.Load())
	t.Run("invalid_configuration", func(t *testing.T) {
		_, e := NewMTLSClient(certPath, keyPath, caPath, 0, 0, 0)
		require.Error(t, e)
		_, e = NewMTLSClient(certPath, "missing", caPath, time.Second, 0, 0)
		require.Error(t, e)
		badCA := filepath.Join(dir, "invalid.pem")
		require.NoError(t, os.WriteFile(badCA, []byte("invalid"), 0600))
		_, e = NewMTLSClient(certPath, keyPath, badCA, time.Second, 0, 0)
		require.Error(t, e)
	})
}
