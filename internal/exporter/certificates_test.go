package exporter

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCertSource struct {
	ca     string
	dialed []string
}

func (f *fakeCertSource) FetchPKICertificates(context.Context) []fetcher.CertificateInfo {
	return []fetcher.CertificateInfo{{Subject: f.ca, Source: "pki"}}
}

func (f *fakeCertSource) DialTLSCertificates(_ context.Context, hosts []string) []fetcher.CertificateInfo {
	f.dialed = hosts
	return []fetcher.CertificateInfo{{Subject: hosts[0], Source: "tls"}}
}

func getCertificates(t *testing.T, h http.Handler, query string) (*httptest.ResponseRecorder, []fetcher.CertificateInfo) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/certificates?"+query, nil))
	var certs []fetcher.CertificateInfo
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &certs))
	}
	return rec, certs
}

func TestCertificatesHandler_Sources(t *testing.T) {
	holder := &StateHolder{}
	storeSnapshot(holder, "", &fetcher.Snapshot{FetchedAt: time.Now(), Metrics: fetcher.MetricsSnapshot{
		Hosts: map[string]*fetcher.HostMetrics{"shop.test": {Host: "shop.test"}, "api.test": {Host: "api.test"}},
	}})
	src := &fakeCertSource{}
	h := CertificatesHandler(holder, singleIntervals, map[string]CertSource{"": src})

	rec, certs := getCertificates(t, h, "source=pki")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "pki", certs[0].Source)

	rec, certs = getCertificates(t, h, "source=tls&host=evil.example")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "tls", certs[0].Source)
	assert.Equal(t, []string{"api.test", "shop.test"}, src.dialed, "only the hosts of the daemon's snapshot")

	rec, _ = getCertificates(t, h, "source=disk")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCertificatesHandler_MultiInstance(t *testing.T) {
	holder := &StateHolder{}
	holder.SetMulti(true)
	intervals := map[string]time.Duration{"web1": time.Second, "web2": time.Second}
	h := CertificatesHandler(holder, intervals, map[string]CertSource{"web1": &fakeCertSource{ca: "web1 CA"}, "web2": &fakeCertSource{ca: "web2 CA"}})

	rec, _ := getCertificates(t, h, "source=pki")
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec, certs := getCertificates(t, h, "source=pki&instance=web2")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "web2 CA", certs[0].Subject)
}
