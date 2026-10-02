package exporter

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// caddyConfig is compact and HTML-escaped as Caddy writes it, which then adds a newline.
const caddyConfig = `{"apps":{"http":{"servers":{"srv0":{"routes":[{"handle":[{"handler":"reverse_proxy","headers":{"request":{"set":{"X-Demo-Token":["demo\u003c\u0026\u003esecret"]}}}}]}]}}}}}`

func getConfig(h http.Handler, query string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config?"+query, nil))
	return rec
}

func TestConfigHandler_RelaysCaddysBytes(t *testing.T) {
	h := ConfigHandler(singleIntervals, map[string]InstanceSource{"": &fakeInstanceSource{config: caddyConfig}})

	rec := getConfig(h, "")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, caddyConfig+"\n", rec.Body.String()) //nolint:testifylint // byte for byte: JSONEq would accept a re-encoded config
}

func TestConfigHandler_CaddyDown(t *testing.T) {
	h := ConfigHandler(singleIntervals, map[string]InstanceSource{"": &fakeInstanceSource{configErr: errors.New("fetch config: connection refused")}})

	rec := getConfig(h, "")

	assert.Equal(t, http.StatusBadGateway, rec.Code)
	assert.Contains(t, rec.Body.String(), "connection refused")
}

func TestConfigHandler_MultiInstance(t *testing.T) {
	intervals := map[string]time.Duration{"web1": time.Second, "web2": time.Second}
	h := ConfigHandler(intervals, map[string]InstanceSource{"web1": &fakeInstanceSource{config: `"web1"`}, "web2": &fakeInstanceSource{config: `"web2"`}})

	assert.Equal(t, http.StatusBadRequest, getConfig(h, "").Code)

	rec := getConfig(h, "instance=web2")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `"web2"`, rec.Body.String())
}
