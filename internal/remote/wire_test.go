package remote

import (
	"bytes"
	"encoding/json"
	"flag"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/pkg/metrics"
)

// -update is for backward-compatible changes only (a new field); anything else is protocol v2.
var updateGolden = flag.Bool("update", false, "rewrite the wire golden files")

var (
	fixtureTime  = time.Date(2026, 9, 25, 12, 3, 4, 500_000_000, time.UTC)
	fixtureEpoch = "01J9ZK3Q8V4T6W0Y2A5C7E9G1H"
)

func fixtureInfo() Info {
	return Info{
		Protocol:     ProtocolVersion,
		EmberVersion: "1.7.0",
		DaemonEpoch:  fixtureEpoch,
		Identity:     "alice",
		Scopes:       []string{CapabilitySnapshot, CapabilityLogs},
		Capabilities: []string{CapabilitySnapshot, CapabilityLogs, CapabilityConfig, CapabilityCertificates},
		Instances:    []InstanceInfo{{Name: DefaultInstance, HasFrankenPHP: true, Interval: Duration(time.Second)}},
	}
}

func fixtureHello() Hello {
	return Hello{DaemonEpoch: fixtureEpoch, SessionID: "s-4f2a9c", Instance: DefaultInstance}
}

func fixtureBuckets() []metrics.HistogramBucket {
	return []metrics.HistogramBucket{
		{UpperBound: 0.005, CumulativeCount: 10},
		{UpperBound: 0.25, CumulativeCount: 38},
		{UpperBound: math.Inf(1), CumulativeCount: 41},
	}
}

func fixtureSnapshot() WireSnapshot {
	snap := &metrics.Snapshot{
		Threads: metrics.ThreadsResponse{
			ThreadDebugStates: []metrics.ThreadDebugState{
				{
					Index: 0, Name: "Worker PHP Thread - /app/public/index.php", State: "busy",
					IsWaiting: true, IsBusy: true, WaitingSinceMilliseconds: 12,
					CurrentURI: "/api/orders?page=2&sort=desc", CurrentMethod: "GET",
					RequestStartedAt: 1790337784000, MemoryUsage: 8388608, RequestCount: 1532,
				},
				{Index: 1, Name: "Regular PHP Thread", State: "ready"},
			},
			ReservedThreadCount: 2,
		},
		Metrics: metrics.MetricsSnapshot{
			TotalThreads: 16,
			BusyThreads:  1,
			QueueDepth:   3,
			Workers: map[string]*metrics.WorkerMetrics{
				"/app/public/index.php": {
					Worker: "/app/public/index.php", Total: 8, Busy: 1, Ready: 7,
					RequestTime: 125.5, RequestCount: 1532, Crashes: 1, Restarts: 2, QueueDepth: 4,
				},
			},
			HTTPRequestErrorsTotal:   5,
			HTTPRequestsTotal:        1200,
			HTTPRequestDurationSum:   42.75,
			HTTPRequestDurationCount: 1200,
			HTTPRequestsInFlight:     2,
			DurationBuckets:          fixtureBuckets(),
			HasHTTPMetrics:           true,
			Hosts: map[string]*metrics.HostMetrics{
				"shop.example": {
					Host: "shop.example", RequestsTotal: 1200, DurationSum: 42.75, DurationCount: 1200,
					InFlight: 2, DurationBuckets: fixtureBuckets(),
					StatusCodes:     map[int]float64{200: 1150, 404: 45, 502: 5},
					Methods:         map[string]float64{"GET": 1000, "POST": 200},
					ResponseSizeSum: 1048576, ResponseSizeCount: 1200,
					RequestSizeSum: 20480, RequestSizeCount: 200,
					ErrorsTotal: 5, TTFBSum: 30.5, TTFBCount: 1200, TTFBBuckets: fixtureBuckets(),
				},
			},
			Upstreams: map[string]*metrics.UpstreamMetrics{
				"php:9000/reverse_proxy": {Address: "php:9000", Handler: "reverse_proxy", Healthy: 1},
			},
			ProcessCPUSecondsTotal:           321.5,
			ProcessRSSBytes:                  134217728,
			ProcessStartTimeSeconds:          1790330000,
			HasConfigReloadMetrics:           true,
			ConfigLastReloadSuccessful:       1,
			ConfigLastReloadSuccessTimestamp: 1790330010,
		},
		Process: metrics.ProcessMetrics{
			PID: 4242, CPUPercent: 12.5, RSS: 134217728, CreateTime: 1790330000000, Uptime: 90 * time.Minute,
		},
		FetchedAt:     fixtureTime,
		Errors:        []string{"fetch threads: context deadline exceeded"},
		HasFrankenPHP: true,
		MetricsFailed: true,
	}
	return NewWireSnapshot(DefaultInstance, snap)
}

func fixtureStatus() Status {
	return Status{State: StateUnreachable, Since: fixtureTime, Error: "dial tcp 10.0.0.5:2019: connect: connection refused"}
}

func fixtureLogBatch() LogBatch {
	return LogBatch{
		Entries: []WireLogEntry{
			{
				Timestamp: fixtureTime, Level: "info", Logger: "http.log.access.log0", Message: "handled request",
				Host: "shop.example", Method: "GET", URI: "/cart?id=1&x=<y>", Status: 200,
				Duration: 0.0125, Size: 5120, RemoteIP: "203.0.113.9",
			},
			{Timestamp: fixtureTime, RawLine: "not json", ParseError: true},
		},
		Dropped: 3,
	}
}

func fixtureCertificate() WireCertificate {
	return WireCertificate{
		Subject: "CN=shop.example", Issuer: "CN=R11,O=Let's Encrypt,C=US",
		DNSNames:  []string{"shop.example", "www.shop.example"},
		NotBefore: fixtureTime.Add(-30 * 24 * time.Hour), NotAfter: fixtureTime.Add(60 * 24 * time.Hour),
		Serial: "4a3f2e1d", IsCA: true, Source: "tls", Host: "shop.example", AutoRenew: true,
	}
}

func fixtureErrorResponse() ErrorResponse {
	return ErrorResponse{
		Error:              "unsupported remote protocol 2",
		SupportedProtocols: []int{1},
		Instances:          []string{"api", "web"},
	}
}

var goldenCases = []struct {
	name  string
	value func() any
}{
	{"info", func() any { return fixtureInfo() }},
	{"hello", func() any { return fixtureHello() }},
	{"snapshot", func() any { return fixtureSnapshot() }},
	{"status", func() any { return fixtureStatus() }},
	{"logs", func() any { return fixtureLogBatch() }},
	{"certificate", func() any { return fixtureCertificate() }},
	{"error", func() any { return fixtureErrorResponse() }},
}

// json.Indent only adds whitespace, so the indented golden files stay byte-exact.
func TestWireGolden(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := Marshal(tc.value())
			require.NoError(t, err)
			var indented bytes.Buffer
			require.NoError(t, json.Indent(&indented, wire, "", "  "))
			indented.WriteByte('\n')

			path := filepath.Join("testdata", "wire", "v1", tc.name+".json")
			if *updateGolden {
				require.NoError(t, os.WriteFile(path, indented.Bytes(), 0o644))
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err, "run go test -update to create the golden file")
			assert.Equal(t, string(want), indented.String(), "wire format of %s changed: add fields only, or bump the protocol", tc.name)
		})
	}
}

// A field left at zero in the fixtures would reach the wire unseen by the golden files.
func TestWireFixturesCoverEveryField(t *testing.T) {
	for _, tc := range goldenCases {
		t.Run(tc.name, func(t *testing.T) {
			v := reflect.ValueOf(tc.value())
			want := map[string]bool{}
			collectFieldPaths(v.Type(), tc.name, want, map[reflect.Type]bool{})
			seen := map[string]bool{}
			collectSetPaths(v, tc.name, seen)

			var missing []string
			for p := range want {
				if !seen[p] {
					missing = append(missing, p)
				}
			}
			slices.Sort(missing)
			assert.Empty(t, missing, "fixture leaves these fields at their zero value")
		})
	}
}

var timeType = reflect.TypeFor[time.Time]()

func jsonFieldIncluded(f reflect.StructField) bool {
	return f.IsExported() && f.Tag.Get("json") != "-"
}

func collectFieldPaths(t reflect.Type, path string, out map[string]bool, visiting map[reflect.Type]bool) {
	switch t.Kind() {
	case reflect.Pointer:
		collectFieldPaths(t.Elem(), path, out, visiting)
	case reflect.Slice, reflect.Map:
		collectFieldPaths(t.Elem(), path+"[]", out, visiting)
	case reflect.Struct:
		if t == timeType {
			out[path] = true
			return
		}
		if visiting[t] {
			return
		}
		visiting[t] = true
		defer delete(visiting, t)
		for i := range t.NumField() {
			f := t.Field(i)
			if jsonFieldIncluded(f) {
				collectFieldPaths(f.Type, path+"."+f.Name, out, visiting)
			}
		}
	default:
		out[path] = true
	}
}

func collectSetPaths(v reflect.Value, path string, out map[string]bool) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			collectSetPaths(v.Elem(), path, out)
		}
	case reflect.Slice:
		for i := range v.Len() {
			collectSetPaths(v.Index(i), path+"[]", out)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			collectSetPaths(v.MapIndex(k), path+"[]", out)
		}
	case reflect.Struct:
		if v.Type() == timeType {
			if !v.IsZero() {
				out[path] = true
			}
			return
		}
		for i := range v.NumField() {
			if jsonFieldIncluded(v.Type().Field(i)) {
				collectSetPaths(v.Field(i), path+"."+v.Type().Field(i).Name, out)
			}
		}
	default:
		if !v.IsZero() {
			out[path] = true
		}
	}
}

func TestWireGolden_SnapshotKeepsInfBucketAsString(t *testing.T) {
	wire, err := Marshal(fixtureSnapshot())
	require.NoError(t, err)
	assert.Contains(t, string(wire), `{"upperBound":"+Inf","cumulativeCount":41}`)
	assert.Contains(t, string(wire), `"metricsFailed":true`)
	assert.NotContains(t, string(wire), `\u0026`, "HTML escaping is off on the wire")
	assert.Contains(t, string(wire), `page=2&sort=desc`)
}

func TestMarshal_ReportsEncodingErrors(t *testing.T) {
	_, err := Marshal(math.NaN())
	require.Error(t, err)
}

func TestWireRoundTrip(t *testing.T) {
	t.Run("info", func(t *testing.T) {
		assertRoundTrip(t, fixtureInfo(), DecodeInfo)
	})
	t.Run("hello", func(t *testing.T) {
		assertRoundTrip(t, fixtureHello(), DecodeHello)
	})
	t.Run("status", func(t *testing.T) {
		assertRoundTrip(t, fixtureStatus(), DecodeStatus)
	})
	t.Run("logs", func(t *testing.T) {
		assertRoundTrip(t, fixtureLogBatch(), DecodeLogBatch)
	})
	t.Run("error", func(t *testing.T) {
		assertRoundTrip(t, fixtureErrorResponse(), DecodeErrorResponse)
	})
	t.Run("certificate", func(t *testing.T) {
		assertRoundTrip(t, fixtureCertificate(), func(b []byte) (WireCertificate, error) {
			return decode[WireCertificate]("certificate", b)
		})
	})
	t.Run("snapshot", func(t *testing.T) {
		want := fixtureSnapshot()
		wire, err := Marshal(want)
		require.NoError(t, err)
		got, err := DecodeSnapshot(wire)
		require.NoError(t, err)

		assert.True(t, math.IsInf(got.Snapshot.Metrics.DurationBuckets[2].UpperBound, 1))
		assert.Equal(t, want, got)
	})
}

func assertRoundTrip[T any](t *testing.T, want T, dec func([]byte) (T, error)) {
	t.Helper()
	wire, err := Marshal(want)
	require.NoError(t, err)
	got, err := dec(wire)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestWireSnapshot_ToSnapshotRestoresMetricsFailed(t *testing.T) {
	ws := fixtureSnapshot()
	require.False(t, ws.Snapshot.MetricsFailed, "the public field is json:\"-\", the envelope carries it")

	snap := ws.ToSnapshot()
	assert.True(t, snap.MetricsFailed)
	assert.Equal(t, fixtureTime, snap.FetchedAt)
	assert.Equal(t, 16.0, snap.Metrics.TotalThreads)

	snap.Metrics.TotalThreads = 1
	assert.Equal(t, 16.0, ws.Snapshot.Metrics.TotalThreads, "ToSnapshot returns a copy")
}

func TestNewWireSnapshot_TakesEnvelopeFieldsFromSnapshot(t *testing.T) {
	snap := &metrics.Snapshot{FetchedAt: fixtureTime, MetricsFailed: true}
	ws := NewWireSnapshot("web", snap)
	assert.Equal(t, "web", ws.Instance)
	assert.Equal(t, fixtureTime, ws.FetchedAt)
	assert.True(t, ws.MetricsFailed)
}

func TestWireSnapshot_ExtraDoesNotTravel(t *testing.T) {
	ws := NewWireSnapshot(DefaultInstance, &metrics.Snapshot{Metrics: metrics.MetricsSnapshot{Extra: nil}})
	wire, err := Marshal(ws)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "extra")
	assert.NotContains(t, string(wire), "Extra")
}

func TestWireLogEntry_ConvertsBothWays(t *testing.T) {
	e := fetcher.LogEntry{
		Timestamp: fixtureTime, Level: "error", Logger: "http.log.access", Message: "m",
		Host: "h", Method: "POST", URI: "/u", Status: 500, Duration: 1.5, Size: 9,
		RemoteIP: "192.0.2.1", RawLine: "raw", ParseError: true,
	}
	assert.Equal(t, e, NewWireLogEntry(e).ToLogEntry())
}

func TestWireCertificate_ConvertsBothWays(t *testing.T) {
	c := fetcher.CertificateInfo{
		Subject: "s", Issuer: "i", DNSNames: []string{"a"}, NotBefore: fixtureTime, NotAfter: fixtureTime,
		Serial: "1", IsCA: true, Source: "pki", Host: "h", AutoRenew: true,
	}
	assert.Equal(t, c, NewWireCertificate(c).ToCertificateInfo())
}

func TestDecode_IgnoresUnknownFields(t *testing.T) {
	info, err := DecodeInfo([]byte(`{"protocol":1,"daemonEpoch":"e","future":{"nested":[1,2]},"identity":"bob"}`))
	require.NoError(t, err)
	assert.Equal(t, "bob", info.Identity)

	ws, err := DecodeSnapshot([]byte(`{"instance":"web","newField":true,"snapshot":{"hasFrankenPHP":true,"threads":{"extra":1}}}`))
	require.NoError(t, err)
	assert.Equal(t, "web", ws.Instance)
	assert.True(t, ws.Snapshot.HasFrankenPHP)

	st, err := DecodeStatus([]byte(`{"state":"ok","since":"2026-09-25T12:03:04Z","hint":"x"}`))
	require.NoError(t, err)
	assert.Equal(t, StateOK, st.State)

	lb, err := DecodeLogBatch([]byte(`{"entries":[{"host":"h","traceId":"abc"}],"dropped":0,"more":1}`))
	require.NoError(t, err)
	require.Len(t, lb.Entries, 1)
	assert.Equal(t, "h", lb.Entries[0].Host)

	h, err := DecodeHello([]byte(`{"daemonEpoch":"e","sessionId":"s","instance":"i","resumed":true}`))
	require.NoError(t, err)
	assert.Equal(t, "s", h.SessionID)
}

func TestDecodeInfo_RefusesOtherProtocols(t *testing.T) {
	for _, body := range []string{`{"protocol":2}`, `{"protocol":0}`, `{}`, `{"protocol":-1}`} {
		_, err := DecodeInfo([]byte(body))
		require.ErrorIs(t, err, ErrUnsupportedProtocol, body)
	}
	_, err := DecodeInfo([]byte(`{"protocol":2}`))
	require.ErrorContains(t, err, "daemon speaks remote protocol 2, this ember speaks 1")
}

func TestDecode_RejectsMalformedPayloads(t *testing.T) {
	for _, body := range []string{``, `nul`, `{"protocol":"1"}`, `{"protocol":1} trailing`, `[]`} {
		_, err := DecodeInfo([]byte(body))
		require.Error(t, err, body)
		require.NotErrorIs(t, err, ErrUnsupportedProtocol, body)
	}

	_, err := DecodeSnapshot([]byte(`{"snapshot":{"metrics":{"durationBuckets":[{"upperBound":"inf"}]}}}`))
	require.ErrorContains(t, err, "decode snapshot")

	_, err = DecodeStatus([]byte(`{"since":"yesterday"}`))
	require.ErrorContains(t, err, "decode status")

	_, err = DecodeErrorResponse([]byte(`{"error":1}`))
	require.ErrorContains(t, err, "decode error response")
}

func TestDuration_JSON(t *testing.T) {
	wire, err := Marshal(Duration(1500 * time.Millisecond))
	require.NoError(t, err)
	assert.Equal(t, `"1.5s"`, string(wire))

	var d Duration
	require.NoError(t, json.Unmarshal([]byte(`"250ms"`), &d))
	assert.Equal(t, Duration(250*time.Millisecond), d)

	require.ErrorContains(t, json.Unmarshal([]byte(`1000000000`), &d), "duration")
	require.ErrorContains(t, json.Unmarshal([]byte(`"soon"`), &d), "duration")
}

func TestEventID_RoundTrip(t *testing.T) {
	id := FormatEventID(fixtureEpoch, 42)
	assert.Equal(t, fixtureEpoch+":42", id)

	epoch, seq, ok := ParseEventID(id)
	require.True(t, ok)
	assert.Equal(t, fixtureEpoch, epoch)
	assert.Equal(t, uint64(42), seq)

	epoch, seq, ok = ParseEventID(FormatEventID("a:b", math.MaxUint64))
	require.True(t, ok, "the seq is what follows the last colon")
	assert.Equal(t, "a:b", epoch)
	assert.Equal(t, uint64(math.MaxUint64), seq)
}

func TestParseEventID_RejectsForeignIDs(t *testing.T) {
	for _, id := range []string{"", "42", ":42", "epoch:", "epoch:-1", "epoch:+1", "epoch:1x", "epoch: 1", "epoch:18446744073709551616", "epoch:0x10"} {
		_, _, ok := ParseEventID(id)
		assert.False(t, ok, "%q", id)
	}
}

func TestGoldenFilesHaveNoStrayCases(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("testdata", "wire", "v1"))
	require.NoError(t, err)
	names := make([]string, 0, len(goldenCases))
	for _, tc := range goldenCases {
		names = append(names, tc.name+".json")
	}
	for _, e := range entries {
		assert.Contains(t, names, e.Name(), "golden file without a test case")
		assert.True(t, strings.HasSuffix(e.Name(), ".json"))
	}
}

func TestWireConstantsArePinned(t *testing.T) {
	assert.Equal(t, 1, ProtocolVersion)
	for _, c := range []struct{ got, want string }{
		{HeaderProtocol, "Ember-Remote-Protocol"},
		{HeaderSession, "Ember-Remote-Session"},
		{RoutePrefix, "/remote/v1/"},
		{RouteInfo, "/remote/v1/info"},
		{RouteStream, "/remote/v1/stream"},
		{RouteConfig, "/remote/v1/config"},
		{RouteCertificates, "/remote/v1/certificates"},
		{EventHello, "hello"},
		{EventSnapshot, "snapshot"},
		{EventStatus, "status"},
		{EventLogs, "logs"},
		{CapabilitySnapshot, "snapshot"},
		{CapabilityLogs, "logs"},
		{CapabilityConfig, "config"},
		{CapabilityCertificates, "certificates"},
		{StateOK, "ok"},
		{StateStale, "stale"},
		{StateUnreachable, "unreachable"},
		{DefaultInstance, "default"},
	} {
		assert.Equal(t, c.want, c.got)
	}
}
