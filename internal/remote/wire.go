// Package remote implements Ember's remote mode: a read-only API served by a
// daemon, and the client a TUI reads it with.
package remote

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/pkg/metrics"
)

const ProtocolVersion = 1

const HeaderProtocol = "Ember-Remote-Protocol"

// HeaderSession carries Hello.SessionID on the requests made outside the stream.
const HeaderSession = "Ember-Remote-Session"

const (
	RoutePrefix       = "/remote/v1/"
	RouteInfo         = RoutePrefix + "info"
	RouteStream       = RoutePrefix + "stream"
	RouteConfig       = RoutePrefix + "config"
	RouteCertificates = RoutePrefix + "certificates"
)

const (
	EventHello    = "hello"
	EventSnapshot = "snapshot"
	EventStatus   = "status"
	EventLogs     = "logs"
)

// Capabilities share their names with scopes: a client reads the intersection.
const (
	CapabilitySnapshot     = "snapshot"
	CapabilityLogs         = "logs"
	CapabilityConfig       = "config"
	CapabilityCertificates = "certificates"
)

const (
	StateOK          = "ok"
	StateStale       = "stale"
	StateUnreachable = "unreachable"
)

// DefaultInstance replaces on the wire the empty name a single-instance daemon uses internally.
const DefaultInstance = "default"

var ErrUnsupportedProtocol = errors.New("unsupported remote protocol")

type Info struct {
	Protocol     int            `json:"protocol"`
	EmberVersion string         `json:"emberVersion"`
	DaemonEpoch  string         `json:"daemonEpoch"`
	Identity     string         `json:"identity"`
	Scopes       []string       `json:"scopes"`
	Capabilities []string       `json:"capabilities"`
	Instances    []InstanceInfo `json:"instances"`
}

type InstanceInfo struct {
	Name          string   `json:"name"`
	HasFrankenPHP bool     `json:"hasFrankenPHP"`
	Interval      Duration `json:"interval"`
}

// Duration encodes as a Go duration string ("1s").
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("duration: %w", err)
	}
	*d = Duration(parsed)
	return nil
}

// Hello opens every stream; a new DaemonEpoch means the daemon restarted.
type Hello struct {
	DaemonEpoch string `json:"daemonEpoch"`
	SessionID   string `json:"sessionId"`
	Instance    string `json:"instance"`
}

// WireSnapshot carries MetricsFailed, which metrics.Snapshot keeps out of JSON.
// The thread keys (ThreadDebugStates, CurrentURI...) stay PascalCase, as in
// FrankenPHP's payload. The golden files in testdata/wire/v1 freeze this format.
type WireSnapshot struct {
	Instance      string           `json:"instance"`
	FetchedAt     time.Time        `json:"fetchedAt"`
	MetricsFailed bool             `json:"metricsFailed"`
	Snapshot      metrics.Snapshot `json:"snapshot"`
}

// NewWireSnapshot drops Metrics.Extra (plugin data, json:"-") and clears the
// body's MetricsFailed so the value equals what a client decodes.
func NewWireSnapshot(instance string, s *metrics.Snapshot) WireSnapshot {
	body := *s
	body.MetricsFailed = false
	return WireSnapshot{
		Instance:      instance,
		FetchedAt:     s.FetchedAt,
		MetricsFailed: s.MetricsFailed,
		Snapshot:      body,
	}
}

func (w WireSnapshot) ToSnapshot() *metrics.Snapshot {
	s := w.Snapshot
	s.MetricsFailed = w.MetricsFailed
	return &s
}

type Status struct {
	State string    `json:"state"`
	Since time.Time `json:"since"`
	Error string    `json:"error,omitempty"`
}

// LogBatch.Dropped counts entries lost since the previous batch.
type LogBatch struct {
	Entries []WireLogEntry `json:"entries"`
	Dropped int64          `json:"dropped"`
}

// WireLogEntry decouples the wire from fetcher.LogEntry, which has no JSON tags.
type WireLogEntry struct {
	Timestamp  time.Time `json:"timestamp"`
	Level      string    `json:"level"`
	Logger     string    `json:"logger"`
	Message    string    `json:"message"`
	Host       string    `json:"host"`
	Method     string    `json:"method"`
	URI        string    `json:"uri"`
	Status     int       `json:"status"`
	Duration   float64   `json:"duration"`
	Size       int64     `json:"size"`
	RemoteIP   string    `json:"remoteIp"`
	RawLine    string    `json:"rawLine,omitempty"`
	ParseError bool      `json:"parseError,omitempty"`
}

func NewWireLogEntry(e fetcher.LogEntry) WireLogEntry {
	return WireLogEntry{
		Timestamp:  e.Timestamp,
		Level:      e.Level,
		Logger:     e.Logger,
		Message:    e.Message,
		Host:       e.Host,
		Method:     e.Method,
		URI:        e.URI,
		Status:     e.Status,
		Duration:   e.Duration,
		Size:       e.Size,
		RemoteIP:   e.RemoteIP,
		RawLine:    e.RawLine,
		ParseError: e.ParseError,
	}
}

func (w WireLogEntry) ToLogEntry() fetcher.LogEntry {
	return fetcher.LogEntry{
		Timestamp:  w.Timestamp,
		Level:      w.Level,
		Logger:     w.Logger,
		Message:    w.Message,
		Host:       w.Host,
		Method:     w.Method,
		URI:        w.URI,
		Status:     w.Status,
		Duration:   w.Duration,
		Size:       w.Size,
		RemoteIP:   w.RemoteIP,
		RawLine:    w.RawLine,
		ParseError: w.ParseError,
	}
}

type WireCertificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dnsNames"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Serial    string    `json:"serial"`
	IsCA      bool      `json:"isCa"`
	Source    string    `json:"source"`
	Host      string    `json:"host"`
	AutoRenew bool      `json:"autoRenew"`
}

func NewWireCertificate(c fetcher.CertificateInfo) WireCertificate {
	return WireCertificate{
		Subject:   c.Subject,
		Issuer:    c.Issuer,
		DNSNames:  c.DNSNames,
		NotBefore: c.NotBefore,
		NotAfter:  c.NotAfter,
		Serial:    c.Serial,
		IsCA:      c.IsCA,
		Source:    c.Source,
		Host:      c.Host,
		AutoRenew: c.AutoRenew,
	}
}

func (w WireCertificate) ToCertificateInfo() fetcher.CertificateInfo {
	return fetcher.CertificateInfo{
		Subject:   w.Subject,
		Issuer:    w.Issuer,
		DNSNames:  w.DNSNames,
		NotBefore: w.NotBefore,
		NotAfter:  w.NotAfter,
		Serial:    w.Serial,
		IsCA:      w.IsCA,
		Source:    w.Source,
		Host:      w.Host,
		AutoRenew: w.AutoRenew,
	}
}

// ErrorResponse is the body of every non-2xx answer.
type ErrorResponse struct {
	Error              string   `json:"error"`
	SupportedProtocols []int    `json:"supportedProtocols,omitempty"`
	Instances          []string `json:"instances,omitempty"`
}

// Marshal encodes without HTML escaping, which would bloat logged URIs.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func decode[T any](what string, data []byte) (T, error) {
	var v T
	if err := json.Unmarshal(data, &v); err != nil {
		return v, fmt.Errorf("decode %s: %w", what, err)
	}
	return v, nil
}

// DecodeInfo refuses any protocol but ProtocolVersion, a missing one included.
func DecodeInfo(data []byte) (Info, error) {
	info, err := decode[Info]("info", data)
	if err != nil {
		return info, err
	}
	if info.Protocol != ProtocolVersion {
		return info, fmt.Errorf("%w: daemon speaks remote protocol %d, this ember speaks %d", ErrUnsupportedProtocol, info.Protocol, ProtocolVersion)
	}
	return info, nil
}

func DecodeHello(data []byte) (Hello, error) { return decode[Hello]("hello", data) }

func DecodeSnapshot(data []byte) (WireSnapshot, error) {
	return decode[WireSnapshot]("snapshot", data)
}

func DecodeStatus(data []byte) (Status, error) { return decode[Status]("status", data) }

func DecodeLogBatch(data []byte) (LogBatch, error) { return decode[LogBatch]("logs", data) }

func DecodeErrorResponse(data []byte) (ErrorResponse, error) {
	return decode[ErrorResponse]("error response", data)
}

// seq is shared by all sessions of an epoch, so an id survives a reconnect.
func FormatEventID(epoch string, seq uint64) string {
	return epoch + ":" + strconv.FormatUint(seq, 10)
}

// ParseEventID reports false for any id FormatEventID could not have produced.
func ParseEventID(id string) (epoch string, seq uint64, ok bool) {
	i := strings.LastIndexByte(id, ':')
	if i <= 0 {
		return "", 0, false
	}
	seq, err := strconv.ParseUint(id[i+1:], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return id[:i], seq, true
}
