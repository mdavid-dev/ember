package exporter

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bufferLogSource struct {
	buf *model.LogBuffer
	err error
}

func (s *bufferLogSource) Since(after int64, limit int) ([]fetcher.LogEntry, int64, error) {
	if s.err != nil {
		return nil, 0, s.err
	}
	entries, next := s.buf.Since(after, limit)
	return entries, next, nil
}

func getLogs(t *testing.T, h http.Handler, query string) (*httptest.ResponseRecorder, fetcher.RemoteLogs) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/logs?"+query, nil))
	var body fetcher.RemoteLogs
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	}
	return rec, body
}

func TestLogsHandler_PagesFromTheCursor(t *testing.T) {
	buf := model.NewLogBuffer(0)
	for i := range 1500 {
		buf.Append(fetcher.LogEntry{Message: strconv.Itoa(i)})
	}
	h := LogsHandler(&bufferLogSource{buf: buf})

	rec, page := getLogs(t, h, "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Len(t, page.Entries, 1000)
	assert.Equal(t, "0", page.Entries[0].Message)
	assert.Equal(t, int64(1000), page.Next)

	_, page = getLogs(t, h, "after=1000")
	require.Len(t, page.Entries, 500)
	assert.Equal(t, "1000", page.Entries[0].Message)
	assert.Equal(t, int64(1500), page.Next)

	_, page = getLogs(t, h, "after=1500")
	assert.Empty(t, page.Entries)
	assert.Equal(t, int64(1500), page.Next)
}

func TestLogsHandler_RejectsABadCursor(t *testing.T) {
	h := LogsHandler(&bufferLogSource{buf: model.NewLogBuffer(0)})
	for _, query := range []string{"after=abc", "after=-2"} {
		rec, _ := getLogs(t, h, query)
		assert.Equal(t, http.StatusBadRequest, rec.Code, query)
	}
}

func TestLogsHandler_UnavailableSource(t *testing.T) {
	h := LogsHandler(&bufferLogSource{err: errors.New("logs are not available on a multi-instance daemon")})

	rec, _ := getLogs(t, h, "")

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "multi-instance daemon")
}
