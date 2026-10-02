package app

import (
	"context"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/alexandre-daubois/ember/internal/exporter"
	"github.com/alexandre-daubois/ember/internal/fetcher"
	"github.com/alexandre-daubois/ember/internal/model"
	"github.com/stretchr/testify/require"
)

var notSent = map[string]bool{"MetricsFailed": true, "Extra": true}

// fillAll reaches every field, so one added to metrics.Snapshot later is covered too.
func fillAll(v reflect.Value, n *int) {
	*n++
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fillAll(v.Elem(), n)
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[time.Time]() {
			v.Set(reflect.ValueOf(time.Unix(int64(1_700_000_000+*n), 0).UTC()))
			return
		}
		for i := range v.NumField() {
			if f := v.Type().Field(i); f.IsExported() && !notSent[f.Name] {
				fillAll(v.Field(i), n)
			}
		}
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 2, 2))
		for i := range 2 {
			fillAll(v.Index(i), n)
		}
	case reflect.Map:
		v.Set(reflect.MakeMap(v.Type()))
		key, val := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fillAll(key, n)
		fillAll(val, n)
		v.SetMapIndex(key, val)
	case reflect.String:
		v.SetString("v" + time.Duration(*n).String())
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(int64(*n))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(*n))
	case reflect.Float32, reflect.Float64:
		v.SetFloat(float64(*n) + 0.5)
	default:
		panic("fillAll: unhandled kind " + v.Kind().String())
	}
}

func fullSnapshot(fetchedAt time.Time) *fetcher.Snapshot {
	var snap fetcher.Snapshot
	n := 0
	fillAll(reflect.ValueOf(&snap).Elem(), &n)
	snap.FetchedAt = fetchedAt
	return &snap
}

func TestRemote_SnapshotSurvivesTheTrip(t *testing.T) {
	fetchedAt := time.Now().UTC().Round(0)
	holder := &exporter.StateHolder{}
	var state model.State
	state.Update(fullSnapshot(fetchedAt))
	holder.StoreAll(state.CopyForExport(), nil)

	srv := httptest.NewServer(exporter.SnapshotHandler(holder, time.Second, map[string]time.Duration{"": time.Second}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	f := fetcher.NewRemoteFetcher(u, "", nil, "test")
	defer f.CloseIdleConnections()

	got, err := f.Fetch(context.Background())
	require.NoError(t, err)
	require.Equal(t, fullSnapshot(fetchedAt), got)
}
