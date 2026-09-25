package metrics_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/pkg/metrics"
)

// assertSameBytes compares byte for byte, which JSONEq does not.
func assertSameBytes(t *testing.T, want string, got []byte) {
	t.Helper()
	assert.Equal(t, []byte(want), got, "got %s", got)
}

func TestHistogramBucket_JSONRoundTripWithInf(t *testing.T) {
	buckets := []metrics.HistogramBucket{
		{UpperBound: 0.25, CumulativeCount: 3},
		{UpperBound: math.Inf(1), CumulativeCount: 5},
	}

	data, err := json.Marshal(buckets)
	require.NoError(t, err)
	assertSameBytes(t, `[{"upperBound":0.25,"cumulativeCount":3},{"upperBound":"+Inf","cumulativeCount":5}]`, data)

	var decoded []metrics.HistogramBucket
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded, 2)
	assert.Equal(t, buckets[0], decoded[0])
	assert.True(t, math.IsInf(decoded[1].UpperBound, 1), "the +Inf bucket carries the total that percentiles need")
	assert.Equal(t, 5.0, decoded[1].CumulativeCount)
}

func TestHistogramBucket_JSONNegativeInf(t *testing.T) {
	data, err := json.Marshal(metrics.HistogramBucket{UpperBound: math.Inf(-1), CumulativeCount: 1})
	require.NoError(t, err)
	assertSameBytes(t, `{"upperBound":"-Inf","cumulativeCount":1}`, data)

	var b metrics.HistogramBucket
	require.NoError(t, json.Unmarshal(data, &b))
	assert.True(t, math.IsInf(b.UpperBound, -1))
}

// plainBucket is HistogramBucket as it encoded before its JSON methods.
type plainBucket struct {
	UpperBound      float64 `json:"upperBound"`
	CumulativeCount float64 `json:"cumulativeCount"`
}

func TestHistogramBucket_FiniteBoundsEncodeUnchanged(t *testing.T) {
	bounds := []float64{0, math.Copysign(0, -1), 5e-324, 1e-7, 0.005, 0.1, 0.25, 1, 2.5, 60, 1e21, -3.5, math.MaxFloat64}
	for _, ub := range bounds {
		got, err := json.Marshal(metrics.HistogramBucket{UpperBound: ub, CumulativeCount: 42.5})
		require.NoError(t, err)
		want, err := json.Marshal(plainBucket{UpperBound: ub, CumulativeCount: 42.5})
		require.NoError(t, err)
		assert.Equal(t, string(want), string(got), "upperBound %v", ub)

		var decoded metrics.HistogramBucket
		require.NoError(t, json.Unmarshal(got, &decoded))
		assert.Equal(t, ub, decoded.UpperBound)
	}
}

func TestHistogramBucket_FiniteBoundsEncodeUnchangedInsideSnapshot(t *testing.T) {
	host := metrics.HostMetrics{
		Host:            "a.test",
		DurationBuckets: []metrics.HistogramBucket{{UpperBound: 0.005, CumulativeCount: 1}, {UpperBound: 0.5, CumulativeCount: 7}},
	}
	data, err := json.Marshal(host)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"durationBuckets":[{"upperBound":0.005,"cumulativeCount":1},{"upperBound":0.5,"cumulativeCount":7}]`)
}

func TestHistogramBucket_UnmarshalRejectsInvalidStrings(t *testing.T) {
	for _, s := range []string{`"inf"`, `"Inf"`, `"+inf"`, `"-inf"`, `"NaN"`, `" +Inf"`, `"+Inf "`, `"1.5"`, `""`} {
		var b metrics.HistogramBucket
		err := json.Unmarshal([]byte(`{"upperBound":`+s+`,"cumulativeCount":1}`), &b)
		require.Error(t, err, "upperBound %s", s)
		assert.Contains(t, err.Error(), "invalid upperBound")
	}
}

func TestHistogramBucket_UnmarshalRejectsOtherTypes(t *testing.T) {
	for _, v := range []string{`true`, `[]`, `{}`, `1e400`} {
		var b metrics.HistogramBucket
		require.Error(t, json.Unmarshal([]byte(`{"upperBound":`+v+`}`), &b), "upperBound %s", v)
	}
}

func TestHistogramBucket_UnmarshalRejectsMalformedObject(t *testing.T) {
	var b metrics.HistogramBucket
	require.Error(t, json.Unmarshal([]byte(`{"cumulativeCount":"3"}`), &b))
	require.Error(t, json.Unmarshal([]byte(`[1,2]`), &b))
}

func TestHistogramBucket_UnmarshalNullOrMissingLeavesValue(t *testing.T) {
	b := metrics.HistogramBucket{UpperBound: 0.5, CumulativeCount: 9}
	require.NoError(t, json.Unmarshal([]byte(`{"upperBound":null}`), &b))
	assert.Equal(t, metrics.HistogramBucket{UpperBound: 0.5, CumulativeCount: 9}, b)

	require.NoError(t, json.Unmarshal([]byte(`null`), &b))
	assert.Equal(t, metrics.HistogramBucket{UpperBound: 0.5, CumulativeCount: 9}, b)

	var fresh metrics.HistogramBucket
	require.NoError(t, json.Unmarshal([]byte(`{}`), &fresh))
	assert.Equal(t, metrics.HistogramBucket{}, fresh)
}

func TestHistogramBucket_NaNBoundStillFailsToEncode(t *testing.T) {
	_, err := json.Marshal(metrics.HistogramBucket{UpperBound: math.NaN()})
	require.Error(t, err)
}

func TestSnapshot_EncodesWithInfBuckets(t *testing.T) {
	inf := []metrics.HistogramBucket{{UpperBound: 0.1, CumulativeCount: 2}, {UpperBound: math.Inf(1), CumulativeCount: 4}}
	snap := metrics.Snapshot{Metrics: metrics.MetricsSnapshot{
		DurationBuckets: inf,
		Hosts:           map[string]*metrics.HostMetrics{"a.test": {Host: "a.test", DurationBuckets: inf, TTFBBuckets: inf}},
	}}

	data, err := json.Marshal(snap)
	require.NoError(t, err, "a snapshot with a +Inf bucket used to fail with json: unsupported value")

	var decoded metrics.Snapshot
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.True(t, math.IsInf(decoded.Metrics.DurationBuckets[1].UpperBound, 1))
	assert.True(t, math.IsInf(decoded.Metrics.Hosts["a.test"].TTFBBuckets[1].UpperBound, 1))
}
