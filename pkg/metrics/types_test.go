package metrics_test

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/alexandre-daubois/ember/pkg/metrics"
)

func TestHistogramBucket_JSONRoundTripWithInf(t *testing.T) {
	buckets := []metrics.HistogramBucket{
		{UpperBound: 0.25, CumulativeCount: 3},
		{UpperBound: math.Inf(1), CumulativeCount: 5},
	}

	data, err := json.Marshal(buckets)
	require.NoError(t, err)
	assert.JSONEq(t, `[{"upperBound":0.25,"cumulativeCount":3},{"upperBound":"+Inf","cumulativeCount":5}]`, string(data))

	var decoded []metrics.HistogramBucket
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded, 2)
	assert.Equal(t, buckets[0], decoded[0])
	assert.True(t, math.IsInf(decoded[1].UpperBound, 1))
	assert.InDelta(t, 5.0, decoded[1].CumulativeCount, 0)
}

// plainBucket is HistogramBucket as it encoded before its JSON methods.
type plainBucket struct {
	UpperBound      float64 `json:"upperBound"`
	CumulativeCount float64 `json:"cumulativeCount"`
}

func TestHistogramBucket_FiniteBoundsEncodeUnchanged(t *testing.T) {
	for _, ub := range []float64{0, 5e-324, 0.005, 0.25, 60, 1e21, -3.5, math.MaxFloat64} {
		got, err := json.Marshal(metrics.HistogramBucket{UpperBound: ub, CumulativeCount: 42.5})
		require.NoError(t, err)
		want, err := json.Marshal(plainBucket{UpperBound: ub, CumulativeCount: 42.5})
		require.NoError(t, err)
		assert.Equal(t, string(want), string(got), "upperBound %v", ub)

		var decoded metrics.HistogramBucket
		require.NoError(t, json.Unmarshal(got, &decoded))
		assert.InDelta(t, ub, decoded.UpperBound, 0)
	}
}

func TestHistogramBucket_UnmarshalRejectsOtherValues(t *testing.T) {
	for _, v := range []string{`"inf"`, `"-Inf"`, `"1.5"`, `true`} {
		var b metrics.HistogramBucket
		require.Error(t, json.Unmarshal([]byte(`{"upperBound":`+v+`}`), &b), "upperBound %s", v)
	}
}

func TestHistogramBucket_UnmarshalNullOrMissingLeavesValue(t *testing.T) {
	b := metrics.HistogramBucket{UpperBound: 0.5, CumulativeCount: 9}
	require.NoError(t, json.Unmarshal([]byte(`null`), &b))
	require.NoError(t, json.Unmarshal([]byte(`{"upperBound":null}`), &b))
	assert.Equal(t, metrics.HistogramBucket{UpperBound: 0.5, CumulativeCount: 9}, b)
}
