package metrics

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHistogramBucket_JSONRoundTrip(t *testing.T) {
	buckets := []HistogramBucket{
		{UpperBound: 0.25, CumulativeCount: 3},
		{UpperBound: math.Inf(1), CumulativeCount: 5},
	}

	data, err := json.Marshal(buckets)
	require.NoError(t, err, "encoding/json rejects +Inf unless the bucket encodes it itself")
	assert.JSONEq(t, `[{"upperBound":0.25,"cumulativeCount":3},{"upperBound":"+Inf","cumulativeCount":5}]`, string(data))

	var back []HistogramBucket
	require.NoError(t, json.Unmarshal(data, &back))
	assert.Equal(t, buckets, back)
}

func TestHistogramBucket_UnmarshalRejectsGarbageBound(t *testing.T) {
	var b HistogramBucket
	assert.Error(t, json.Unmarshal([]byte(`{"upperBound":"lots","cumulativeCount":1}`), &b))
}
