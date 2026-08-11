package logging

import (
	"context"
	"net/http"
	"testing"
)

func TestRoutingUsageMetadataOnlyEnrichesUsageHeaderSnapshot(t *testing.T) {
	ctx := WithResponseHeadersHolder(context.Background())
	downstreamHeaders := http.Header{"Content-Type": []string{"text/event-stream"}}
	SetResponseHeaders(ctx, downstreamHeaders)
	SetRoutingUsageMetadata(ctx, RoutingUsageMetadata{
		AffinityOutcome:      "cache_hit",
		SessionSource:        "pck",
		BindingGeneration:    3,
		QuotaUsedPercent:     81.25,
		QuotaSnapshotPresent: true,
		PCKShadowSampled:     true,
		PCKOriginalHash:      "original",
		PCKContextRootHash:   "context",
		PCKPrefixGeneration:  "prefix",
	})

	usageHeaders := GetResponseHeaders(ctx)
	if usageHeaders.Get("X-Cpa-Affinity-Outcome") != "cache_hit" || usageHeaders.Get("X-Cpa-Binding-Generation") != "3" {
		t.Fatalf("usage routing headers = %#v", usageHeaders)
	}
	if usageHeaders.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("response content type was lost: %#v", usageHeaders)
	}
	if downstreamHeaders.Get("X-Cpa-Affinity-Outcome") != "" {
		t.Fatalf("internal routing metadata leaked into downstream headers: %#v", downstreamHeaders)
	}
}
