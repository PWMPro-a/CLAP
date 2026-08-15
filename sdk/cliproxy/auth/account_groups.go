package auth

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

func normalizeRuntimeGroupIDs(value any) []int64 {
	var values []any
	switch typed := value.(type) {
	case []any:
		values = typed
	case []int64:
		out := append([]int64(nil), typed...)
		return normalizePositiveGroupIDs(out)
	case []int:
		out := make([]int64, 0, len(typed))
		for _, item := range typed {
			out = append(out, int64(item))
		}
		return normalizePositiveGroupIDs(out)
	case []float64:
		out := make([]int64, 0, len(typed))
		for _, item := range typed {
			if item == float64(int64(item)) {
				out = append(out, int64(item))
			}
		}
		return normalizePositiveGroupIDs(out)
	default:
		return nil
	}

	out := make([]int64, 0, len(values))
	for _, item := range values {
		if id, ok := runtimeGroupID(item); ok {
			out = append(out, id)
		}
	}
	return normalizePositiveGroupIDs(out)
}

func runtimeGroupID(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), typed > 0
	case int64:
		return typed, typed > 0
	case float64:
		id := int64(typed)
		return id, typed == float64(id) && id > 0
	case json.Number:
		id, err := typed.Int64()
		return id, err == nil && id > 0
	case string:
		id, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64)
		return id, err == nil && id > 0
	default:
		return 0, false
	}
}

func normalizePositiveGroupIDs(ids []int64) []int64 {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[int64]struct{}, len(ids))
	out := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
