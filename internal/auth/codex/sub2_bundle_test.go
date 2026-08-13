package codex

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSub2Bundle(t *testing.T) {
	payload, err := json.Marshal(map[string]any{
		"type": "sub2api-data",
		"accounts": []map[string]any{
			{
				"name":        "pro-one",
				"type":        "oauth",
				"platform":    "openai",
				"priority":    2,
				"concurrency": 10,
				"credentials": map[string]any{
					"access_token":       "access-one",
					"refresh_token":      "refresh-one",
					"chatgpt_account_id": "account-one",
					"email":              "one@example.com",
					"plan_type":          "pro",
				},
				"extra": map[string]any{
					"proxy_url":      "http://proxy.example",
					"email_password": "must-not-copy",
					"last_refresh":   1780000000,
					"openai_oauth_responses_websockets_v2_enabled": true,
				},
			},
			{
				"name":     "team-two",
				"type":     "oauth",
				"platform": "openai",
				"credentials": map[string]any{
					"type":                 "codex",
					"auth_mode":            "personalAccessToken",
					"session_access_token": "access-two",
					"account_id":           "account-one",
					"email":                "two@example.com",
					"disabled":             true,
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	files, handled, err := ParseSub2Bundle(payload)
	if err != nil || !handled {
		t.Fatalf("ParseSub2Bundle() handled=%v err=%v", handled, err)
	}
	if len(files) != 2 {
		t.Fatalf("files = %d, want 2", len(files))
	}
	if files[0].FileName == files[1].FileName {
		t.Fatal("stable filenames must differ across accounts")
	}
	for _, file := range files {
		if !strings.HasPrefix(file.FileName, "codex-sub2-") || !strings.HasSuffix(file.FileName, ".json") {
			t.Fatalf("unexpected generated filename %q", file.FileName)
		}
		if file.Metadata["type"] != "codex" || file.Metadata["import_format"] != Sub2ImportFormat {
			t.Fatalf("canonical metadata is missing Sub2 Codex fields")
		}
		if _, copied := file.Metadata["email_password"]; copied {
			t.Fatal("unrelated Sub2 extra credentials must not be copied")
		}
	}
	if files[0].Metadata["account_id"] != "account-one" {
		t.Fatalf("account_id = %#v, want chatgpt account id fallback", files[0].Metadata["account_id"])
	}
	if files[0].Metadata["priority"] != float64(2) || files[0].Metadata["max_concurrency"] != float64(10) {
		t.Fatalf("Sub2 scheduling metadata was not preserved")
	}
	if files[0].Metadata["proxy_url"] != "http://proxy.example" {
		t.Fatalf("proxy_url = %#v", files[0].Metadata["proxy_url"])
	}
	if files[0].Metadata["last_refresh"] != float64(1780000000) || files[0].Metadata["websockets"] != true {
		t.Fatalf("Sub2 runtime metadata was not preserved")
	}
	if files[1].Metadata["access_token"] != "access-two" || files[1].Metadata["disabled"] != true {
		t.Fatalf("personal access token metadata was not normalized")
	}
}

func TestParseSub2BundleWithoutRootMarker(t *testing.T) {
	payload := []byte(`{"accounts":[{"type":"oauth","platform":"openai","credentials":{"access_token":"access","refresh_token":"refresh","email":"user@example.com"}}]}`)
	files, handled, err := ParseSub2Bundle(payload)
	if err != nil || !handled || len(files) != 1 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
}

func TestParseSub2BundlePinsAuthoritativeTeamOverGenericFree(t *testing.T) {
	payload := []byte(`{"type":"sub2api-data","accounts":[{"type":"oauth","platform":"openai","credentials":{"access_token":"access","refresh_token":"refresh","email":"team@example.com","plan_type":"free","chatgpt_plan_type":"team"}}]}`)
	files, handled, err := ParseSub2Bundle(payload)
	if err != nil || !handled || len(files) != 1 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
	metadata := files[0].Metadata
	if metadata["plan_type"] != "team" || metadata["chatgpt_plan_type"] != "team" {
		t.Fatalf("normalized plan metadata = %#v", metadata)
	}
	if metadata["codex_plan_type_pinned"] != true {
		t.Fatalf("codex_plan_type_pinned = %#v, want true", metadata["codex_plan_type_pinned"])
	}
}

func TestParseSub2BundleRejectsMixedProviders(t *testing.T) {
	payload := []byte(`{"type":"sub2api-data","accounts":[{"type":"oauth","platform":"openai","credentials":{"access_token":"access"}},{"type":"oauth","platform":"anthropic","credentials":{"access_token":"other"}}]}`)
	files, handled, err := ParseSub2Bundle(payload)
	if err == nil || !handled || len(files) != 0 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
}

func TestParseSub2BundleIgnoresNativeAuthFile(t *testing.T) {
	files, handled, err := ParseSub2Bundle([]byte(`{"type":"codex","access_token":"access"}`))
	if err != nil || handled || len(files) != 0 {
		t.Fatalf("files=%d handled=%v err=%v", len(files), handled, err)
	}
}
