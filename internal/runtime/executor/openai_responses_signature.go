package executor

import (
	"context"
	"fmt"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/signature"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func sanitizeOpenAIResponsesReasoningEncryptedContent(ctx context.Context, provider string, body []byte) []byte {
	inputResult := gjson.GetBytes(body, "input")
	if !inputResult.Exists() || !inputResult.IsArray() {
		return body
	}
	provider = strings.TrimSpace(provider)
	if provider == "" {
		provider = "openai responses upstream"
	}

	// Codex backend rejects store=true and does not persist items when store=false.
	// A reasoning item that still carries an id without usable encrypted_content is
	// treated as a store lookup and returns:
	//   Item with id '...' not found. Items are not persisted when `store` is set to false.
	// Strip those orphan ids unless the request explicitly opts into store=true.
	stripOrphanReasoningIDs := !gjson.GetBytes(body, "store").Bool()

	items := inputResult.Array()

	// rebuilt accumulates the edited "input" array as JSON array bytes. It
	// stays nil while no item needs editing so the common case (nothing to
	// sanitize) does no allocation or rebuilding. Edits are applied directly
	// to each item's own raw JSON rather than re-parsing the whole body,
	// keeping the cost proportional to the item being edited.
	var rebuilt []byte
	itemsWritten := 0
	keep := func(raw string) {
		if rebuilt == nil {
			return
		}
		if itemsWritten > 0 {
			rebuilt = append(rebuilt, ',')
		}
		rebuilt = append(rebuilt, raw...)
		itemsWritten++
	}
	startRebuild := func(index int) {
		if rebuilt != nil {
			return
		}
		// First item that needs editing: start the buffer and backfill
		// it with the raw JSON of every preceding item.
		rebuilt = make([]byte, 0, len(inputResult.Raw))
		rebuilt = append(rebuilt, '[')
		for i := range index {
			keep(items[i].Raw)
		}
	}

	for index, item := range items {
		itemType := strings.TrimSpace(item.Get("type").String())
		itemRaw := item.Raw
		itemChanged := false
		role := strings.ToLower(strings.TrimSpace(item.Get("role").String()))
		content := item.Get("content")
		if content.Exists() && content.IsArray() {
			textPartType := "input_text"
			if role == "assistant" {
				textPartType = "output_text"
			}
			for contentIndex, part := range content.Array() {
				if strings.TrimSpace(part.Get("type").String()) != "text" {
					continue
				}
				nextItem, err := sjson.Set(itemRaw, fmt.Sprintf("content.%d.type", contentIndex), textPartType)
				if err != nil {
					helps.LogWithRequestID(ctx).Debugf("%s: failed to normalize legacy text content at input[%d].content[%d]: %v", provider, index, contentIndex, err)
					continue
				}
				itemRaw = nextItem
				itemChanged = true
				helps.LogWithRequestID(ctx).Debugf("%s: normalized legacy text content at input[%d].content[%d] role=%q", provider, index, contentIndex, role)
			}
		}
		keepCurrentItem := func() {
			if itemChanged {
				startRebuild(index)
			}
			keep(itemRaw)
		}

		itemIDResult := item.Get("id")
		itemID := strings.TrimSpace(itemIDResult.String())
		if itemType != "reasoning" && itemIDResult.Exists() && strings.HasPrefix(itemID, "item_") {
			var (
				nextItem string
				err      error
			)

			switch itemType {
			case "message":
				// Historical Responses transcripts can contain item_* IDs on message
				// items. Codex expects a msg_* ID (or no ID for an input message).
				nextItem, err = sjson.Delete(itemRaw, "id")
				if err == nil {
					helps.LogWithRequestID(ctx).Debugf("%s: dropped invalid historical message id at input[%d] item_id=%q", provider, index, itemID)
				}
			case "function_call", "function_call_output", "custom_tool_call", "custom_tool_call_output":
				// Older Responses transcripts use item_* for tool items. The Codex
				// backend validates a type-specific ID prefix. Preserve the suffix and
				// call_id so tool result items remain tied to their invocation.
				prefix := map[string]string{
					"function_call":           "fc_",
					"function_call_output":    "fco_",
					"custom_tool_call":        "ctc_",
					"custom_tool_call_output": "ctco_",
				}[itemType]
				nextItem, err = sjson.Set(itemRaw, "id", prefix+strings.TrimPrefix(itemID, "item_"))
				if err == nil {
					helps.LogWithRequestID(ctx).Debugf("%s: normalized legacy %s id at input[%d] item_id=%q", provider, itemType, index, itemID)
				}
			default:
				keepCurrentItem()
				continue
			}

			if err != nil {
				helps.LogWithRequestID(ctx).Debugf("%s: failed to sanitize historical %s id at input[%d]: %v", provider, itemType, index, err)
				keepCurrentItem()
				continue
			}
			startRebuild(index)
			keep(nextItem)
			continue
		}
		if itemType != "reasoning" {
			keepCurrentItem()
			continue
		}

		encryptedContent := item.Get("encrypted_content")
		itemID = strings.TrimSpace(item.Get("id").String())
		legacyReasoningID := strings.HasPrefix(itemID, "item_")
		if itemID == "" {
			itemID = fmt.Sprintf("input[%d]", index)
		}

		if !encryptedContent.Exists() {
			if stripOrphanReasoningIDs && item.Get("id").Exists() {
				nextItem, err := sjson.Delete(itemRaw, "id")
				if err != nil {
					helps.LogWithRequestID(ctx).Debugf("%s: failed to drop orphan reasoning id at input[%d]: %v", provider, index, err)
					keepCurrentItem()
					continue
				}
				startRebuild(index)
				keep(nextItem)
				helps.LogWithRequestID(ctx).Debugf("%s: dropped orphan reasoning id at input[%d] item_id=%q reason=missing encrypted_content with store disabled", provider, index, itemID)
				continue
			}
			if legacyReasoningID {
				nextItem, err := sjson.Set(itemRaw, "id", "rs_"+strings.TrimPrefix(itemID, "item_"))
				if err != nil {
					helps.LogWithRequestID(ctx).Debugf("%s: failed to normalize orphan reasoning id at input[%d]: %v", provider, index, err)
					keepCurrentItem()
					continue
				}
				startRebuild(index)
				keep(nextItem)
				helps.LogWithRequestID(ctx).Debugf("%s: normalized legacy orphan reasoning id at input[%d] item_id=%q", provider, index, itemID)
				continue
			}
			keepCurrentItem()
			continue
		}

		reason := ""
		switch encryptedContent.Type {
		case gjson.String:
			rawSignature := encryptedContent.String()
			if rawSignature != strings.TrimSpace(rawSignature) {
				reason = "encrypted_content has leading or trailing whitespace"
			} else if _, err := signature.InspectGPTReasoningSignature(rawSignature); err != nil {
				reason = err.Error()
			}
		case gjson.Null:
			reason = "encrypted_content is null"
		default:
			reason = fmt.Sprintf("encrypted_content must be a string, got %s", encryptedContent.Type.String())
		}
		if reason == "" {
			if legacyReasoningID {
				nextItem, err := sjson.Set(itemRaw, "id", "rs_"+strings.TrimPrefix(itemID, "item_"))
				if err != nil {
					helps.LogWithRequestID(ctx).Debugf("%s: failed to normalize legacy reasoning id at input[%d]: %v", provider, index, err)
					keepCurrentItem()
					continue
				}
				startRebuild(index)
				keep(nextItem)
				helps.LogWithRequestID(ctx).Debugf("%s: normalized legacy reasoning id at input[%d] item_id=%q", provider, index, itemID)
				continue
			}
			keepCurrentItem()
			continue
		}

		nextItem, err := sjson.Delete(itemRaw, "encrypted_content")
		if err != nil {
			helps.LogWithRequestID(ctx).Debugf("%s: failed to drop invalid reasoning encrypted_content at input[%d]: %v", provider, index, err)
			keepCurrentItem()
			continue
		}
		if stripOrphanReasoningIDs && item.Get("id").Exists() {
			if nextID, errID := sjson.Delete(nextItem, "id"); errID != nil {
				helps.LogWithRequestID(ctx).Debugf("%s: failed to drop reasoning id after invalid encrypted_content at input[%d]: %v", provider, index, errID)
			} else {
				nextItem = nextID
			}
		} else if legacyReasoningID {
			if nextID, errID := sjson.Set(nextItem, "id", "rs_"+strings.TrimPrefix(itemID, "item_")); errID != nil {
				helps.LogWithRequestID(ctx).Debugf("%s: failed to normalize reasoning id after invalid encrypted_content at input[%d]: %v", provider, index, errID)
			} else {
				nextItem = nextID
			}
		}

		startRebuild(index)
		keep(nextItem)

		helps.LogWithRequestID(ctx).Debugf("%s: dropped invalid reasoning encrypted_content at input[%d] item_id=%q reason=%s", provider, index, itemID, reason)
	}

	if rebuilt == nil {
		return body
	}
	rebuilt = append(rebuilt, ']')

	updated, err := sjson.SetRawBytes(body, "input", rebuilt)
	if err != nil {
		helps.LogWithRequestID(ctx).Debugf("%s: failed to rebuild input array while sanitizing reasoning encrypted_content: %v", provider, err)
		return body
	}
	return updated
}
