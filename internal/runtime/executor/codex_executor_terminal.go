package executor

import (
	"bytes"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const codexIncompleteStreamMessage = "stream error: stream disconnected before completion: stream closed before response.completed"

type codexIncompleteStreamError struct {
	statusErr
}

func newCodexIncompleteStreamError() codexIncompleteStreamError {
	return codexIncompleteStreamError{statusErr: statusErr{
		code: http.StatusRequestTimeout,
		msg:  codexIncompleteStreamMessage,
	}}
}

func (codexIncompleteStreamError) IsRequestScoped() bool {
	return true
}

// Streamed Codex responses may emit response.output_item.done events while leaving
// response.completed.response.output empty. Keep the stream path aligned with the
// already-patched non-stream path by reconstructing response.output from those items.
func collectCodexOutputItemDone(eventData []byte, outputItemsByIndex map[int64][]byte, outputItemsFallback *[][]byte) {
	itemResult := gjson.GetBytes(eventData, "item")
	if !itemResult.Exists() || itemResult.Type != gjson.JSON {
		return
	}
	outputIndexResult := gjson.GetBytes(eventData, "output_index")
	if outputIndexResult.Exists() {
		outputItemsByIndex[outputIndexResult.Int()] = []byte(itemResult.Raw)
		return
	}
	*outputItemsFallback = append(*outputItemsFallback, []byte(itemResult.Raw))
}

type codexOutputTextAccumulator struct {
	byOutput map[int64]*codexOutputTextItem
	byItem   map[string]*codexOutputTextItem
	order    []string
	fallback *codexOutputTextItem
}

type codexOutputTextItem struct {
	id       string
	parts    map[int64]*strings.Builder
	partKeys []int64
}

func collectCodexOutputTextEvent(eventData []byte, acc *codexOutputTextAccumulator) {
	if acc == nil {
		return
	}
	eventType := strings.TrimSpace(gjson.GetBytes(eventData, "type").String())
	if eventType != "response.output_text.delta" && eventType != "response.output_text.done" {
		return
	}
	textPath := "delta"
	if eventType == "response.output_text.done" {
		textPath = "text"
	}
	text := gjson.GetBytes(eventData, textPath).String()
	if text == "" && eventType == "response.output_text.done" {
		text = gjson.GetBytes(eventData, "delta").String()
	}
	if text == "" {
		return
	}
	item := acc.itemForEvent(eventData)
	if item == nil {
		return
	}
	contentIndex := int64(0)
	if result := gjson.GetBytes(eventData, "content_index"); result.Exists() {
		contentIndex = result.Int()
	}
	if item.parts == nil {
		item.parts = make(map[int64]*strings.Builder)
	}
	part := item.parts[contentIndex]
	if part == nil {
		part = &strings.Builder{}
		item.parts[contentIndex] = part
		item.partKeys = append(item.partKeys, contentIndex)
	}
	if eventType == "response.output_text.done" {
		part.Reset()
		part.WriteString(text)
		return
	}
	part.WriteString(text)
}

func (acc *codexOutputTextAccumulator) itemForEvent(eventData []byte) *codexOutputTextItem {
	if acc == nil {
		return nil
	}
	itemID := strings.TrimSpace(gjson.GetBytes(eventData, "item_id").String())
	if outputIndex := gjson.GetBytes(eventData, "output_index"); outputIndex.Exists() {
		if acc.byOutput == nil {
			acc.byOutput = make(map[int64]*codexOutputTextItem)
		}
		idx := outputIndex.Int()
		item := acc.byOutput[idx]
		if item == nil {
			item = &codexOutputTextItem{}
			acc.byOutput[idx] = item
		}
		if item.id == "" {
			item.id = itemID
		}
		return item
	}
	if itemID != "" {
		if acc.byItem == nil {
			acc.byItem = make(map[string]*codexOutputTextItem)
		}
		item := acc.byItem[itemID]
		if item == nil {
			item = &codexOutputTextItem{id: itemID}
			acc.byItem[itemID] = item
			acc.order = append(acc.order, itemID)
		}
		return item
	}
	if acc.fallback == nil {
		acc.fallback = &codexOutputTextItem{}
	}
	return acc.fallback
}

func (acc *codexOutputTextAccumulator) outputItems() [][]byte {
	if acc == nil {
		return nil
	}
	items := make([][]byte, 0, len(acc.byOutput)+len(acc.byItem)+1)
	indexes := make([]int64, 0, len(acc.byOutput))
	for idx := range acc.byOutput {
		indexes = append(indexes, idx)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	for _, idx := range indexes {
		if raw := buildCodexOutputTextItem(acc.byOutput[idx]); len(raw) > 0 {
			items = append(items, raw)
		}
	}
	for _, itemID := range acc.order {
		if raw := buildCodexOutputTextItem(acc.byItem[itemID]); len(raw) > 0 {
			items = append(items, raw)
		}
	}
	if raw := buildCodexOutputTextItem(acc.fallback); len(raw) > 0 {
		items = append(items, raw)
	}
	return items
}

func buildCodexOutputTextItem(item *codexOutputTextItem) []byte {
	if item == nil || len(item.parts) == 0 {
		return nil
	}
	partKeys := append([]int64(nil), item.partKeys...)
	sort.Slice(partKeys, func(i, j int) bool { return partKeys[i] < partKeys[j] })
	var buf bytes.Buffer
	buf.WriteByte('{')
	if item.id != "" {
		buf.WriteString(`"id":`)
		buf.WriteString(strconv.Quote(item.id))
		buf.WriteByte(',')
	}
	buf.WriteString(`"type":"message","role":"assistant","status":"completed","content":[`)
	wrote := false
	for _, key := range partKeys {
		part := item.parts[key]
		if part == nil || part.String() == "" {
			continue
		}
		if wrote {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"type":"output_text","text":`)
		buf.WriteString(strconv.Quote(part.String()))
		buf.WriteByte('}')
		wrote = true
	}
	if !wrote {
		return nil
	}
	buf.WriteString(`]}`)
	return buf.Bytes()
}

func hydrateCodexCompletedOutputItemIDs(eventData []byte, outputItems []gjson.Result, outputItemsByIndex map[int64][]byte) []byte {
	patchedData := eventData
	for outputIndex, outputItem := range outputItems {
		itemData := []byte(outputItem.Raw)
		itemID := gjson.GetBytes(itemData, "id")
		if itemID.Exists() && itemID.Type != gjson.Null && (itemID.Type != gjson.String || strings.TrimSpace(itemID.String()) != "") {
			continue
		}

		completedItem, ok := outputItemsByIndex[int64(outputIndex)]
		if !ok {
			continue
		}
		completedID := gjson.GetBytes(completedItem, "id")
		if completedID.Type != gjson.String || strings.TrimSpace(completedID.String()) == "" {
			continue
		}

		updatedData, errSet := sjson.SetRawBytes(patchedData, "response.output."+strconv.Itoa(outputIndex)+".id", []byte(completedID.Raw))
		if errSet != nil {
			continue
		}
		patchedData = updatedData
	}
	return patchedData
}

func patchCodexCompletedOutput(eventData []byte, outputItemsByIndex map[int64][]byte, outputItemsFallback [][]byte) []byte {
	return patchCodexCompletedOutputWithText(eventData, outputItemsByIndex, outputItemsFallback, nil)
}

func patchCodexCompletedOutputWithText(eventData []byte, outputItemsByIndex map[int64][]byte, outputItemsFallback [][]byte, outputText *codexOutputTextAccumulator) []byte {
	outputResult := gjson.GetBytes(eventData, "response.output")
	textItems := outputText.outputItems()
	doneItems := codexCollectedOutputItems(outputItemsByIndex, outputItemsFallback)
	if len(doneItems) > 0 && !codexOutputItemsHaveVisibleMessageText(doneItems) && len(textItems) > 0 {
		doneItems = codexMergeOutputItemsWithBackfill(doneItems, textItems)
	}
	sourceItems := doneItems
	if len(sourceItems) == 0 {
		sourceItems = textItems
	}
	if !outputResult.Exists() || !outputResult.IsArray() || len(outputResult.Array()) == 0 {
		return codexSetCompletedOutput(eventData, sourceItems)
	}
	hydratedData := hydrateCodexCompletedOutputItemIDs(eventData, outputResult.Array(), outputItemsByIndex)
	hydratedOutput := gjson.GetBytes(hydratedData, "response.output")
	existingItems := codexOutputArrayItems(hydratedOutput)
	if codexOutputItemsHaveVisibleMessageText(existingItems) {
		return hydratedData
	}
	needsMessageBackfill := false
	for _, item := range existingItems {
		if codexOutputMessageItemEffectivelyEmpty(item) {
			needsMessageBackfill = true
			break
		}
	}
	if !needsMessageBackfill {
		return hydratedData
	}
	merged := codexMergeOutputItemsWithBackfill(existingItems, sourceItems)
	if len(merged) == 0 || codexOutputItemsEqual(existingItems, merged) {
		return hydratedData
	}
	return codexSetCompletedOutput(hydratedData, merged)
}

func codexCollectedOutputItems(byIndex map[int64][]byte, fallback [][]byte) [][]byte {
	indexes := make([]int64, 0, len(byIndex))
	for idx := range byIndex {
		indexes = append(indexes, idx)
	}
	sort.Slice(indexes, func(i, j int) bool { return indexes[i] < indexes[j] })
	items := make([][]byte, 0, len(byIndex)+len(fallback))
	for _, idx := range indexes {
		items = append(items, byIndex[idx])
	}
	return append(items, fallback...)
}

func codexOutputArrayItems(result gjson.Result) [][]byte {
	if !result.Exists() || !result.IsArray() {
		return nil
	}
	items := make([][]byte, 0, len(result.Array()))
	for _, item := range result.Array() {
		if item.Type == gjson.JSON && strings.TrimSpace(item.Raw) != "" {
			items = append(items, []byte(item.Raw))
		}
	}
	return items
}

func codexSetCompletedOutput(eventData []byte, items [][]byte) []byte {
	if len(items) == 0 {
		return eventData
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i, item := range items {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(item)
	}
	buf.WriteByte(']')
	patched, _ := sjson.SetRawBytes(eventData, "response.output", buf.Bytes())
	return patched
}

func codexMergeOutputItemsWithBackfill(existing, backfill [][]byte) [][]byte {
	items := make([][]byte, 0, len(existing)+len(backfill))
	seen := make(map[string]struct{}, len(existing)+len(backfill))
	appendItem := func(item []byte) {
		if len(bytes.TrimSpace(item)) == 0 || !codexOutputItemHasMeaningfulContent(item) {
			return
		}
		key := codexOutputItemDedupKey(item)
		if _, ok := seen[key]; key != "" && ok {
			return
		}
		if key != "" {
			seen[key] = struct{}{}
		}
		items = append(items, item)
	}
	for _, item := range existing {
		if !codexOutputMessageItemEffectivelyEmpty(item) {
			appendItem(item)
		}
	}
	for _, item := range backfill {
		appendItem(item)
	}
	return items
}

func codexOutputItemsHaveVisibleMessageText(items [][]byte) bool {
	for _, item := range items {
		if codexOutputMessageItemHasVisibleText(gjson.ParseBytes(item)) {
			return true
		}
	}
	return false
}

func codexOutputItemHasMeaningfulContent(item []byte) bool {
	result := gjson.ParseBytes(item)
	if !result.Exists() || result.Type != gjson.JSON {
		return false
	}
	return strings.TrimSpace(result.Get("type").String()) != "message" || !codexOutputMessageItemEffectivelyEmptyResult(result)
}

func codexOutputMessageItemEffectivelyEmpty(item []byte) bool {
	return codexOutputMessageItemEffectivelyEmptyResult(gjson.ParseBytes(item))
}

func codexOutputMessageItemEffectivelyEmptyResult(item gjson.Result) bool {
	if strings.TrimSpace(item.Get("type").String()) != "message" {
		return false
	}
	if codexOutputMessageItemHasVisibleText(item) {
		return false
	}
	content := item.Get("content")
	if !content.Exists() || content.Type == gjson.Null {
		return true
	}
	if content.Type == gjson.String {
		return strings.TrimSpace(content.String()) == ""
	}
	if !content.IsArray() {
		return strings.TrimSpace(content.Raw) == "" || content.Raw == "null"
	}
	if len(content.Array()) == 0 {
		return true
	}
	for _, part := range content.Array() {
		if codexOutputContentPartHasVisibleText(part) {
			return false
		}
		partType := strings.TrimSpace(part.Get("type").String())
		if partType != "" && partType != "output_text" && partType != "input_text" && partType != "text" && partType != "refusal" {
			if raw := strings.TrimSpace(part.Raw); raw != "" && raw != "{}" && raw != "null" {
				return false
			}
		}
	}
	return true
}

func codexOutputMessageItemHasVisibleText(item gjson.Result) bool {
	if item.Type != gjson.JSON {
		return false
	}
	itemType := strings.TrimSpace(item.Get("type").String())
	if itemType != "" && itemType != "message" && itemType != "output_text" {
		return false
	}
	if strings.TrimSpace(item.Get("text").String()) != "" || strings.TrimSpace(item.Get("output_text").String()) != "" || strings.TrimSpace(item.Get("refusal").String()) != "" {
		return true
	}
	content := item.Get("content")
	if content.Type == gjson.String {
		return strings.TrimSpace(content.String()) != ""
	}
	for _, part := range content.Array() {
		if codexOutputContentPartHasVisibleText(part) {
			return true
		}
	}
	return false
}

func codexOutputContentPartHasVisibleText(part gjson.Result) bool {
	if part.Type == gjson.String {
		return strings.TrimSpace(part.String()) != ""
	}
	if part.Type != gjson.JSON {
		return false
	}
	return strings.TrimSpace(part.Get("text").String()) != "" || strings.TrimSpace(part.Get("output_text").String()) != "" || strings.TrimSpace(part.Get("refusal").String()) != ""
}

func codexOutputItemDedupKey(item []byte) string {
	result := gjson.ParseBytes(item)
	itemType := strings.TrimSpace(result.Get("type").String())
	if id := strings.TrimSpace(result.Get("id").String()); id != "" {
		return itemType + ":id:" + id
	}
	if callID := strings.TrimSpace(result.Get("call_id").String()); callID != "" {
		return itemType + ":call:" + callID
	}
	return ""
}

func codexOutputItemsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(bytes.TrimSpace(a[i]), bytes.TrimSpace(b[i])) {
			return false
		}
	}
	return true
}

func codexTerminalStreamContextLengthErr(eventData []byte) (statusErr, bool) {
	streamErr, body, ok := codexTerminalStreamErr(eventData)
	if !ok || !codexTerminalErrorIsContextLength(body) {
		return statusErr{}, false
	}
	return streamErr, true
}

func codexTerminalStreamErr(eventData []byte) (statusErr, []byte, bool) {
	body, ok := codexTerminalFailureBody(eventData)
	if !ok || !codexTerminalStreamErrShouldHandle(body) {
		return statusErr{}, nil, false
	}
	return newCodexStatusErr(http.StatusBadRequest, body), body, true
}

func codexTerminalFailureErr(eventData []byte) (statusErr, []byte, bool) {
	if streamErr, body, ok := codexTerminalStreamErr(eventData); ok {
		return streamErr, body, true
	}
	body, ok := codexTerminalFailureBody(eventData)
	if !ok {
		return statusErr{}, nil, false
	}
	return newCodexStatusErr(codexTerminalFailureStatus(body), body), body, true
}

func codexTerminalFailureStatus(body []byte) int {
	for _, path := range []string{"error.status_code", "error.status"} {
		if status := int(gjson.GetBytes(body, path).Int()); status >= 400 && status <= 599 {
			return status
		}
	}

	errorType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.type").String()))
	errorCode := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.code").String()))
	switch {
	case errorCode == "cyber_policy":
		return http.StatusBadRequest
	case errorType == "invalid_request_error", errorType == "bad_request_error":
		return http.StatusBadRequest
	case errorType == "authentication_error", errorCode == "invalid_api_key", errorCode == "unauthorized":
		return http.StatusUnauthorized
	case errorType == "permission_error", errorCode == "forbidden", errorCode == "permission_denied":
		return http.StatusForbidden
	case errorType == "not_found_error", errorCode == "not_found", errorCode == "model_not_found":
		return http.StatusNotFound
	case errorType == "rate_limit_error", errorCode == "rate_limit_exceeded":
		return http.StatusTooManyRequests
	default:
		return http.StatusBadGateway
	}
}

func codexTerminalFailureBody(eventData []byte) ([]byte, bool) {
	eventType := gjson.GetBytes(eventData, "type").String()
	var body []byte
	switch eventType {
	case "error":
		body = codexTerminalErrorBody(eventData, "error")
		if len(body) == 0 {
			body = codexTerminalTopLevelErrorBody(eventData)
		}
	case "response.failed":
		body = codexTerminalErrorBody(eventData, "response.error")
		if len(body) == 0 {
			body = codexTerminalErrorBody(eventData, "error")
		}
	default:
		return nil, false
	}
	if len(body) == 0 {
		body = []byte(`{"error":{"message":"upstream stream failed without error details"}}`)
	}
	return body, true
}

func codexTerminalStreamErrShouldHandle(body []byte) bool {
	if codexTerminalErrorIsContextLength(body) {
		return true
	}
	if isCodexUsageLimitError(body) || isCodexModelCapacityError(body) {
		return true
	}
	code, _, ok := codexStatusErrorClassification(http.StatusBadRequest, body)
	return ok && code == "thinking_signature_invalid"
}

func codexTerminalErrorBody(eventData []byte, path string) []byte {
	errorResult := gjson.GetBytes(eventData, path)
	if !errorResult.Exists() {
		return nil
	}
	body := []byte(`{"error":{}}`)
	if errorResult.Type == gjson.JSON {
		body, _ = sjson.SetRawBytes(body, "error", []byte(errorResult.Raw))
	} else if message := strings.TrimSpace(errorResult.String()); message != "" {
		body, _ = sjson.SetBytes(body, "error.message", message)
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if message := strings.TrimSpace(gjson.GetBytes(eventData, "response.error.message").String()); message != "" {
			body, _ = sjson.SetBytes(body, "error.message", message)
		}
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if code := strings.TrimSpace(gjson.GetBytes(body, "error.code").String()); code != "" {
			body, _ = sjson.SetBytes(body, "error.message", code)
		}
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if errorType := strings.TrimSpace(gjson.GetBytes(body, "error.type").String()); errorType != "" {
			body, _ = sjson.SetBytes(body, "error.message", errorType)
		}
	}
	return body
}

func codexTerminalTopLevelErrorBody(eventData []byte) []byte {
	message := strings.TrimSpace(gjson.GetBytes(eventData, "message").String())
	code := strings.TrimSpace(gjson.GetBytes(eventData, "code").String())
	errorType := strings.TrimSpace(gjson.GetBytes(eventData, "error_type").String())
	param := strings.TrimSpace(gjson.GetBytes(eventData, "param").String())
	if message == "" && code == "" && errorType == "" && param == "" {
		return nil
	}

	body := []byte(`{"error":{}}`)
	if message != "" {
		body, _ = sjson.SetBytes(body, "error.message", message)
	}
	if code != "" {
		body, _ = sjson.SetBytes(body, "error.code", code)
	}
	if errorType != "" {
		body, _ = sjson.SetBytes(body, "error.type", errorType)
	}
	if param != "" {
		body, _ = sjson.SetBytes(body, "error.param", param)
	}
	if strings.TrimSpace(gjson.GetBytes(body, "error.message").String()) == "" {
		if code != "" {
			body, _ = sjson.SetBytes(body, "error.message", code)
		} else if errorType != "" {
			body, _ = sjson.SetBytes(body, "error.message", errorType)
		}
	}
	return body
}

func codexTerminalErrorIsContextLength(body []byte) bool {
	errorCode := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.code").String()))
	message := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.message").String()))
	return errorCode == "context_length_exceeded" ||
		errorCode == "context_too_large" ||
		strings.Contains(message, "context window") ||
		strings.Contains(message, "context length") ||
		strings.Contains(message, "too many tokens")
}

func newCodexStatusErr(statusCode int, body []byte) statusErr {
	errCode := statusCode
	if isCodexModelCapacityError(body) || isCodexUsageLimitError(body) {
		errCode = http.StatusTooManyRequests
	}
	body = classifyCodexStatusError(errCode, body)
	err := statusErr{code: errCode, msg: string(body)}
	if retryAfter := parseCodexRetryAfter(errCode, body, time.Now()); retryAfter != nil {
		err.retryAfter = retryAfter
	}
	return err
}

func classifyCodexStatusError(statusCode int, body []byte) []byte {
	code, errType, ok := codexStatusErrorClassification(statusCode, body)
	if !ok {
		return body
	}
	message := gjson.GetBytes(body, "error.message").String()
	if message == "" {
		message = gjson.GetBytes(body, "message").String()
	}
	if message == "" {
		message = strings.TrimSpace(string(body))
	}
	if message == "" {
		message = http.StatusText(statusCode)
	}
	out := []byte(`{"error":{}}`)
	out, _ = sjson.SetBytes(out, "error.message", message)
	out, _ = sjson.SetBytes(out, "error.type", errType)
	out, _ = sjson.SetBytes(out, "error.code", code)
	return out
}

func codexStatusErrorClassification(statusCode int, body []byte) (code string, errType string, ok bool) {
	errorMessage := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.message").String()))
	if errorMessage == "" {
		errorMessage = strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "message").String()))
	}
	lower := strings.ToLower(strings.TrimSpace(string(body)))
	upstreamCode := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.code").String()))
	upstreamType := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, "error.type").String()))
	isInvalidRequest := upstreamType == "" || upstreamType == "invalid_request_error"

	switch {
	case statusCode == http.StatusRequestEntityTooLarge || upstreamCode == "context_length_exceeded" || upstreamCode == "context_too_large" || isInvalidRequest && (strings.Contains(errorMessage, "context length") || strings.Contains(errorMessage, "context_length") || strings.Contains(errorMessage, "maximum context") || strings.Contains(errorMessage, "too many tokens")):
		return "context_too_large", "invalid_request_error", true
	case strings.Contains(lower, "invalid signature in thinking block") || strings.Contains(lower, "invalid_encrypted_content"):
		return "thinking_signature_invalid", "invalid_request_error", true
	case upstreamCode == "previous_response_not_found" || strings.Contains(lower, "previous_response_not_found") || strings.Contains(lower, "previous_response_id") && strings.Contains(lower, "not found"):
		return "previous_response_not_found", "invalid_request_error", true
	case statusCode == http.StatusUnauthorized || upstreamType == "authentication_error" || upstreamCode == "invalid_api_key" || strings.Contains(lower, "invalid or expired token") || strings.Contains(lower, "refresh_token_reused"):
		return "auth_unavailable", "authentication_error", true
	default:
		return "", "", false
	}
}

func isCodexModelCapacityError(errorBody []byte) bool {
	if len(errorBody) == 0 {
		return false
	}
	candidates := []string{
		gjson.GetBytes(errorBody, "error.message").String(),
		gjson.GetBytes(errorBody, "message").String(),
		string(errorBody),
	}
	for _, candidate := range candidates {
		lower := strings.ToLower(strings.TrimSpace(candidate))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "selected model is at capacity") ||
			strings.Contains(lower, "model is at capacity. please try a different model") {
			return true
		}
	}
	return false
}

// isCodexUsageLimitError reports whether the error body represents a Codex
// quota/plan-limit exhaustion (error.type == "usage_limit_reached"). This is the
// signal Codex emits when a credential's usage quota is depleted, and it carries
// reset timing (resets_at/resets_in_seconds) parsed by parseCodexRetryAfter.
// Transient per-minute rate limits (rate_limit_error/rate_limit_exceeded) are
// intentionally excluded, as they should be retried rather than cooled down.
func isCodexUsageLimitError(errorBody []byte) bool {
	if len(errorBody) == 0 {
		return false
	}
	candidates := []string{
		gjson.GetBytes(errorBody, "error.type").String(),
		gjson.GetBytes(errorBody, "type").String(),
	}
	for _, candidate := range candidates {
		if strings.EqualFold(strings.TrimSpace(candidate), "usage_limit_reached") {
			return true
		}
	}
	return false
}

func parseCodexRetryAfter(statusCode int, errorBody []byte, now time.Time) *time.Duration {
	if statusCode != http.StatusTooManyRequests || len(errorBody) == 0 {
		return nil
	}
	if strings.TrimSpace(gjson.GetBytes(errorBody, "error.type").String()) != "usage_limit_reached" {
		return nil
	}
	if resetsAt := gjson.GetBytes(errorBody, "error.resets_at").Int(); resetsAt > 0 {
		resetAtTime := time.Unix(resetsAt, 0)
		if resetAtTime.After(now) {
			retryAfter := resetAtTime.Sub(now)
			return &retryAfter
		}
	}
	if resetsInSeconds := gjson.GetBytes(errorBody, "error.resets_in_seconds").Int(); resetsInSeconds > 0 {
		retryAfter := time.Duration(resetsInSeconds) * time.Second
		return &retryAfter
	}
	return nil
}
