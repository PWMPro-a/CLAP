package wsrelay

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestManagerConcurrentResponsesRemainCorrelated(t *testing.T) {
	mgr := NewManager(Options{
		Path: "/v1/ws",
		ProviderFactory: func(*http.Request) (string, error) {
			return "provider-a", nil
		},
	})
	server := httptest.NewServer(mgr.Handler())
	defer server.Close()
	defer mgr.Stop(context.Background())

	conn, _, errDial := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/ws", nil)
	if errDial != nil {
		t.Fatalf("dial relay websocket: %v", errDial)
	}
	defer conn.Close()

	providerErr := make(chan error, 1)
	go func() {
		requests := make([]Message, 0, 2)
		for len(requests) < 2 {
			var msg Message
			if errRead := conn.ReadJSON(&msg); errRead != nil {
				providerErr <- errRead
				return
			}
			if msg.Type == MessageTypeHTTPReq {
				requests = append(requests, msg)
			}
		}
		for i := len(requests) - 1; i >= 0; i-- {
			requestBody, _ := requests[i].Payload["body"].(string)
			if errWrite := conn.WriteJSON(Message{
				ID:   requests[i].ID,
				Type: MessageTypeHTTPResp,
				Payload: map[string]any{
					"status": float64(http.StatusOK),
					"body":   "response-for-" + requestBody,
				},
			}); errWrite != nil {
				providerErr <- errWrite
				return
			}
		}
		providerErr <- nil
	}()

	deadline := time.Now().Add(2 * time.Second)
	for mgr.session("provider-a") == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if mgr.session("provider-a") == nil {
		t.Fatal("provider websocket was not registered")
	}

	type outcome struct {
		request string
		body    string
		err     error
	}
	outcomes := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for _, requestBody := range []string{"request-a", "request-b"} {
		requestBody := requestBody
		go func() {
			start.Wait()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			resp, errRequest := mgr.NonStream(ctx, "provider-a", &HTTPRequest{
				Method: http.MethodPost,
				URL:    "https://upstream.example/v1/test",
				Body:   []byte(requestBody),
			})
			result := outcome{request: requestBody, err: errRequest}
			if resp != nil {
				result.body = string(resp.Body)
			}
			outcomes <- result
		}()
	}
	start.Done()

	for range 2 {
		result := <-outcomes
		if result.err != nil {
			t.Fatalf("request %s failed: %v", result.request, result.err)
		}
		want := fmt.Sprintf("response-for-%s", result.request)
		if result.body != want {
			t.Fatalf("request %s received %q, want %q", result.request, result.body, want)
		}
	}
	if errProvider := <-providerErr; errProvider != nil {
		t.Fatalf("provider relay failed: %v", errProvider)
	}
}

func TestPendingRequestCloseRacesWithDispatchSafely(t *testing.T) {
	for i := 0; i < 1000; i++ {
		req := newPendingRequest()
		started := make(chan struct{})
		done := make(chan struct{})
		go func() {
			close(started)
			_ = req.send(Message{ID: "request", Type: MessageTypeStreamChunk})
			close(done)
		}()
		<-started
		req.close()
		<-done
	}
}
