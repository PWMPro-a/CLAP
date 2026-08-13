package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type middlewareAccessProvider struct {
	result  *sdkaccess.Result
	authErr *sdkaccess.AuthError
}

func (p middlewareAccessProvider) Identifier() string { return "middleware-test" }

func (p middlewareAccessProvider) Authenticate(context.Context, *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	return p.result, p.authErr
}

func TestAccessAuthMiddlewareMarksAuthenticatedAppServerWithoutProviderName(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := sdkaccess.NewManager()
	manager.SetProviders([]sdkaccess.Provider{middlewareAccessProvider{result: &sdkaccess.Result{
		Principal: "static-api-key",
		Provider:  "",
	}}})

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	called := false

	accessAuthMiddleware(manager, false)(ctx)
	if !ctx.IsAborted() {
		called = true
	}

	if !called {
		t.Fatal("authenticated request did not continue")
	}
	if trusted, exists := ctx.Get(coreexecutor.CodexAppServerAuthenticatedContextKey); !exists || trusted != true {
		t.Fatalf("app-server authentication proof = %v, exists=%v", trusted, exists)
	}
}

func TestAccessAuthMiddlewareDoesNotMarkEmptyAuthenticationResult(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := sdkaccess.NewManager()
	manager.SetProviders([]sdkaccess.Provider{middlewareAccessProvider{result: nil}})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	accessAuthMiddleware(manager, false)(ctx)

	if trusted, exists := ctx.Get(coreexecutor.CodexAppServerAuthenticatedContextKey); exists {
		t.Fatalf("empty authentication result created proof: %v", trusted)
	}
}

func TestAccessAuthMiddlewareDoesNotMarkEmptyPrincipal(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := sdkaccess.NewManager()
	manager.SetProviders([]sdkaccess.Provider{middlewareAccessProvider{result: &sdkaccess.Result{
		Principal: "  ",
		Provider:  "provider",
	}}})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	accessAuthMiddleware(manager, false)(ctx)

	if trusted, exists := ctx.Get(coreexecutor.CodexAppServerAuthenticatedContextKey); exists {
		t.Fatalf("empty principal created proof: %v", trusted)
	}
}

func TestAccessAuthMiddlewareIgnoresClientAppServerHeader(t *testing.T) {
	gin.SetMode(gin.TestMode)
	manager := sdkaccess.NewManager()
	manager.SetProviders([]sdkaccess.Provider{middlewareAccessProvider{
		authErr: sdkaccess.NewInvalidCredentialError(),
	}})

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ctx.Request.Header.Set("X-CPA-Codex-App-Server", "true")
	accessAuthMiddleware(manager, false)(ctx)

	if !ctx.IsAborted() {
		t.Fatal("invalid request was not aborted")
	}
	if trusted, exists := ctx.Get(coreexecutor.CodexAppServerAuthenticatedContextKey); exists {
		t.Fatalf("client header created proof: %v", trusted)
	}
}
