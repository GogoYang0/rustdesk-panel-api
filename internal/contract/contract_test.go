// Package contract 是契约测试基建：以 openapi.yaml 为准绳，
// 对 httptest 回放做请求与响应双向校验（kin-openapi openapi3filter）。
// M1 退出标准即"全部端点契约用例通过"。
package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"

	"github.com/rustdesk-panel/rustdesk-panel-api/internal/server"
	"github.com/rustdesk-panel/rustdesk-panel-api/internal/testutil"
)

var (
	specOnce sync.Once
	specDoc  *openapi3.T
	specErr  error
)

// loadSpec 加载并校验 openapi.yaml（单一契约源，进程内一次）。
func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	specOnce.Do(func() {
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromFile("../../openapi.yaml")
		if err != nil {
			specErr = fmt.Errorf("load openapi.yaml: %w", err)
			return
		}
		if err := doc.Validate(loader.Context); err != nil {
			specErr = fmt.Errorf("validate openapi.yaml: %w", err)
			return
		}
		// 清空 servers，使 FindRoute 与测试服务器 host 无关。
		doc.Servers = nil
		specDoc = doc
	})
	if specErr != nil {
		t.Fatalf("spec load failed: %v", specErr)
	}
	return specDoc
}

// contractServer = httptest.Server + kin-openapi 校验路由。
type contractServer struct {
	TS     *httptest.Server
	Doc    *openapi3.T
	Router routers.Router
}

// newContractServer 构建默认（仅系统端点）契约服务器。
// 域 handler 用例通过 newContractServerWith 注入完整路由。
func newContractServer(t *testing.T) *contractServer {
	t.Helper()
	return newContractServerWith(t, func() *server.Router {
		return server.NewRouter(server.RouterDeps{
			Logger:           testutil.TestLogger(),
			RateLimitEnabled: true,
		})
	})
}

// newContractServerWith 以自定义路由构建契约服务器（T04/T05 业务域用例）。
func newContractServerWith(t *testing.T, build func() *server.Router) *contractServer {
	t.Helper()
	doc := loadSpec(t)
	rt := build()
	ts := httptest.NewServer(rt.Handler())
	t.Cleanup(ts.Close)
	router, err := legacyrouter.NewRouter(doc)
	if err != nil {
		t.Fatalf("build openapi router: %v", err)
	}
	return &contractServer{TS: ts, Doc: doc, Router: router}
}

// sendAndValidate 发送原始请求并返回（req, 响应头, 响应体），
// 是 raw / postMultipart / invalid 的共用核心：
// 传输后重置 req.Body（ValidateRequest 会重新读取），并断言状态码。
func (cs *contractServer) sendAndValidate(t *testing.T, method, path, contentType string, rawBody []byte, headers map[string]string, expectStatus int) (*http.Request, http.Header, []byte) {
	t.Helper()

	var reader io.Reader
	if rawBody != nil {
		reader = bytes.NewReader(rawBody)
	}
	req, err := http.NewRequest(method, cs.TS.URL+path, reader)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := cs.TS.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	// ValidateRequest 会重新读取 req.Body；传输后 body 已耗尽，
	// 校验前重置为未读副本。
	if len(rawBody) > 0 {
		req.Body = io.NopCloser(bytes.NewReader(rawBody))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(rawBody)), nil }
	} else {
		req.Body = http.NoBody
		req.ContentLength = 0
	}

	if resp.StatusCode != expectStatus {
		t.Fatalf("%s %s status = %d, want %d (body: %s)", method, path, resp.StatusCode, expectStatus, respBytes)
	}
	return req, resp.Header, respBytes
}

// raw 发送原始请求并做请求/响应双向契约校验；
// body 为 any（JSON 序列化）、string（原样）或 nil。
func (cs *contractServer) raw(t *testing.T, method, path string, body any, headers map[string]string, expectStatus int) []byte {
	t.Helper()
	var rawBody []byte
	contentType := ""
	switch b := body.(type) {
	case nil:
	case string:
		rawBody = []byte(b)
		contentType = "text/plain"
	default:
		var err error
		rawBody, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		contentType = "application/json"
	}
	req, header, respBytes := cs.sendAndValidate(t, method, path, contentType, rawBody, headers, expectStatus)
	if err := cs.validatePair(req, expectStatus, header, respBytes); err != nil {
		t.Errorf("%v", err)
	}
	return respBytes
}

// multipartBytes 构造 multipart/form-data 原始字节，返回 Content-Type 与 body。
func multipartBytes(t *testing.T, field, filename string, content []byte) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

// postMultipart 上传 multipart 请求并做双向契约校验。
func (cs *contractServer) postMultipart(t *testing.T, path, field, filename string, content []byte, headers map[string]string, expectStatus int) []byte {
	t.Helper()
	contentType, rawBody := multipartBytes(t, field, filename, content)
	req, header, respBytes := cs.sendAndValidate(t, http.MethodPost, path, contentType, rawBody, headers, expectStatus)
	if err := cs.validatePair(req, expectStatus, header, respBytes); err != nil {
		t.Errorf("%v", err)
	}
	return respBytes
}

// invalid 发送故意违反请求契约的输入（format: email / minLength / 路径
// pattern 违规等），断言两道防线：(1) 契约校验器必须拒绝该请求；
// (2) 服务端防线仍以 expectStatus 错误包络拒绝（响应形状由
// assertEnvelopeShape 保证；请求违规时 validatePair 不会做响应校验）。
func (cs *contractServer) invalid(t *testing.T, method, path string, body any, headers map[string]string, expectStatus int) []byte {
	t.Helper()
	var rawBody []byte
	if body != nil {
		var err error
		rawBody, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
	}
	req, _, respBytes := cs.sendAndValidate(t, method, path, "application/json", rawBody, headers, expectStatus)
	assertEnvelopeShape(t, respBytes, expectStatus)
	if verr := cs.validatePair(req, expectStatus, nil, respBytes); verr == nil {
		t.Errorf("expected contract violation on %s %s, but validator accepted the request", method, path)
	}
	return respBytes
}

// get / post / patch / delete 是 raw 的便捷封装。
func (cs *contractServer) get(t *testing.T, path string, headers map[string]string, expectStatus int) []byte {
	return cs.raw(t, http.MethodGet, path, nil, headers, expectStatus)
}

func (cs *contractServer) post(t *testing.T, path string, body any, headers map[string]string, expectStatus int) []byte {
	return cs.raw(t, http.MethodPost, path, body, headers, expectStatus)
}

func (cs *contractServer) patch(t *testing.T, path string, body any, headers map[string]string, expectStatus int) []byte {
	return cs.raw(t, http.MethodPatch, path, body, headers, expectStatus)
}

func (cs *contractServer) delete(t *testing.T, path string, headers map[string]string, expectStatus int) []byte {
	return cs.raw(t, http.MethodDelete, path, nil, headers, expectStatus)
}

// contractAuthFunc security scheme 校验桩：bearerAuth 的真实语义
// （JWT 有状态校验）由业务层承担，契约层只关心形状，恒放行。
var contractAuthFunc openapi3filter.AuthenticationFunc = func(_ context.Context, _ *openapi3filter.AuthenticationInput) error {
	return nil
}

// validatePair 对请求与响应做双向校验，返回首个契约违规错误。
// 独立于 testing 失败机制，便于篡改用例断言"校验器必须失败"。
func (cs *contractServer) validatePair(req *http.Request, status int, header http.Header, body []byte) error {
	ctx := context.Background()

	route, params, err := cs.Router.FindRoute(req)
	if err != nil {
		return fmt.Errorf("no route in spec for %s %s: %w", req.Method, req.URL.Path, err)
	}
	reqInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		Route:      route,
		PathParams: params,
		Options:    &openapi3filter.Options{AuthenticationFunc: contractAuthFunc},
	}
	if err := openapi3filter.ValidateRequest(ctx, reqInput); err != nil {
		return fmt.Errorf("request contract violation on %s %s: %w", req.Method, req.URL.Path, err)
	}

	respInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: reqInput,
		Status:                 status,
		Header:                 header,
	}
	respInput.SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(ctx, respInput); err != nil {
		return fmt.Errorf("response contract violation on %s %s: %w", req.Method, req.URL.Path, err)
	}
	return nil
}

// assertEnvelopeShape 断言错误包络三字段存在且 statusCode/error 与预期一致。
func assertEnvelopeShape(t *testing.T, body []byte, wantStatus int) {
	t.Helper()
	var env struct {
		StatusCode int             `json:"statusCode"`
		Message    json.RawMessage `json:"message"`
		Error      string          `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("error body not json: %v (%s)", err, body)
	}
	if env.StatusCode != wantStatus {
		t.Errorf("statusCode = %d, want %d", env.StatusCode, wantStatus)
	}
	if env.Error == "" {
		t.Error("error field must be non-empty (NestJS shape)")
	}
	if len(env.Message) == 0 {
		t.Error("message field must exist")
	}
}
