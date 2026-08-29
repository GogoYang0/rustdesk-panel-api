package httpx

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"reflect"

	"github.com/go-playground/validator/v10"
)

// validate 是请求体校验器（validator v10，语义对齐 class-validator）。
var validate = validator.New(validator.WithRequiredStructEnabled())

// DecodeJSON 严格绑定 JSON 请求体：
//   - DisallowUnknownFields（对齐 forbidNonWhitelisted，未知字段拒绝）；
//   - validator v10 结构校验，失败输出 message 数组；
//   - JSON 语法/类型错误输出纯文本 message。
//
// 失败时已写出 400 并返回 (nil, false)。
func DecodeJSON[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	var body T
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		Fail(w, http.StatusBadRequest, "Invalid request body")
		return nil, false
	}
	if err := validate.Struct(body); err != nil {
		var verrs validator.ValidationErrors
		if errors.As(err, &verrs) {
			msgs := make([]string, 0, len(verrs))
			for _, ve := range verrs {
				msgs = append(msgs, validationMessage(ve))
			}
			ErrBadRequestMessages(w, msgs)
			return nil, false
		}
		// 非字段级错误（如指针必填缺失）也以数组形态输出。
		ErrBadRequestMessages(w, []string{err.Error()})
		return nil, false
	}
	return &body, true
}

// DecodeJSONOptional 可选 JSON 请求体绑定（M3 T07 扩展点）：
//   - 空体 / Content-Length 0 → 返回 (nil, true)，不写任何响应；
//   - 非空体走 DecodeJSON 的严格语义（未知字段拒绝 + validator）。
//
// 供 settings smtp/ldap test 端点使用（openapi requestBody required: false，
// 缺省用已存配置）。失败时已写出 400 并返回 (nil, false)。
func DecodeJSONOptional[T any](w http.ResponseWriter, r *http.Request) (*T, bool) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, true
	}
	return DecodeJSON[T](w, r)
}

// maxMultipartMemory 与 NestJS memory storage 行为对齐的内存缓冲上限。
const maxMultipartMemory = 32 << 20 // 32 MiB

// ParseMultipart 解析 multipart 表单；maxBytes 为整包大小上限。
// 失败时已写出 400 并返回 (nil, false)。
// 调用方用完须调用 form.RemoveAll 释放临时文件。
func ParseMultipart(w http.ResponseWriter, r *http.Request, maxBytes int64) (*multipart.Form, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseMultipartForm(maxMultipartMemory); err != nil {
		Fail(w, http.StatusBadRequest, "Invalid multipart body")
		return nil, false
	}
	if r.MultipartForm == nil {
		ErrBadRequest(w, "multipart form is required")
		return nil, false
	}
	return r.MultipartForm, true
}

// validationMessage 生成 class-validator 风格的错误文案（稳定契约，测试断言依赖）。
func validationMessage(ve validator.FieldError) string {
	field, param := ve.Field(), ve.Param()
	switch ve.Tag() {
	case "required":
		return fmt.Sprintf("%s should not be empty", field)
	case "min":
		if ve.Kind() == reflect.String {
			return fmt.Sprintf("%s must be longer than or equal to %s characters", field, param)
		}
		return fmt.Sprintf("%s must not be less than %s", field, param)
	case "max":
		if ve.Kind() == reflect.String {
			return fmt.Sprintf("%s must be shorter than or equal to %s characters", field, param)
		}
		return fmt.Sprintf("%s must not be greater than %s", field, param)
	case "email":
		return fmt.Sprintf("%s must be an email", field)
	case "oneof":
		return fmt.Sprintf("%s must be one of the following values: %s", field, param)
	case "gte":
		return fmt.Sprintf("%s must not be less than %s", field, param)
	case "lte":
		return fmt.Sprintf("%s must not be greater than %s", field, param)
	default:
		return fmt.Sprintf("%s failed %s validation", field, ve.Tag())
	}
}
