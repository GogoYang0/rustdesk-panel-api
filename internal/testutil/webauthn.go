package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"

	cbor "github.com/fxamacker/cbor/v2"
)

// SoftAuthenticator 软件模拟 WebAuthn authenticator（测试专用）：
// ECDSA P-256 密钥 + "none" attestation，可精确控制签名计数器
// （覆盖 counter 回退拒绝场景）。
//
// 响应形状对齐 WebAuthn L3 客户端 JSON：base64url 无填充字符串，
// 与 go-webauthn protocol.URLEncodedBase64 解码兼容。
type SoftAuthenticator struct {
	RPID       string
	Origin     string
	UserHandle []byte
	CredID     []byte
	Key        *ecdsa.PrivateKey
	SignCount  uint32
}

// NewSoftAuthenticator 创建模拟器（credId 随机 32 字节，初始计数 0）。
func NewSoftAuthenticator(rpid, origin string, userHandle []byte) (*SoftAuthenticator, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, err
	}
	return &SoftAuthenticator{
		RPID: rpid, Origin: origin, UserHandle: userHandle,
		CredID: credID, Key: key,
	}, nil
}

// CredentialIDB64 返回 base64url（无填充）凭据 ID。
func (a *SoftAuthenticator) CredentialIDB64() string {
	return base64.RawURLEncoding.EncodeToString(a.CredID)
}

// CreateRegistrationResponse 构造 webauthn.create 注册响应
// （PublicKeyCredential JSON 形状，fmt=none）。
func (a *SoftAuthenticator) CreateRegistrationResponse(challenge string) (map[string]any, error) {
	clientDataJSON, err := json.Marshal(map[string]any{
		"type": "webauthn.create", "challenge": challenge,
		"origin": a.Origin, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	attObj, err := cbor.Marshal(map[string]any{
		"fmt": "none", "attStmt": map[string]any{},
		"authData": a.attestationAuthData(),
	})
	if err != nil {
		return nil, err
	}
	return publicKeyCredentialJSON(b64url(a.CredID), map[string]any{
		"clientDataJSON":    b64url(clientDataJSON),
		"attestationObject": b64url(attObj),
	}), nil
}

// CreateAssertionResponse 构造 webauthn.get 断言响应（计数器自增）。
func (a *SoftAuthenticator) CreateAssertionResponse(challenge string) (map[string]any, error) {
	a.SignCount++
	return a.CreateAssertionResponseWithCounter(challenge, a.SignCount)
}

// CreateAssertionResponseWithCounter 构造断言响应并以指定值写入签名计数器
// （克隆模拟：回放旧计数器）。
func (a *SoftAuthenticator) CreateAssertionResponseWithCounter(challenge string, counter uint32) (map[string]any, error) {
	clientDataJSON, err := json.Marshal(map[string]any{
		"type": "webauthn.get", "challenge": challenge,
		"origin": a.Origin, "crossOrigin": false,
	})
	if err != nil {
		return nil, err
	}
	authData := a.assertionAuthData(counter)
	clientHash := sha256.Sum256(clientDataJSON)
	sigInput := append(append([]byte{}, authData...), clientHash[:]...)
	digest := sha256.Sum256(sigInput)
	sig, err := ecdsa.SignASN1(rand.Reader, a.Key, digest[:])
	if err != nil {
		return nil, err
	}
	return publicKeyCredentialJSON(b64url(a.CredID), map[string]any{
		"clientDataJSON":    b64url(clientDataJSON),
		"authenticatorData": b64url(authData),
		"signature":         b64url(sig),
		"userHandle":        b64url(a.UserHandle),
	}), nil
}

// ---- 内部构造 ----

// attestationAuthData 注册 authenticatorData：
// rpIdHash || flags(UP|UV|BE|BS|AT) || signCount || aaguid || credId || COSE key。
func (a *SoftAuthenticator) attestationAuthData() []byte {
	a.SignCount++
	buf := make([]byte, 0, 128)
	buf = append(buf, a.rpIDHash()...)
	buf = append(buf, 0x5D) // UP|UV|BE|BS|AT
	buf = append(buf, counterBytes(a.SignCount)...)
	buf = append(buf, make([]byte, 16)...) // AAGUID（全零）
	buf = append(buf, uint16Bytes(len(a.CredID))...)
	buf = append(buf, a.CredID...)
	cose, err := cbor.Marshal(a.coseKey())
	if err != nil {
		// 构造错误直接 panic（测试工具，配置固定不会发生）。
		panic("testutil: marshal cose key: " + err.Error())
	}
	return append(buf, cose...)
}

// assertionAuthData 断言 authenticatorData：rpIdHash || flags || signCount。
// flags = UP|UV|BE|BS（0x1D）：与注册凭据的备份资格状态保持一致
// （go-webauthn 校验断言 BE 必须与凭据注册时一致）。
func (a *SoftAuthenticator) assertionAuthData(counter uint32) []byte {
	buf := make([]byte, 0, 37)
	buf = append(buf, a.rpIDHash()...)
	buf = append(buf, 0x1D) // UP|UV|BE|BS
	buf = append(buf, counterBytes(counter)...)
	return buf
}

// rpIDHash sha256(RPID)。
func (a *SoftAuthenticator) rpIDHash() []byte {
	sum := sha256.Sum256([]byte(a.RPID))
	return sum[:]
}

// coseKey EC2/P-256/ES256 COSE 公钥：{1:2, 3:-7, -1:1, -2:x, -3:y}。
func (a *SoftAuthenticator) coseKey() map[int32]any {
	// Go 1.26 起 PublicKey.X/Y 大数坐标访问已 deprecated：经 uncompressed
	// point 序列化（0x04 || X || Y，65 字节）拆出 32 字节大端坐标，
	// 与原 FillBytes(X/Y) 语义等价。
	raw, err := a.Key.PublicKey.Bytes()
	if err != nil {
		// 构造错误直接 panic（测试工具，P-256 固定不会发生）。
		panic("testutil: encode public key: " + err.Error())
	}
	return map[int32]any{
		1: int64(2), 3: int64(-7), -1: int64(1),
		-2: raw[1:33], -3: raw[33:65],
	}
}

// publicKeyCredentialJSON 组装 PublicKeyCredential 顶层形状。
func publicKeyCredentialJSON(id string, response map[string]any) map[string]any {
	return map[string]any{
		"id":       id,
		"rawId":    id,
		"type":     "public-key",
		"response": response,
		// 客户端扩展输出（go-webauthn 解析可选字段）。
		"clientExtensionResults":  map[string]any{},
		"authenticatorAttachment": "platform",
	}
}

// b64url base64url 无填充编码。
func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// counterBytes 大端 uint32。
func counterBytes(n uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return b[:]
}

// uint16Bytes 大端 uint16。
func uint16Bytes(n int) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(n))
	return b[:]
}
