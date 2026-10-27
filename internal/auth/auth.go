package auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// ZeroBytes overwrites all bytes in the slice with zeroes to prevent key/password
// material from lingering in memory after use.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateTOTPCode derives a 6-digit RFC6238 TOTP code (SHA1, 30s step) from a Base32 secret.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if normalized == "" {
		return "", fmt.Errorf("空のTOTPシークレット")
	}
	if m := len(normalized) % 8; m != 0 {
		normalized += strings.Repeat("=", 8-m)
	}
	key, err := base32.StdEncoding.DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("base32デコード失敗: %w", err)
	}
	defer ZeroBytes(key)
	if len(key) == 0 {
		return "", fmt.Errorf("デコード後のキーが空")
	}

	counter := uint64(t.Unix()) / 30
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	h := hmac.New(sha1.New, key)
	h.Write(buf[:])
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	code %= 1000000

	return fmt.Sprintf("%06d", code), nil
}

// ResolveTOTPInput accepts either a 6-digit one-time TOTP code or a Base32 TOTP secret
// and returns the 6-digit code to send to Proton's 2FA endpoint.
func ResolveTOTPInput(input string, t time.Time) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("2FAコードまたはTOTPシークレットが空です")
	}
	if isSixDigits(trimmed) {
		return trimmed, nil
	}
	return GenerateTOTPCode(trimmed, t)
}

func isSixDigits(s string) bool {
	if len(s) != 6 {
		return false
	}
	for i := 0; i < 6; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
