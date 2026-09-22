package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// ComputeHMAC generates a hex-encoded HMAC-SHA256 signature for a payload.
func ComputeHMAC(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC compares a provided hex signature with the expected HMAC-SHA256 using constant-time comparison.
func VerifyHMAC(secret string, payload []byte, providedHexSig string) bool {
	sigBytes, err := hex.DecodeString(providedHexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedBytes := mac.Sum(nil)

	return hmac.Equal(sigBytes, expectedBytes)
}
