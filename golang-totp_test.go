package totp

import (
	"fmt"
	"testing"
)

func TestTOTPGen(t *testing.T) {
	mockedEpochTime := 1700681792
	testKey := "ABCDEFGHIJKLMNOPPONMLKJIHGFEDCBA"
	totpStruct := &TOTP{Key: testKey}
	expectTOTP := "496979"

	t.Run("RFC 4226 - Step 1 - HMAC", func(t *testing.T) {
		hmacGenerated := GenerateHmac(totpStruct, mockedEpochTime)
		if len(hmacGenerated) != 20 {
			t.Errorf("Expected 20 bytes, got %d", len(hmacGenerated))
		}
	})
	t.Run("RFC 4226 - Step 1 - Counter", func(t *testing.T) {
		counter := GenerateCounter(mockedEpochTime)
		expected := "00000000036102f1"
		if fmt.Sprintf("%x", string(counter)) != expected {
			t.Errorf("Expected %s, got %s", expected, fmt.Sprintf("%x", string(counter)))
		}
	})
	t.Run("RFC 4226 - Step 2", func(t *testing.T) {
		hmac := []byte{69, 58, 87, 245, 105, 87, 62, 96, 232, 180, 38, 226, 198, 78, 225, 122, 73, 111, 132, 156}
		numeric31BitBin := DynamicTruncation(hmac, mockedEpochTime)
		binaryRepresentation := fmt.Sprintf("%b", numeric31BitBin)
		if len(binaryRepresentation) != 31 {
			t.Errorf("Expected %d, got %d", 31, len(binaryRepresentation))
		}
	})
	t.Run("RFC 4226 - Step 3", func(t *testing.T) {
		otp := totpStruct.GenerateOTP(mockedEpochTime)
		if len(otp) != 6 {
			t.Errorf("Expected %d, got %d", 32, len(otp))
		}
		if otp != expectTOTP {
			t.Errorf("Expected %s, got %s", expectTOTP, otp)
		}
	})
}
