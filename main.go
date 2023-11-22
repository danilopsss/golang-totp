package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

type TOTP struct {
	key string
}

func GenerateCounter(epochTime int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(epochTime/30))
	return b
}

func GenerateHmac(t *TOTP, epochTime int) []byte {
	key, _ := base32.StdEncoding.DecodeString(strings.ToUpper(t.key))
	counter := GenerateCounter(epochTime)
	h := hmac.New(sha1.New, key)
	h.Write(counter)
	return h.Sum(nil)
}

func DynamicTruncation(hmac []byte, epochTime int) int {
	offset := hmac[19] & 0xf
	binary := binary.BigEndian.Uint32(hmac[offset : offset+4])
	return int(binary & 0x7fffffff)
}

func (t *TOTP) GenerateOTP(epochTime int) string {
	hmac := GenerateHmac(t, epochTime)
	truncatedHmac := DynamicTruncation(hmac, epochTime)
	otp := int(math.Mod(float64(truncatedHmac), math.Pow10(6)))
	sizeDiff := 6 - len(fmt.Sprintf("%d", otp))
	if sizeDiff > 1 {
		return strings.Repeat("0", sizeDiff) + fmt.Sprintf("%d", otp)
	}
	return fmt.Sprintf("%d", otp)
}

func main() {
	epochTime := time.Now().Unix()
	key := "ABCDEFGHIJKLMNOPPONMLKJIHGFEDCBA"
	totp := &TOTP{key: key}
	fmt.Println(totp.GenerateOTP(int(epochTime)))
}