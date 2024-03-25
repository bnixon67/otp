// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

// Package otp generates one-time password based on RFCs 4226 and 6238.
package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

// hmacHash calculates HMAC using the specified hash function, key, and message.
func hmacHash(h func() hash.Hash, key, message []byte) ([]byte, error) {
	mac := hmac.New(h, key)
	if _, err := mac.Write(message); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// generateOTP generates a HMAC-based OTP based on the given parameters.
func generateOTP(h func() hash.Hash, secret []byte, counter uint64, digits uint) (string, error) {
	// Convert counter to bytes
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Compute HMAC hash
	hash, err := hmacHash(h, secret, counterBytes)
	if err != nil {
		return "", err
	}

	// Dynamic truncation to extract a 4-byte dynamic binary code
	offset := int(hash[len(hash)-1] & 0xf)
	code := (int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1]&0xff)<<16 |
		int(hash[offset+2]&0xff)<<8 |
		int(hash[offset+3]&0xff))

	// Calculate OTP
	otp := code % int(math.Pow10(int(digits)))

	// Format OTP with leading zeros
	result := fmt.Sprintf("%0*d", digits, otp)
	return result, nil
}
