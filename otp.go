// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

// Package otp generates one-time passwords based on RFCs 4226 and 6238.
package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

// Checksum returns the HMAC checksum for the given function, key, and message.
func Checksum(h func() hash.Hash, key, message []byte) ([]byte, error) {
	mac := hmac.New(h, key)
	if _, err := mac.Write(message); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// GenerateOTP generates a HMAC-based One Time Password (OTP) using the
// specified hash function, a secret key, a counter value, and the desired
// number of digits in the OTP.
//
// This function contains common logic of the HOTP and TOTP algorithms.
func GenerateOTP(h func() hash.Hash, secret []byte, counter uint64, digits uint) (string, error) {
	// Convert the counter value to a byte slice in big-endian order.
	counterBytes := make([]byte, 8) // 8 bytes for uint64
	binary.BigEndian.PutUint64(counterBytes, counter)

	// Compute the HMAC hash of the counter using the secret key.
	hash, err := Checksum(h, secret, counterBytes)
	if err != nil {
		return "", err
	}

	// Dynamic truncation to extract a 4-byte dynamic binary code from
	// the hash per RFC 4226.
	offset := int(hash[len(hash)-1] & 0xf)
	code := (int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1]&0xff)<<16 |
		int(hash[offset+2]&0xff)<<8 |
		int(hash[offset+3]&0xff))

	// Calculate the OTP by reducing the code modulo 10^digits.
	otp := code % int(math.Pow10(int(digits)))

	// Format the OTP to include leading zeros if necessary.
	result := fmt.Sprintf("%0*d", digits, otp)
	return result, nil
}
