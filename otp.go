// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

// Package otp provides tools for generating and validating one-time passwords
// (OTPs) according to the HOTP (RFC 4226) and TOTP (RFC 6238) standards.
package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
)

// ComputeHMAC calculates the HMAC checksum for message using the provided
// hash function and key. It returns the HMAC checksum or an error if the
// message cannot be processed.
func ComputeHMAC(hashFunc func() hash.Hash, key, message []byte) ([]byte, error) {
	mac := hmac.New(hashFunc, key)
	if _, err := mac.Write(message); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// uint64SizeBytes represents the size of a uint64 type in bytes.
const uint64SizeBytes = 8

// uint64ToBytes converts a counter value to a byte slice in big-endian order.
func uint64ToBytes(counter uint64) []byte {
	counterBytes := make([]byte, uint64SizeBytes)
	binary.BigEndian.PutUint64(counterBytes, counter)
	return counterBytes
}

// dynamicTruncation extracts a dynamic binary code from the hash using an
// offset. This step is defined in RFC 4226 for generating an OTP.
func dynamicTruncation(hash []byte) int {
	offset := hash[len(hash)-1] & 0xf
	return (int(hash[offset]&0x7f)<<24 |
		int(hash[offset+1]&0xff)<<16 |
		int(hash[offset+2]&0xff)<<8 |
		int(hash[offset+3]&0xff))
}

// formatOTP formats the OTP to have leading zeros and match the desired
// number of digits.
func formatOTP(code int, digits uint) string {
	otp := code % int(math.Pow10(int(digits)))
	return fmt.Sprintf("%0*d", digits, otp)
}

// GenerateOTP generates a HMAC-based One Time Password (OTP) using the given
// parameters. It supports generating OTPs as per HOTP (RFC 4226) and TOTP
// (RFC 6238) standards. This function contains common logic of the HOTP
// and TOTP algorithms.
func GenerateOTP(hashFunc func() hash.Hash, secret []byte, counter uint64, digits uint) (string, error) {
	counterBytes := uint64ToBytes(counter)
	hash, err := ComputeHMAC(hashFunc, secret, counterBytes)
	if err != nil {
		return "", err
	}

	code := dynamicTruncation(hash)
	otp := formatOTP(code, digits)

	return otp, nil
}
