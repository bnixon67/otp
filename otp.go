// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

// Package otp provides tools for generating and validating one-time passwords
// (OTPs) according to the HOTP (RFC 4226) and TOTP (RFC 6238) standards.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// minSecretLen is the minimum secret length in bytes as required by RFC 4226.
const minSecretLen = 16

// GenerateSecret returns a cryptographically random secret of n bytes,
// suitable for use with GenerateTOTP or GenerateHOTP.
//
// RFC 4226 requires a minimum of 16 bytes (128 bits) and recommends at
// least 20 bytes (160 bits).
func GenerateSecret(n uint) ([]byte, error) {
	if n < minSecretLen {
		return nil, fmt.Errorf("secret length must be at least %d bytes, got %d", minSecretLen, n)
	}

	secret := make([]byte, n)
	_, err := rand.Read(secret)
	if err != nil {
		return nil, err // crypto/rand.Read never returns an error in Go 1.20+.
	}

	return secret, nil
}

// EncodeSecret encodes secret as a base32 string without padding,
// suitable for provisioning URIs and QR codes.
func EncodeSecret(secret []byte) string {
	return base32NoPad.EncodeToString(secret)
}

// DecodeSecret decodes a base32-encoded secret string into raw bytes.
// Input is accepted in upper or lower case and without padding characters.
func DecodeSecret(s string) ([]byte, error) {
	return base32NoPad.DecodeString(strings.ToUpper(s))
}

// ConstantTimeEqual compares two OTP strings to prevent timing attacks.
func ConstantTimeEqual(x, y string) bool {
	return subtle.ConstantTimeCompare([]byte(x), []byte(y)) == 1
}

// computeHMAC calculates the HMAC checksum for message using the provided
// hash function and key. It returns the HMAC checksum or an error if the
// message cannot be processed.
func computeHMAC(hashFunc HashFunc, key, message []byte) ([]byte, error) {
	if hashFunc == nil {
		return nil, errors.New("hash function is nil")
	}

	h := hmac.New(hashFunc, key)
	if _, err := h.Write(message); err != nil {
		return nil, err // Hash.Write never returns an error per interface contract.
	}

	return h.Sum(nil), nil
}

// uint64ToBytes converts v to a byte slice in big-endian order.
func uint64ToBytes(v uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, v)
}

// dynamicTruncation extracts a dynamic binary code from the hash using an
// offset. This step is defined in RFC 4226 for generating an OTP.
func dynamicTruncation(hashBytes []byte) (int, error) {
	if len(hashBytes) < 20 {
		return 0, fmt.Errorf("hash length must be at least 20 bytes, got %d", len(hashBytes))
	}

	offset := hashBytes[len(hashBytes)-1] & 0x0f

	return int(hashBytes[offset+0]&0x7f)<<24 |
		int(hashBytes[offset+1]&0xff)<<16 |
		int(hashBytes[offset+2]&0xff)<<8 |
		int(hashBytes[offset+3]&0xff), nil
}

// pow10 contains powers of 10 from 10^0 to 10^8, used to truncate and
// format OTP codes to a specific number of digits.
var pow10 = [9]int{
	1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000,
}

// formatOTP formats code as a zero-padded string of the requested number
// of digits, truncating to the least significant digits if necessary.
func formatOTP(code int, digits uint) (string, error) {
	if digits == 0 || int(digits) >= len(pow10) {
		return "", fmt.Errorf("invalid number of digits: %d", digits)
	}

	return fmt.Sprintf("%0*d", digits, code%pow10[digits]), nil
}

// generateOTP generates a HMAC-based One Time Password using the given hash
// function, secret, counter, and digit length.
//
// It implements common logic shared by HOTP (RFC 4226) and TOTP (RFC 6238).
func generateOTP(hashFunc HashFunc, secret []byte, counter uint64, digits uint) (string, error) {
	if hashFunc == nil {
		return "", errors.New("hash function is nil")
	}
	if len(secret) < minSecretLen {
		return "", fmt.Errorf("secret must be at least %d bytes, got %d", minSecretLen, len(secret))
	}

	hash, err := computeHMAC(hashFunc, secret, uint64ToBytes(counter))
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	code, err := dynamicTruncation(hash)
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	otp, err := formatOTP(code, digits)
	if err != nil {
		return "", fmt.Errorf("generate otp: %w", err)
	}

	return otp, nil
}
