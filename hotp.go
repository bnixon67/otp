// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import "crypto/sha1" // skipcq: GSC-G505

// GenerateHOTP generates a HMAC-based One-Time Password (HOTP) per RFC 4226
// using the provided secret, counter, and the desired OTP length in digits.
func GenerateHOTP(secret []byte, counter uint64, digits uint) (string, error) {
	return generateOTP(sha1.New, secret, counter, digits)
}

// ValidateHOTP checks whether code matches the HOTP for secret at any counter
// step in [counter, counter+lookAhead]. It returns the next counter value the
// caller should store for replay prevention. A lookAhead of 0 requires an
// exact match; RFC 4226 recommends a default window of 10.
func ValidateHOTP(secret []byte, code string, counter uint64, lookAhead uint,
	digits uint) (bool, uint64, error) {
	for i := uint64(0); i <= uint64(lookAhead); i++ {
		got, err := generateOTP(sha1.New, secret, counter+i, digits)
		if err != nil {
			return false, 0, err
		}
		if ConstantTimeEqual(got, code) {
			return true, counter + i + 1, nil
		}
	}
	return false, 0, nil
}
