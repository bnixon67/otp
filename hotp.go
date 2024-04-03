// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import "crypto/sha1" // skipcq: GSC-G505

// GenerateHOTP generates a HMAC-based One-Time Password (HOTP) per RFC 4226
// using the provided secret, counter, and the desired OTP length in digits.
func GenerateHOTP(secret []byte, counter uint64, digits uint) (string, error) {
	return GenerateOTP(sha1.New, secret, counter, digits)
}
