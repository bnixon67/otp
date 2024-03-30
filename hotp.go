// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import "crypto/sha1"

// GenerateHOTP generates HMAC-based one-time password per RFC 4226.
func GenerateHOTP(secret []byte, counter uint64, digits uint) (string, error) {
	return GenerateOTP(sha1.New, secret, counter, digits)
}
