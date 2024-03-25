// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package otp

import (
	"crypto/sha1"
	"hash"
	"time"
)

// DefaultTimeStep is the default time step in seconds for TOTP.
// RFC 6238 recommends 30 seconds.
const DefaultTimeStep = 30

// GenerateTOTP generates a TOTP based on the given parameters as per RFC 6238.
// If 'h' is nil, SHA-1 is used by default.
func GenerateTOTP(secret []byte, time time.Time, digits uint, h func() hash.Hash) (string, error) {
	// Convert time to a counter value based on a 30-second time step.
	interval := time.Unix() / DefaultTimeStep

	// Use SHA-1 as the default hash function if none is specified.
	if h == nil {
		h = sha1.New
	}

	return generateOTP(h, secret, uint64(interval), digits)
}
