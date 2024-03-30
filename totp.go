// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package otp

import (
	"crypto/sha1"
	"hash"
	"time"
)

// DefaultTimeStep in seconds per RFC 6238.
const DefaultTimeStep = 30

// GenerateTOTP returns a Time-based One-Time Password as per RFC 6238.
// If h is nil, SHA-1 is used.
func GenerateTOTP(secret []byte, time time.Time, digits uint, h func() hash.Hash) (string, error) {
	// Convert time to a counter value based on a 30-second time step.
	interval := time.Unix() / DefaultTimeStep

	// Default to SHA-1 if no hash function is provided.
	if h == nil {
		h = sha1.New
	}

	return GenerateOTP(h, secret, uint64(interval), digits)
}
