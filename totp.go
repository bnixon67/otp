// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package otp

import (
	"crypto/sha1" // skipcq: GSC-G505
	"hash"
	"time"
)

// DefaultTimeStepSeconds defines the time step in seconds used to calculate
// the TOTP counter, as per RFC 6238.
const DefaultTimeStepSeconds = 30

// DefaultHashFunction provides a default hash function (SHA-1) for TOTP
// generation when none is specified.  SHA-1 is chosen for its compatibility
// with RFC 6238.
var DefaultHashFunction = sha1.New

// calculateTimeStepCounter converts a timestamp to a counter based on the
// timestep. This counter is used to generate the TOTP value.
func calculateTimeStepCounter(timestamp time.Time, timestep int64) uint64 {
	return uint64(timestamp.Unix() / timestep)
}

// GenerateTOTP generates a Time-based One-Time Password (TOTP) per
// RFC 6238 using the provided secret, timestamp, and the desired OTP length
// in digits. It allows for a custom hash function; if none is provided,
// SHA-1 is used by default.
func GenerateTOTP(secret []byte, timestamp time.Time, digits uint, hashFunc func() hash.Hash) (string, error) {
	// Convert the timestamp to counter value using time step.
	interval := calculateTimeStepCounter(timestamp, DefaultTimeStepSeconds)

	if hashFunc == nil {
		hashFunc = DefaultHashFunction
	}

	return GenerateOTP(hashFunc, secret, uint64(interval), digits)
}
