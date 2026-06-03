// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package otp

import (
	"crypto/sha1" // skipcq: GSC-G505
	"errors"
	"fmt"
	"hash"
	"time"
)

// DefaultTimeStepSeconds defines the time step in seconds used to calculate
// the TOTP counter, as per RFC 6238.
const DefaultTimeStepSeconds int64 = 30

// HashFunc is a function that returns a new hash.Hash, used to specify the
// hashing algorithm for OTP generation.
type HashFunc func() hash.Hash

// defaultHashFunc provides a default hash function (SHA-1) for TOTP
// generation when none is specified.  SHA-1 is chosen for its compatibility
// with RFC 6238.
func defaultHashFunc() hash.Hash { return sha1.New() }

// calcTimeStepCounter converts a timestamp to a counter based on the
// timestep. This counter is used to generate the TOTP value.
func calcTimeStepCounter(timestamp time.Time, timestep int64) (int64, error) {
	if timestep <= 0 {
		return 0, errors.New("timestep must be > 0")
	}

	counter := timestamp.Unix() / timestep
	if counter < 0 {
		return 0, errors.New("timestamp must not be before Unix epoch")
	}

	return counter, nil
}

type TOTPOptions struct {
	Digits   uint
	HashFunc HashFunc
	TimeStep int64
}

func (o TOTPOptions) withDefaults() TOTPOptions {
	if o.HashFunc == nil {
		o.HashFunc = defaultHashFunc
	}
	if o.Digits == 0 {
		o.Digits = 6
	}
	if o.TimeStep == 0 {
		o.TimeStep = DefaultTimeStepSeconds
	}
	return o
}

func (o TOTPOptions) validate() error {
	if o.Digits == 0 || int(o.Digits) >= len(pow10) {
		return fmt.Errorf("digits must be between 1 and %d", len(pow10)-1)
	}
	if o.TimeStep <= 0 {
		return errors.New("timestep must be > 0")
	}
	return nil
}

// GenerateTOTP generates a Time-based One-Time Password (TOTP) per
// RFC 6238 using the provided secret, timestamp, and the desired OTP length
// in digits. It allows for a custom hash function; if none is provided,
// SHA-1 is used by default.
func GenerateTOTP(secret []byte, timestamp time.Time, opts TOTPOptions) (string, error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return "", fmt.Errorf("generate totp: invalid options: %w", err)
	}

	// Convert the timestamp to counter value using time step.
	counter, err := calcTimeStepCounter(timestamp, opts.TimeStep)
	if err != nil {
		return "", fmt.Errorf("generate totp: %w", err)
	}

	return generateOTP(opts.HashFunc, secret, uint64(counter), opts.Digits)
}

// ValidateTOTP checks whether code matches the TOTP for secret at timestamp,
// allowing skew steps in either direction for clock drift tolerance.
// It returns the matched counter step so callers can store it for replay
// prevention. A skew of 1 allows the previous and next 30-second windows
// (RFC 6238 recommendation).
func ValidateTOTP(secret []byte, code string, timestamp time.Time, skew uint, opts TOTPOptions) (matched bool, counter uint64, err error) {
	opts = opts.withDefaults()
	if err := opts.validate(); err != nil {
		return false, 0, fmt.Errorf("validate totp: invalid options: %w", err)
	}

	base, err := calcTimeStepCounter(timestamp, opts.TimeStep)
	if err != nil {
		return false, 0, fmt.Errorf("validate totp: %w", err)
	}

	for i := -int64(skew); i <= int64(skew); i++ {
		step := base + i
		if step < 0 {
			continue
		}
		gotCode, err := generateOTP(opts.HashFunc, secret, uint64(step), opts.Digits)
		if err != nil {
			return false, 0, err
		}

		if ConstantTimeEqual(gotCode, code) {
			return true, uint64(step), nil
		}
	}
	return false, 0, nil
}
