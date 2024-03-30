// Copyright 2024 Bill Nixon. All rights reserved.  Use of this source code
// is governed by the license found in the LICENSE file.

package otp_test

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"

	"github.com/bnixon67/otp"
)

func ExampleGenerateTOTP() {
	secret := []byte("12345678901234567890")
	layout := "2006-01-02 15:04:05"
	time, err := time.Parse(layout, "2033-05-18 03:33:20")
	if err != nil {
		fmt.Println(err)
		return
	}
	digits := uint(8)

	fmt.Println("secret", secret)
	fmt.Println("time", time)
	fmt.Println("digits", digits)

	hotp, err := otp.GenerateTOTP(secret, time, digits, nil)
	if err != nil {
		fmt.Println("Error generating TOTP:", err)
		return
	}

	fmt.Println("TOTP:", hotp)
	// Output:
	// secret [49 50 51 52 53 54 55 56 57 48 49 50 51 52 53 54 55 56 57 48]
	// time 2033-05-18 03:33:20 +0000 UTC
	// digits 8
	// TOTP: 69279037
}

// generateSequence returns a string of a given length by repeating pattern.
func generateSequence(pattern string, length uint) string {
	patternLen := len(pattern)
	count := int(length) / patternLen
	remainder := int(length) % patternLen

	// Repeat base pattern count times and add the remainder of the pattern.
	result := strings.Repeat(pattern, count) + pattern[:remainder]
	return result
}

func TestGenerateTOTP(t *testing.T) {
	// Test Values from Appendix B of RFC 6238

	pattern := "1234567890"
	modes := map[string]struct {
		secret []byte
		hash   func() hash.Hash
	}{
		"": {
			secret: []byte(generateSequence(pattern, 20)),
			hash:   nil,
		},
		"SHA1": {
			secret: []byte(generateSequence(pattern, 20)),
			hash:   sha1.New,
		},
		"SHA256": {
			secret: []byte(generateSequence(pattern, 32)),
			hash:   sha256.New,
		},
		"SHA512": {
			secret: []byte(generateSequence(pattern, 64)),
			hash:   sha512.New,
		},
	}

	digits := uint(8)

	layout := "2006-01-02 15:04:05"

	tests := []struct {
		time string
		want string // Expected OTP result
		mode string
	}{
		{"1970-01-01 00:00:59", "94287082", ""},

		{"1970-01-01 00:00:59", "94287082", "SHA1"},
		{"1970-01-01 00:00:59", "46119246", "SHA256"},
		{"1970-01-01 00:00:59", "90693936", "SHA512"},

		{"2005-03-18 01:58:29", "07081804", "SHA1"},
		{"2005-03-18 01:58:29", "68084774", "SHA256"},
		{"2005-03-18 01:58:29", "25091201", "SHA512"},

		{"2005-03-18 01:58:31", "14050471", "SHA1"},
		{"2005-03-18 01:58:31", "67062674", "SHA256"},
		{"2005-03-18 01:58:31", "99943326", "SHA512"},

		{"2009-02-13 23:31:30", "89005924", "SHA1"},
		{"2009-02-13 23:31:30", "91819424", "SHA256"},
		{"2009-02-13 23:31:30", "93441116", "SHA512"},

		{"2033-05-18 03:33:20", "69279037", "SHA1"},
		{"2033-05-18 03:33:20", "90698825", "SHA256"},
		{"2033-05-18 03:33:20", "38618901", "SHA512"},

		{"2603-10-11 11:33:20", "65353130", "SHA1"},
		{"2603-10-11 11:33:20", "77737706", "SHA256"},
		{"2603-10-11 11:33:20", "47863826", "SHA512"},
	}

	// Loop through each test
	for _, tc := range tests {
		t.Run(tc.time, func(t *testing.T) {
			time, err := time.Parse(layout, tc.time)
			if err != nil {
				t.Fatal(err)
			}

			got, err := otp.GenerateTOTP(
				modes[tc.mode].secret,
				time,
				digits,
				modes[tc.mode].hash,
			)
			if err != nil {
				t.Fatalf("Error generating OTP: %v", err)
			}

			if got != tc.want {
				t.Fatalf("GenerateTOTP(%v, %q, %d, %q) = %q, want %q",
					modes[tc.mode].secret,
					time,
					digits,
					tc.mode,
					got,
					tc.want)
			}
		})
	}
}
