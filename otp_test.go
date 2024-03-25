// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

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

func TestGenerateHOTP(t *testing.T) {
	key := []byte("12345678901234567890")
	digits := uint(6)

	tests := []struct {
		counter  uint64 // Counter value
		key      []byte // Secret key
		digits   uint   // Number of digits in the generated OTP
		expected string // Expected OTP result
	}{
		{0, key, digits, "755224"},
		{1, key, digits, "287082"},
		{2, key, digits, "359152"},
		{3, key, digits, "969429"},
		{4, key, digits, "338314"},
		{5, key, digits, "254676"},
		{6, key, digits, "287922"},
		{7, key, digits, "162583"},
		{8, key, digits, "399871"},
		{9, key, digits, "520489"},
	}

	// Loop through each test
	for _, test := range tests {
		t.Run(fmt.Sprintf("Count%d", test.counter), func(t *testing.T) {
			result, err := otp.GenerateHOTP(test.key, test.counter, test.digits)
			if err != nil {
				t.Errorf("Error generating OTP: %v", err)
			}
			if result != test.expected {
				t.Errorf("generateOTP(%d) = %v, want %v", test.counter, result, test.expected)
			}
		})
	}
}

func generateSequence(length int) string {
	basePattern := "1234567890"
	repeatCount := length / 10
	remainder := length % 10

	// Repeat the base pattern for 'repeatCount' times and add the remainder of the pattern
	result := strings.Repeat(basePattern, repeatCount) + basePattern[:remainder]
	return result
}

func TestGenerateTOTP(t *testing.T) {
	// Test Values from Appendix B of RFC 6238

	key1 := []byte(generateSequence(20))
	key256 := []byte(generateSequence(32))
	key512 := []byte(generateSequence(64))

	digits := uint(8)

	tests := []struct {
		time     string // Time value
		key      []byte // Secret key
		digits   uint   // Number of digits in the generated OTP
		expected string // Expected OTP result
		hash     func() hash.Hash
	}{
		{"1970-01-01 00:00:59", key1, digits, "94287082", nil},
		{"1970-01-01 00:00:59", key1, digits, "94287082", sha1.New},
		{"1970-01-01 00:00:59", key256, digits, "46119246", sha256.New},
		{"1970-01-01 00:00:59", key512, digits, "90693936", sha512.New},

		{"2005-03-18 01:58:29", key1, digits, "07081804", nil},
		{"2005-03-18 01:58:29", key1, digits, "07081804", sha1.New},
		{"2005-03-18 01:58:29", key256, digits, "68084774", sha256.New},
		{"2005-03-18 01:58:29", key512, digits, "25091201", sha512.New},

		{"2005-03-18 01:58:31", key1, digits, "14050471", nil},
		{"2005-03-18 01:58:31", key1, digits, "14050471", sha1.New},
		{"2005-03-18 01:58:31", key256, digits, "67062674", sha256.New},
		{"2005-03-18 01:58:31", key512, digits, "99943326", sha512.New},

		{"2009-02-13 23:31:30", key1, digits, "89005924", nil},
		{"2009-02-13 23:31:30", key1, digits, "89005924", sha1.New},
		{"2009-02-13 23:31:30", key256, digits, "91819424", sha256.New},
		{"2009-02-13 23:31:30", key512, digits, "93441116", sha512.New},

		{"2033-05-18 03:33:20", key1, digits, "69279037", nil},
		{"2033-05-18 03:33:20", key1, digits, "69279037", sha1.New},
		{"2033-05-18 03:33:20", key256, digits, "90698825", sha256.New},
		{"2033-05-18 03:33:20", key512, digits, "38618901", sha512.New},

		{"2603-10-11 11:33:20", key1, digits, "65353130", nil},
		{"2603-10-11 11:33:20", key1, digits, "65353130", sha1.New},
		{"2603-10-11 11:33:20", key256, digits, "77737706", sha256.New},
		{"2603-10-11 11:33:20", key512, digits, "47863826", sha512.New},
	}

	// Loop through each test
	for _, test := range tests {
		t.Run(test.time, func(t *testing.T) {
			layout := "2006-01-02 15:04:05"

			time, err := time.Parse(layout, test.time)
			if err != nil {
				t.Errorf("Cannot parse time %q: %v", test.time, err)
			}

			result, err := otp.GenerateTOTP(test.key, time, test.digits, test.hash)
			if err != nil {
				t.Errorf("Error generating OTP: %v", err)
			}
			if result != test.expected {
				t.Errorf("GenerateTOTP(%s, %s, %d) = %v, want %v", test.key, test.time, test.digits, result, test.expected)
			}
		})
	}
}
