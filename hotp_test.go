// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp_test

import (
	"fmt"
	"testing"

	"github.com/bnixon67/otp"
)

func ExampleGenerateHOTP() {
	secret := []byte("12345678901234567890")
	counter := uint64(9)
	digits := uint(6)

	fmt.Println("secret", secret)
	fmt.Println("counter", counter)
	fmt.Println("digits", digits)

	hotp, err := otp.GenerateHOTP(secret, counter, digits)
	if err != nil {
		fmt.Println("Error generating HOTP:", err)
		return
	}

	fmt.Println("HOTP:", hotp)

	// Output:
	// secret [49 50 51 52 53 54 55 56 57 48 49 50 51 52 53 54 55 56 57 48]
	// counter 9
	// digits 6
	// HOTP: 520489
}

func TestGenerateHOTP(t *testing.T) {
	// Test using expected values from RFC 4226.

	secret := []byte("12345678901234567890")
	digits := uint(6)

	tests := []struct {
		count    uint64
		expected string
	}{
		{0, "755224"},
		{1, "287082"},
		{2, "359152"},
		{3, "969429"},
		{4, "338314"},
		{5, "254676"},
		{6, "287922"},
		{7, "162583"},
		{8, "399871"},
		{9, "520489"},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("Count%d", tc.count), func(t *testing.T) {
			hotp, err := otp.GenerateHOTP(secret, tc.count, digits)
			if err != nil {
				t.Fatalf("Error generating OTP: %v", err)
			}
			if hotp != tc.expected {
				t.Fatalf("generateOTP(%d) = %v, want %v", tc.count, hotp, tc.expected)
			}
		})
	}
}
