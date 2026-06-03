// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import (
	"fmt"
	"testing"
)

func TestValidateHOTP_RFC4226(t *testing.T) {
	secret := []byte("12345678901234567890")
	digits := uint(6)

	tests := []struct {
		count uint64
		hotp  string
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
		t.Run(fmt.Sprintf("count %d", tc.count), func(t *testing.T) {
			matched, counter, err := ValidateHOTP(secret, tc.hotp, tc.count, 0, digits)
			if err != nil {
				t.Fatalf("ValidateHOTP() error: %v", err)
			}
			if !matched {
				t.Fatal("ValidateHOTP() expected match")
			}
			if counter != tc.count+1 {
				t.Fatalf("ValidateHOTP() got counter %d, want %d", counter, tc.count)
			}
		})
	}
}

func TestValidateHOTP(t *testing.T) {
	// RFC 4226 test vectors (Appendix D).
	secret := []byte("12345678901234567890")
	digits := uint(6)

	tests := []struct {
		name        string
		secret      []byte
		code        string
		counter     uint64
		lookAhead   uint
		digits      uint
		wantMatched bool
		wantNext    uint64
		wantErr     bool
	}{
		{
			name:        "exact match at counter",
			secret:      secret,
			code:        "755224", // counter=0
			counter:     0,
			lookAhead:   0,
			digits:      digits,
			wantMatched: true,
			wantNext:    1,
		},
		{
			name:        "one step ahead but lookAhead=0",
			secret:      secret,
			code:        "287082", // counter=1
			counter:     0,
			lookAhead:   0,
			digits:      digits,
			wantMatched: false,
		},
		{
			name:        "match within look-ahead window",
			secret:      secret,
			code:        "287082", // counter=1
			counter:     0,
			lookAhead:   1,
			digits:      digits,
			wantMatched: true,
			wantNext:    2,
		},
		{
			name:        "match at far edge of look-ahead window",
			secret:      secret,
			code:        "520489", // counter=9
			counter:     0,
			lookAhead:   9,
			digits:      digits,
			wantMatched: true,
			wantNext:    10,
		},
		{
			name:        "just outside look-ahead window",
			secret:      secret,
			code:        "520489", // counter=9
			counter:     0,
			lookAhead:   8,
			digits:      digits,
			wantMatched: false,
		},
		{
			name:        "does not look backward",
			secret:      secret,
			code:        "755224", // counter=0, but server is at counter=1
			counter:     1,
			lookAhead:   5,
			digits:      digits,
			wantMatched: false,
		},
		{
			name:        "non-zero starting counter",
			secret:      secret,
			code:        "338314", // counter=4
			counter:     3,
			lookAhead:   2,
			digits:      digits,
			wantMatched: true,
			wantNext:    5,
		},
		{
			name:        "wrong code",
			secret:      secret,
			code:        "000000",
			counter:     0,
			lookAhead:   10,
			digits:      digits,
			wantMatched: false,
		},
		{
			name:      "secret too short",
			secret:    []byte("tooshort"),
			code:      "755224",
			counter:   0,
			lookAhead: 0,
			digits:    digits,
			wantErr:   true,
		},
		{
			name:      "invalid digits zero",
			secret:    secret,
			code:      "755224",
			counter:   0,
			lookAhead: 0,
			digits:    0,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, next, err := ValidateHOTP(tc.secret, tc.code, tc.counter, tc.lookAhead, tc.digits)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateHOTP() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if matched != tc.wantMatched {
				t.Errorf("ValidateHOTP() matched = %v, want %v", matched, tc.wantMatched)
			}
			if next != tc.wantNext {
				t.Errorf("ValidateHOTP() nextCounter = %v, want %v", next, tc.wantNext)
			}
		})
	}
}

func ExampleGenerateHOTP() {
	secret := []byte("12345678901234567890")
	counter := uint64(9)
	digits := uint(6)

	hotp, err := GenerateHOTP(secret, counter, digits)
	if err != nil {
		fmt.Println("Error generating HOTP:", err)
		return
	}

	fmt.Printf("secret: 0x%x\n", secret)
	fmt.Printf("counter: %d\n", counter)
	fmt.Printf("digits: %d\n", digits)
	fmt.Printf("HOTP: %s\n", hotp)
	// Output:
	// secret: 0x3132333435363738393031323334353637383930
	// counter: 9
	// digits: 6
	// HOTP: 520489
}

func TestGenerateHOTP(t *testing.T) {
	// Expected values from RFC 4226.
	secret := []byte("12345678901234567890")
	digits := uint(6)
	tests := []struct {
		count uint64
		want  string
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
			hotp, err := GenerateHOTP(secret, tc.count, digits)
			if err != nil {
				t.Fatalf("Error generating OTP: %v", err)
			}
			if tc.want != hotp {
				t.Fatalf("generateOTP(%d) = %v, want %v", tc.count, hotp, tc.want)
			}
		})
	}
}
