// Copyright 2024 Bill Nixon. All rights reserved.  Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import (
	"crypto/sha1" // skipcq: GSC-G505
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"
	"time"
)

func ExampleGenerateTOTP() {
	secret := []byte("12345678901234567890")
	layout := "2006-01-02 15:04:05"
	parsedTime, err := time.Parse(layout, "2033-05-18 03:33:20")
	if err != nil {
		fmt.Println(err)
		return
	}
	digits := uint(8)

	fmt.Println("secret", secret)
	fmt.Println("time", parsedTime)
	fmt.Println("digits", digits)

	totp, err := GenerateTOTP(secret, parsedTime, TOTPOptions{Digits: 8})
	if err != nil {
		fmt.Println("Error generating TOTP:", err)
		return
	}

	fmt.Println("TOTP:", totp)
	// Output:
	// secret [49 50 51 52 53 54 55 56 57 48 49 50 51 52 53 54 55 56 57 48]
	// time 2033-05-18 03:33:20 +0000 UTC
	// digits 8
	// TOTP: 69279037
}

var (
	rfc6238sha1secret   = []byte("12345678901234567890")
	rfc6238sha256secret = []byte("12345678901234567890123456789012")
	rfc6238sha512secret = []byte("1234567890123456789012345678901234567890123456789012345678901234")
)

func TestGenerateTOTP_RFC6238(t *testing.T) {
	// Test Values from Appendix B of RFC 6238
	layout := "2006-01-02 15:04:05"

	modes := map[string]struct {
		secret []byte
		hash   HashFunc
	}{
		"SHA1":   {rfc6238sha1secret, sha1.New},
		"SHA256": {rfc6238sha256secret, sha256.New},
		"SHA512": {rfc6238sha512secret, sha512.New},
	}

	tests := []struct {
		time string
		want string
		mode string
	}{
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

	for _, tc := range tests {
		t.Run(tc.time+"-"+tc.mode, func(t *testing.T) {
			timestamp, err := time.Parse(layout, tc.time)
			if err != nil {
				t.Fatal(err)
			}

			secret := modes[tc.mode].secret
			opts := TOTPOptions{Digits: 8, HashFunc: modes[tc.mode].hash}
			got, err := GenerateTOTP(secret, timestamp, opts)
			if err != nil {
				t.Fatalf("Error generating OTP: %v", err)
			}

			if !ConstantTimeEqual(got, tc.want) {
				t.Fatalf("GenerateTOTP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGenerateTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")
	timestamp := time.Unix(59, 0)

	tests := []struct {
		name      string
		secret    []byte
		timestamp time.Time
		opts      TOTPOptions
		want      string
		wantErr   bool
	}{
		{
			name:      "invalid options",
			secret:    secret,
			timestamp: timestamp,
			opts:      TOTPOptions{Digits: uint(len(pow10)) + 1},
			wantErr:   true,
		},
		{
			name:      "secret too short",
			secret:    []byte("tooshort"),
			timestamp: timestamp,
			opts:      TOTPOptions{},
			wantErr:   true,
		},
		{
			name:      "before unix epoch",
			secret:    secret,
			timestamp: time.Unix(-31, 0),
			opts:      TOTPOptions{},
			wantErr:   true,
		},
		{
			name:      "default options 6 digits",
			secret:    secret,
			timestamp: timestamp,
			opts:      TOTPOptions{},
			want:      "287082",
		},
		{
			name:      "explicit 6 digits",
			secret:    secret,
			timestamp: timestamp,
			opts:      TOTPOptions{Digits: 6},
			want:      "287082",
		},
		{
			name:      "explicit 8 digits",
			secret:    secret,
			timestamp: timestamp,
			opts:      TOTPOptions{Digits: 8},
			want:      "94287082",
		},
		{
			name:      "non-standard timestep 60s",
			secret:    secret,
			timestamp: time.Unix(60, 0),
			opts:      TOTPOptions{TimeStep: 60},
			want:      "287082",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateTOTP(tc.secret, tc.timestamp, tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateTOTP() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("GenerateTOTP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestValidateTOTP_RFC6238(t *testing.T) {
	modes := map[string]struct {
		secret []byte
		hash   HashFunc
	}{
		"SHA1":   {rfc6238sha1secret, sha1.New},
		"SHA256": {rfc6238sha256secret, sha256.New},
		"SHA512": {rfc6238sha512secret, sha512.New},
	}

	tests := []struct {
		time string
		want string
		mode string
	}{
		// Test Values from Appendix B of RFC 6238
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

	for _, tc := range tests {
		t.Run(tc.time+"-"+tc.mode, func(t *testing.T) {
			layout := "2006-01-02 15:04:05"
			timestamp, err := time.Parse(layout, tc.time)
			if err != nil {
				t.Fatal(err)
			}

			secret := modes[tc.mode].secret
			opts := TOTPOptions{Digits: 8, HashFunc: modes[tc.mode].hash}
			matched, _, err := ValidateTOTP(secret, tc.want, timestamp, 1, opts)
			if err != nil {
				t.Fatalf("Error generating OTP: %v", err)
			}

			if !matched {
				t.Fatalf("validate failed")
			}
		})
	}
}

func TestCalcTimeStepCounter(t *testing.T) {
	tests := []struct {
		name      string
		timestamp time.Time
		timestep  int64
		want      int64
		wantErr   bool
	}{
		{
			name:      "zero timestep",
			timestamp: time.Unix(59, 0),
			timestep:  0,
			wantErr:   true,
		},
		{
			name:      "negative timestep",
			timestamp: time.Unix(59, 0),
			timestep:  -1,
			wantErr:   true,
		},
		{
			name:      "before unix epoch",
			timestamp: time.Unix(-31, 0),
			timestep:  30,
			wantErr:   true,
		},
		{
			name:      "unix epoch",
			timestamp: time.Unix(0, 0),
			timestep:  30,
			want:      0,
		},
		// RFC 6238 Appendix B test vectors
		{
			name:      "RFC 6238 T=1 (59s)",
			timestamp: time.Unix(59, 0),
			timestep:  30,
			want:      1,
		},
		{
			name:      "RFC 6238 T=37037036 (1111111109s)",
			timestamp: time.Unix(1111111109, 0),
			timestep:  30,
			want:      37037036,
		},
		{
			name:      "RFC 6238 T=37037037 (1111111111s)",
			timestamp: time.Unix(1111111111, 0),
			timestep:  30,
			want:      37037037,
		},
		{
			name:      "RFC 6238 T=666666666 (20000000000s)",
			timestamp: time.Unix(20000000000, 0),
			timestep:  30,
			want:      666666666,
		},
		{
			name:      "non-standard timestep 60s",
			timestamp: time.Unix(120, 0),
			timestep:  60,
			want:      2,
		},
		{
			name:      "truncates within step",
			timestamp: time.Unix(59, 0),
			timestep:  60,
			want:      0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := calcTimeStepCounter(tc.timestamp, tc.timestep)
			if (err != nil) != tc.wantErr {
				t.Errorf("calcTimeStepCounter() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("calcTimeStepCounter() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTOTPOptionsWithDefaults(t *testing.T) {
	tests := []struct {
		name  string
		input TOTPOptions
		want  TOTPOptions
	}{
		{
			name:  "all zero values get defaults",
			input: TOTPOptions{},
			want: TOTPOptions{
				HashFunc: defaultHashFunc,
				Digits:   6,
				TimeStep: DefaultTimeStepSeconds,
			},
		},
		{
			name: "existing values are not overwritten",
			input: TOTPOptions{
				HashFunc: sha256.New,
				Digits:   8,
				TimeStep: 60,
			},
			want: TOTPOptions{
				HashFunc: sha256.New,
				Digits:   8,
				TimeStep: 60,
			},
		},
		{
			name: "only hash is defaulted",
			input: TOTPOptions{
				Digits:   8,
				TimeStep: 60,
			},
			want: TOTPOptions{
				HashFunc: defaultHashFunc,
				Digits:   8,
				TimeStep: 60,
			},
		},
		{
			name: "only digits is defaulted",
			input: TOTPOptions{
				HashFunc: sha256.New,
				TimeStep: 60,
			},
			want: TOTPOptions{
				HashFunc: sha256.New,
				Digits:   6,
				TimeStep: 60,
			},
		},
		{
			name: "only timestep is defaulted",
			input: TOTPOptions{
				HashFunc: sha256.New,
				Digits:   8,
			},
			want: TOTPOptions{
				HashFunc: sha256.New,
				Digits:   8,
				TimeStep: DefaultTimeStepSeconds,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.input.withDefaults()
			if got.Digits != tc.want.Digits {
				t.Errorf("Digits = %v, want %v", got.Digits, tc.want.Digits)
			}
			if got.TimeStep != tc.want.TimeStep {
				t.Errorf("TimeStep = %v, want %v", got.TimeStep, tc.want.TimeStep)
			}
			if (got.HashFunc == nil) != (tc.want.HashFunc == nil) {
				t.Errorf("Hash nil mismatch: got nil=%v, want nil=%v", got.HashFunc == nil, tc.want.HashFunc == nil)
			}
			if got.HashFunc != nil && got.HashFunc() == nil {
				t.Errorf("Hash() returned nil")
			}
		})
	}
}

func TestTOTPOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   TOTPOptions
		wantErr bool
	}{
		{
			name: "valid defaults",
			input: TOTPOptions{
				Digits:   6,
				TimeStep: DefaultTimeStepSeconds,
			},
		},
		{
			name: "valid 8 digits",
			input: TOTPOptions{
				Digits:   8,
				TimeStep: DefaultTimeStepSeconds,
			},
		},
		{
			name: "zero digits",
			input: TOTPOptions{
				Digits:   0,
				TimeStep: DefaultTimeStepSeconds,
			},
			wantErr: true,
		},
		{
			name: "too many digits",
			input: TOTPOptions{
				Digits:   uint(len(pow10)) + 1,
				TimeStep: DefaultTimeStepSeconds,
			},
			wantErr: true,
		},
		{
			name: "zero timestep",
			input: TOTPOptions{
				Digits:   6,
				TimeStep: 0,
			},
			wantErr: true,
		},
		{
			name: "negative timestep",
			input: TOTPOptions{
				Digits:   6,
				TimeStep: -1,
			},
			wantErr: true,
		},
		{
			name: "both invalid",
			input: TOTPOptions{
				Digits:   0,
				TimeStep: 0,
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.input.validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateTOTP(t *testing.T) {
	secret := []byte("12345678901234567890")
	timestamp := time.Unix(59, 0)

	tests := []struct {
		name        string
		secret      []byte
		code        string
		timestamp   time.Time
		skew        uint
		opts        TOTPOptions
		wantMatched bool
		wantCounter uint64
		wantErr     bool
	}{
		{
			name:      "invalid options",
			secret:    secret,
			code:      "123456",
			timestamp: timestamp,
			skew:      0,
			opts:      TOTPOptions{Digits: uint(len(pow10)) + 1},
			wantErr:   true,
		},
		{
			name:      "secret too short",
			secret:    []byte("tooshort"),
			code:      "123456",
			timestamp: timestamp,
			skew:      0,
			opts:      TOTPOptions{},
			wantErr:   true,
		},
		{
			name:      "before unix epoch with skew",
			secret:    secret,
			code:      "123456",
			timestamp: time.Unix(-31, 0),
			skew:      0,
			opts:      TOTPOptions{},
			wantErr:   true,
		},
		{
			name:        "no match no skew",
			secret:      secret,
			code:        "000000",
			timestamp:   timestamp,
			skew:        0,
			opts:        TOTPOptions{},
			wantMatched: false,
			wantCounter: 0,
		},
		{
			name:        "match with default options 6 digits",
			secret:      secret,
			code:        "287082",
			timestamp:   timestamp,
			skew:        0,
			opts:        TOTPOptions{},
			wantMatched: true,
			wantCounter: 1,
		},
		{
			name:        "match with skew -1",
			secret:      secret,
			code:        "287082",
			timestamp:   time.Unix(89, 0), // T=2, but code is for T=1
			skew:        1,
			opts:        TOTPOptions{},
			wantMatched: true,
			wantCounter: 1,
		},
		{
			name:        "match with skew +1",
			secret:      secret,
			code:        "081804",
			timestamp:   time.Unix(1111111079, 0),
			skew:        1,
			opts:        TOTPOptions{},
			wantMatched: true,
			wantCounter: 37037036,
		},
		{
			name:        "no match outside skew window",
			secret:      secret,
			code:        "287082",          // code for T=1
			timestamp:   time.Unix(119, 0), // T=3, two steps ahead
			skew:        1,
			opts:        TOTPOptions{},
			wantMatched: false,
			wantCounter: 0,
		},
		{
			name:        "skew does not go below zero",
			secret:      secret,
			code:        "000000",
			timestamp:   time.Unix(15, 0), // T=0, skew would try T=-1 but skips it
			skew:        1,
			opts:        TOTPOptions{},
			wantMatched: false,
			wantCounter: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matched, counter, err := ValidateTOTP(tc.secret, tc.code, tc.timestamp, tc.skew, tc.opts)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateTOTP() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && matched != tc.wantMatched {
				t.Errorf("ValidateTOTP() matched = %v, want %v", matched, tc.wantMatched)
			}
			if !tc.wantErr && counter != tc.wantCounter {
				t.Errorf("ValidateTOTP() counter = %v, want %v", counter, tc.wantCounter)
			}
		})
	}
}
