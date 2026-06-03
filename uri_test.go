// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import (
	"bytes"
	"testing"
)

// rfcSecretBase32 is the base32 (no padding) encoding of the RFC 4226/6238
// test secret "12345678901234567890".
var rfcSecretBase32 = base32NoPad.EncodeToString(rfc6238sha1secret)

func TestFormatURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     URI
		want    string
		wantErr bool
	}{
		{
			name: "TOTP defaults omitted",
			uri: URI{
				Type:    "totp",
				Account: "alice",
				Secret:  rfc6238sha1secret,
			},
			want: "otpauth://totp/alice?secret=" + rfcSecretBase32,
		},
		{
			name: "TOTP with issuer",
			uri: URI{
				Type:    "totp",
				Issuer:  "ACME",
				Account: "alice",
				Secret:  rfc6238sha1secret,
			},
			want: "otpauth://totp/ACME:alice?issuer=ACME&secret=" + rfcSecretBase32,
		},
		{
			name: "TOTP SHA256",
			uri: URI{
				Type:      "totp",
				Account:   "alice",
				Secret:    rfc6238sha256secret,
				Algorithm: "SHA256",
			},
			want: "otpauth://totp/alice?algorithm=SHA256&secret=" + base32NoPad.EncodeToString(rfc6238sha256secret),
		},
		{
			name: "TOTP 8 digits",
			uri: URI{
				Type:    "totp",
				Account: "alice",
				Secret:  rfc6238sha1secret,
				Digits:  8,
			},
			want: "otpauth://totp/alice?digits=8&secret=" + rfcSecretBase32,
		},
		{
			name: "TOTP non-default period",
			uri: URI{
				Type:    "totp",
				Account: "alice",
				Secret:  rfc6238sha1secret,
				Period:  60,
			},
			want: "otpauth://totp/alice?period=60&secret=" + rfcSecretBase32,
		},
		{
			name: "HOTP counter zero",
			uri: URI{
				Type:    "hotp",
				Account: "alice",
				Secret:  rfc6238sha1secret,
				Counter: 0,
			},
			want: "otpauth://hotp/alice?counter=0&secret=" + rfcSecretBase32,
		},
		{
			name: "HOTP counter non-zero",
			uri: URI{
				Type:    "hotp",
				Account: "alice",
				Secret:  rfc6238sha1secret,
				Counter: 42,
			},
			want: "otpauth://hotp/alice?counter=42&secret=" + rfcSecretBase32,
		},
		{
			name: "account with at-sign",
			uri: URI{
				Type:    "totp",
				Account: "alice@example.com",
				Secret:  rfc6238sha1secret,
			},
			// url.PathEscape does not encode '@'; it is valid in a URI path.
			want: "otpauth://totp/alice@example.com?secret=" + rfcSecretBase32,
		},
		{
			name:    "invalid type",
			uri:     URI{Type: "otp", Account: "alice", Secret: rfc6238sha1secret},
			wantErr: true,
		},
		{
			name:    "empty account",
			uri:     URI{Type: "totp", Account: "", Secret: rfc6238sha1secret},
			wantErr: true,
		},
		{
			name:    "secret too short",
			uri:     URI{Type: "totp", Account: "alice", Secret: []byte("tooshort")},
			wantErr: true,
		},
		{
			name:    "unsupported algorithm",
			uri:     URI{Type: "totp", Account: "alice", Secret: rfc6238sha1secret, Algorithm: "MD5"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FormatURI(tc.uri)
			if (err != nil) != tc.wantErr {
				t.Fatalf("FormatURI() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("FormatURI()\ngot  %q\nwant %q", got, tc.want)
			}
		})
	}
}

func TestParseURI(t *testing.T) {
	tests := []struct {
		name    string
		rawURI  string
		want    URI
		wantErr bool
	}{
		{
			name:   "TOTP minimal",
			rawURI: "otpauth://totp/alice?secret=" + rfcSecretBase32,
			want: URI{
				Type:      "totp",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
			},
		},
		{
			name:   "TOTP with issuer in label",
			rawURI: "otpauth://totp/ACME:alice?secret=" + rfcSecretBase32,
			want: URI{
				Type:      "totp",
				Issuer:    "ACME",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
			},
		},
		{
			name:   "TOTP with issuer query param",
			rawURI: "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&issuer=ACME",
			want: URI{
				Type:      "totp",
				Issuer:    "ACME",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
			},
		},
		{
			name:   "issuer query param overrides label prefix",
			rawURI: "otpauth://totp/OldIssuer:alice?secret=" + rfcSecretBase32 + "&issuer=NewIssuer",
			want: URI{
				Type:      "totp",
				Issuer:    "NewIssuer",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Period:    30,
			},
		},
		{
			name:   "TOTP SHA256",
			rawURI: "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&algorithm=SHA256",
			want: URI{
				Type:      "totp",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA256",
				Digits:    6,
				Period:    30,
			},
		},
		{
			name:   "TOTP 8 digits",
			rawURI: "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&digits=8",
			want: URI{
				Type:      "totp",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    8,
				Period:    30,
			},
		},
		{
			name:   "TOTP non-default period",
			rawURI: "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&period=60",
			want: URI{
				Type:      "totp",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Period:    60,
			},
		},
		{
			name:   "HOTP counter zero",
			rawURI: "otpauth://hotp/alice?secret=" + rfcSecretBase32 + "&counter=0",
			want: URI{
				Type:      "hotp",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Counter:   0,
			},
		},
		{
			name:   "HOTP counter non-zero",
			rawURI: "otpauth://hotp/alice?secret=" + rfcSecretBase32 + "&counter=42",
			want: URI{
				Type:      "hotp",
				Account:   "alice",
				Secret:    rfc6238sha1secret,
				Algorithm: "SHA1",
				Digits:    6,
				Counter:   42,
			},
		},
		{
			name:    "wrong scheme",
			rawURI:  "https://totp/alice?secret=" + rfcSecretBase32,
			wantErr: true,
		},
		{
			name:    "invalid type",
			rawURI:  "otpauth://otp/alice?secret=" + rfcSecretBase32,
			wantErr: true,
		},
		{
			name:    "missing secret",
			rawURI:  "otpauth://totp/alice",
			wantErr: true,
		},
		{
			name:    "invalid base32 secret",
			rawURI:  "otpauth://totp/alice?secret=!!!",
			wantErr: true,
		},
		{
			name:    "unsupported algorithm",
			rawURI:  "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&algorithm=MD5",
			wantErr: true,
		},
		{
			name:    "invalid digits",
			rawURI:  "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&digits=0",
			wantErr: true,
		},
		{
			name:    "HOTP missing counter",
			rawURI:  "otpauth://hotp/alice?secret=" + rfcSecretBase32,
			wantErr: true,
		},
		{
			name:    "TOTP zero period",
			rawURI:  "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&period=0",
			wantErr: true,
		},
		{
			name:    "TOTP negative period",
			rawURI:  "otpauth://totp/alice?secret=" + rfcSecretBase32 + "&period=-1",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseURI(tc.rawURI)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ParseURI() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.Type != tc.want.Type {
				t.Errorf("Type = %q, want %q", got.Type, tc.want.Type)
			}
			if got.Issuer != tc.want.Issuer {
				t.Errorf("Issuer = %q, want %q", got.Issuer, tc.want.Issuer)
			}
			if got.Account != tc.want.Account {
				t.Errorf("Account = %q, want %q", got.Account, tc.want.Account)
			}
			if !bytes.Equal(got.Secret, tc.want.Secret) {
				t.Errorf("Secret = %v, want %v", got.Secret, tc.want.Secret)
			}
			if got.Algorithm != tc.want.Algorithm {
				t.Errorf("Algorithm = %q, want %q", got.Algorithm, tc.want.Algorithm)
			}
			if got.Digits != tc.want.Digits {
				t.Errorf("Digits = %d, want %d", got.Digits, tc.want.Digits)
			}
			if got.Period != tc.want.Period {
				t.Errorf("Period = %d, want %d", got.Period, tc.want.Period)
			}
			if got.Counter != tc.want.Counter {
				t.Errorf("Counter = %d, want %d", got.Counter, tc.want.Counter)
			}
		})
	}
}

func TestURIRoundTrip(t *testing.T) {
	originals := []URI{
		{
			Type:      "totp",
			Account:   "alice",
			Secret:    rfc6238sha1secret,
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
		{
			Type:      "totp",
			Issuer:    "ACME",
			Account:   "alice@example.com",
			Secret:    rfc6238sha1secret,
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
		{
			Type:      "totp",
			Account:   "alice",
			Secret:    rfc6238sha256secret,
			Algorithm: "SHA256",
			Digits:    8,
			Period:    60,
		},
		{
			Type:      "hotp",
			Issuer:    "ACME",
			Account:   "bob",
			Secret:    rfc6238sha1secret,
			Algorithm: "SHA1",
			Digits:    6,
			Counter:   7,
		},
	}

	for _, orig := range originals {
		rawURI, err := FormatURI(orig)
		if err != nil {
			t.Fatalf("FormatURI(%+v): %v", orig, err)
		}

		parsed, err := ParseURI(rawURI)
		if err != nil {
			t.Fatalf("ParseURI(%q): %v", rawURI, err)
		}

		if parsed.Type != orig.Type {
			t.Errorf("Type: got %q, want %q", parsed.Type, orig.Type)
		}
		if parsed.Issuer != orig.Issuer {
			t.Errorf("Issuer: got %q, want %q", parsed.Issuer, orig.Issuer)
		}
		if parsed.Account != orig.Account {
			t.Errorf("Account: got %q, want %q", parsed.Account, orig.Account)
		}
		if !bytes.Equal(parsed.Secret, orig.Secret) {
			t.Errorf("Secret: got %v, want %v", parsed.Secret, orig.Secret)
		}
		if parsed.Digits != orig.Digits {
			t.Errorf("Digits: got %d, want %d", parsed.Digits, orig.Digits)
		}
		if parsed.Counter != orig.Counter {
			t.Errorf("Counter: got %d, want %d", parsed.Counter, orig.Counter)
		}
	}
}
