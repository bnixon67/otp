package otp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"math"
	"testing"
)

func TestComputeHMAC(t *testing.T) {
	tests := []struct {
		name     string
		hashFunc HashFunc
		secret   []byte
		message  []byte
		want     []byte
		wantErr  bool
	}{
		{
			name:    "empty",
			wantErr: true,
		},
		{
			name:     "sha1",
			hashFunc: sha1.New,
			secret:   rfc6238sha1secret,
			message:  []byte{0, 0, 0, 0, 0, 0, 0, 1},
			want: []byte{
				0x75, 0xA4, 0x8A, 0x19, 0xD4, 0xCB, 0xE1, 0x00, 0x64, 0x4E,
				0x8A, 0xC1, 0x39, 0x7E, 0xEA, 0x74, 0x7A, 0x2D, 0x33, 0xAB},
		},
		{
			name:     "sha256",
			hashFunc: sha256.New,
			secret:   rfc6238sha256secret,
			message:  []byte{0, 0, 0, 0, 0, 0, 0, 1},
			want: []byte{
				0x39, 0x25, 0x14, 0xC9, 0xDD, 0x41, 0x65, 0xD4,
				0x70, 0x94, 0x56, 0x06, 0x2C, 0x78, 0xE0, 0x4E,
				0x16, 0xE6, 0x87, 0x18, 0x51, 0x59, 0x51, 0x33,
				0x3B, 0xDB, 0x8B, 0x26, 0xCA, 0xA3, 0x05, 0x3C},
		},
		{
			name:     "sha512",
			hashFunc: sha512.New,
			secret:   rfc6238sha512secret,
			message:  []byte{0, 0, 0, 0, 0, 0, 0, 1},
			want: []byte{
				0x6F, 0x76, 0xF3, 0x24, 0x23, 0x0C, 0xEF, 0xDA,
				0x1D, 0x3F, 0x65, 0x30, 0x9A, 0x0B, 0xAD, 0xB3,
				0x6E, 0xFC, 0xE9, 0x52, 0x8A, 0xDA, 0x64, 0x96,
				0x7D, 0x71, 0xE4, 0xE9, 0xD7, 0x4C, 0x4A, 0xA3,
				0x7F, 0xE7, 0x65, 0x0F, 0x93, 0x1A, 0xB8, 0x6D,
				0xDC, 0xCC, 0x2D, 0x38, 0x96, 0x2D, 0x72, 0x0E,
				0xE6, 0x26, 0xA2, 0x0F, 0xEB, 0x31, 0x1B, 0x48,
				0x5A, 0x92, 0xE3, 0xBB, 0x07, 0x96, 0xDF, 0x28},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := computeHMAC(tc.hashFunc, tc.secret, tc.message)

			if (err != nil) != tc.wantErr {
				t.Fatalf("got error = %v, wantErr %t", err, tc.wantErr)
			}

			if !hmac.Equal(got, tc.want) {
				t.Fatalf("\ngot\n%v\nwant\n%v", got, tc.want)
			}
		})
	}
}

func TestUint64ToBytes(t *testing.T) {
	tests := []struct {
		name  string
		count uint64
		want  []byte
	}{
		{"zero",
			0, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{"one",
			1, []byte{0, 0, 0, 0, 0, 0, 0, 1}},
		{"max",
			math.MaxUint64, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"mixed",
			0x0102030405060708, []byte{1, 2, 3, 4, 5, 6, 7, 8}}, // check byte-order
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := uint64ToBytes(tc.count)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
func TestDynamicTruncation(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    int
		wantErr bool
	}{
		{
			name:    "too short",
			input:   make([]byte, 19),
			wantErr: true,
		},
		{
			name: "high bit masked on first byte",
			input: func() []byte {
				b := make([]byte, 20)
				b[19] = 0x00 // offset = 0
				b[0] = 0xFF
				b[1] = 0xFF
				b[2] = 0xFF
				b[3] = 0xFF
				return b
			}(),
			want: 0x7FFFFFFF,
		},
		{
			name: "offset zero",
			input: func() []byte {
				b := make([]byte, 20)
				b[19] = 0x00 // offset = 0
				b[0] = 0x01
				b[1] = 0x02
				b[2] = 0x03
				b[3] = 0x04
				return b
			}(),
			want: 0x01020304,
		},
		{
			name: "offset fifteen",
			input: func() []byte {
				b := make([]byte, 20)
				b[19] = 0x0F // offset = 15, reads bytes 15-18
				b[15] = 0x01
				b[16] = 0x02
				b[17] = 0x03
				b[18] = 0x04
				return b
			}(),
			want: 0x01020304,
		},
		{
			name: "RFC 6238 T=1 SHA1",
			input: []byte{
				0x75, 0xA4, 0x8A, 0x19, 0xD4, 0xCB, 0xE1, 0x00, 0x64, 0x4E,
				0x8A, 0xC1, 0x39, 0x7E, 0xEA, 0x74, 0x7A, 0x2D, 0x33, 0xAB},
			want: 1094287082,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := dynamicTruncation(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("dynamicTruncation() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("dynamicTruncation() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestFormatOTP(t *testing.T) {
	tests := []struct {
		name    string
		code    int
		digits  uint
		want    string
		wantErr bool
	}{
		{
			name:    "zero digits",
			code:    123456,
			digits:  0,
			wantErr: true,
		},
		{
			name:    "too many digits",
			code:    123456,
			digits:  uint(len(pow10)),
			wantErr: true,
		},
		{
			name:   "six digits no truncation",
			code:   123456,
			digits: 6,
			want:   "123456",
		},
		{
			name:   "six digits truncated",
			code:   1234567890,
			digits: 6,
			want:   "567890",
		},
		{
			name:   "leading zeros",
			code:   42,
			digits: 6,
			want:   "000042",
		},
		{
			name:   "eight digits",
			code:   94287082,
			digits: 8,
			want:   "94287082",
		},
		{
			name:   "RFC 6238 T=1 SHA1",
			code:   1094287082,
			digits: 8,
			want:   "94287082",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := formatOTP(tc.code, tc.digits)
			if (err != nil) != tc.wantErr {
				t.Errorf("formatOTP() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("formatOTP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGenerateOTP(t *testing.T) {
	tests := []struct {
		name    string
		hash    HashFunc
		secret  []byte
		counter uint64
		digits  uint
		want    string
		wantErr bool
	}{
		{
			name:    "nil hash function",
			hash:    nil,
			secret:  []byte(rfc6238sha1secret),
			counter: 0,
			digits:  6,
			wantErr: true,
		},
		{
			name:    "secret too short",
			hash:    sha1.New,
			secret:  []byte("tooshort"),
			counter: 0,
			digits:  6,
			wantErr: true,
		},
		{
			name:    "invalid digits",
			hash:    sha1.New,
			secret:  []byte(rfc6238sha1secret),
			counter: 0,
			digits:  0,
			wantErr: true,
		},
		// RFC 6238 Appendix B test vectors - SHA1
		{
			name:    "RFC 6238 SHA1 T=1",
			hash:    sha1.New,
			secret:  rfc6238sha1secret,
			counter: 1,
			digits:  8,
			want:    "94287082",
		},
		{
			name:    "RFC 6238 SHA1 T=37037036",
			hash:    sha1.New,
			secret:  rfc6238sha1secret,
			counter: 37037036,
			digits:  8,
			want:    "07081804",
		},
		{
			name:    "RFC 6238 SHA1 T=37037037",
			hash:    sha1.New,
			secret:  rfc6238sha1secret,
			counter: 37037037,
			digits:  8,
			want:    "14050471",
		},
		// RFC 6238 Appendix B test vectors - SHA256
		{
			name:    "RFC 6238 SHA256 T=1",
			hash:    sha256.New,
			secret:  rfc6238sha256secret,
			counter: 1,
			digits:  8,
			want:    "46119246",
		},
		{
			name:    "RFC 6238 SHA256 T=37037036",
			hash:    sha256.New,
			secret:  rfc6238sha256secret,
			counter: 37037036,
			digits:  8,
			want:    "68084774",
		},
		// RFC 6238 Appendix B test vectors - SHA512
		{
			name:    "RFC 6238 SHA512 T=1",
			hash:    sha512.New,
			secret:  rfc6238sha512secret,
			counter: 1,
			digits:  8,
			want:    "90693936",
		},
		{
			name:    "RFC 6238 SHA512 T=37037036",
			hash:    sha512.New,
			secret:  rfc6238sha512secret,
			counter: 37037036,
			digits:  8,
			want:    "25091201",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := generateOTP(tc.hash, tc.secret, tc.counter, tc.digits)
			if (err != nil) != tc.wantErr {
				t.Errorf("generateOTP() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("generateOTP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name string
		x    string
		y    string
		want bool
	}{
		{"equal", "123456", "123456", true},
		{"not equal", "123456", "654321", false},
		{"different lengths", "123456", "12345", false},
		{"empty equal", "", "", true},
		{"empty and nonempty", "", "123456", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ConstantTimeEqual(tc.x, tc.y)
			if got != tc.want {
				t.Errorf("ConstantTimeEqual(%q, %q) = %v, want %v",
					tc.x, tc.y, got, tc.want)
			}
		})
	}
}

func TestEncodeSecret(t *testing.T) {
	tests := []struct {
		name   string
		secret []byte
		want   string
	}{
		{
			name:   "RFC 4226 SHA1 secret",
			secret: rfc6238sha1secret,
			want:   "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		},
		{
			name:   "RFC 6238 SHA256 secret",
			secret: rfc6238sha256secret,
			want:   "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA",
		},
		{
			name:   "empty",
			secret: []byte{},
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EncodeSecret(tc.secret)
			if got != tc.want {
				t.Errorf("EncodeSecret() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDecodeSecret(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:  "uppercase",
			input: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
			want:  rfc6238sha1secret,
		},
		{
			name:  "lowercase accepted",
			input: "gezdgnbvgy3tqojqgezdgnbvgy3tqojq",
			want:  rfc6238sha1secret,
		},
		{
			name:  "mixed case accepted",
			input: "GezdGnbvGY3TQOJQgezdgnbvgy3tqojq",
			want:  rfc6238sha1secret,
		},
		{
			name:  "empty string",
			input: "",
			want:  []byte{},
		},
		{
			name:    "invalid base32",
			input:   "!!!",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeSecret(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DecodeSecret() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && !bytes.Equal(got, tc.want) {
				t.Errorf("DecodeSecret() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSecretRoundTrip(t *testing.T) {
	secrets := [][]byte{
		rfc6238sha1secret,
		rfc6238sha256secret,
		rfc6238sha512secret,
	}
	for _, secret := range secrets {
		encoded := EncodeSecret(secret)
		decoded, err := DecodeSecret(encoded)
		if err != nil {
			t.Fatalf("DecodeSecret(%q) error: %v", encoded, err)
		}
		if !bytes.Equal(decoded, secret) {
			t.Errorf("round-trip mismatch: got %v, want %v", decoded, secret)
		}
	}
}

func TestGenerateSecret(t *testing.T) {
	tests := []struct {
		name    string
		n       uint
		wantErr bool
	}{
		{"too short", 15, true},
		{"zero", 0, true},
		{"minimum 16 bytes", 16, false},
		{"20 bytes", 20, false},
		{"32 bytes", 32, false},
		{"64 bytes", 64, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateSecret(tc.n)
			if (err != nil) != tc.wantErr {
				t.Errorf("GenerateSecret() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr {
				if uint(len(got)) != tc.n {
					t.Errorf("GenerateSecret() len = %d, want %d", len(got), tc.n)
				}
				if len(got) == 0 {
					t.Error("GenerateSecret() returned empty slice")
				}
			}
		})
	}

	t.Run("unique outputs", func(t *testing.T) {
		a, err := GenerateSecret(32)
		if err != nil {
			t.Fatal(err)
		}
		b, err := GenerateSecret(32)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, b) {
			t.Error("GenerateSecret() returned identical secrets on consecutive calls")
		}
	})
}
