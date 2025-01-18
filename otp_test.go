package otp_test

import (
	"testing"

	"github.com/bnixon67/otp"
)

func TestValidateOTP(t *testing.T) {
	tests := []struct {
		x, y string
		want bool
	}{
		{"123456", "123456", true},
		{"123456", "654321", false},
		{"123456", "12345", false},
		{"", "", true},
	}

	for _, test := range tests {
		if got := otp.Validate(test.x, test.y); got != test.want {
			t.Errorf("ValidateOTP(%q, %q) = %v; want %v", test.x, test.y, got, test.want)
		}
	}
}
