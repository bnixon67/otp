// Copyright 2024 Bill Nixon. All rights reserved. Use of this source code
// is governed by the license found in the LICENSE file.

package otp

import (
	"crypto/sha1" // skipcq: GSC-G505
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// URI represents a parsed otpauth:// URI as defined by the Google
// Authenticator Key URI Format specification.
type URI struct {
	Type      string // "totp" or "hotp"
	Issuer    string
	Account   string
	Secret    []byte // raw bytes (decoded from base32)
	Algorithm string // "SHA1", "SHA256", or "SHA512"; empty defaults to SHA1
	Digits    uint   // 0 defaults to 6
	Period    int64  // TOTP: seconds per window; 0 defaults to 30
	Counter   uint64 // HOTP: initial counter value
}

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// hashFuncByName returns the HashFunc for a named algorithm.
// An empty name is treated as "SHA1" per the otpauth URI spec default.
func hashFuncByName(name string) (HashFunc, error) {
	switch strings.ToUpper(name) {
	case "", "SHA1":
		return sha1.New, nil // skipcq: GSC-G505
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", name)
	}
}

// HashFunc returns the hash constructor for the URI's Algorithm field.
func (u URI) HashFunc() (HashFunc, error) {
	return hashFuncByName(u.Algorithm)
}

// TOTPOptions converts the URI into a TOTPOptions value ready for use with
// GenerateTOTP or ValidateTOTP. Zero-value fields use their spec defaults
// (SHA1, 6 digits, 30-second period) via TOTPOptions.withDefaults.
func (u URI) TOTPOptions() (TOTPOptions, error) {
	h, err := u.HashFunc()
	if err != nil {
		return TOTPOptions{}, err
	}
	return TOTPOptions{
		HashFunc: h,
		Digits:   u.Digits,
		TimeStep: u.Period,
	}, nil
}

func (u URI) validate() error {
	switch u.Type {
	case "totp", "hotp":
	default:
		return fmt.Errorf("invalid type %q", u.Type)
	}
	if u.Account == "" {
		return errors.New("account is required")
	}
	if len(u.Secret) < minSecretLen {
		return fmt.Errorf("secret must be at least %d bytes", minSecretLen)
	}
	if u.Algorithm != "" {
		if _, err := hashFuncByName(u.Algorithm); err != nil {
			return err
		}
	}
	if u.Digits != 0 && int(u.Digits) >= len(pow10) {
		return fmt.Errorf("digits must be between 1 and %d", len(pow10)-1)
	}
	if u.Type == "totp" && u.Period < 0 {
		return errors.New("period must be > 0")
	}
	return nil
}

// ParseURI parses an otpauth:// URI and returns a URI.
// The secret query parameter is base32-decoded into URI.Secret.
// Period (TOTP) and Counter (HOTP) are always set, using spec defaults when
// the parameter is absent. Algorithm is normalized to uppercase.
func ParseURI(rawURI string) (URI, error) {
	u, err := url.Parse(rawURI)
	if err != nil {
		return URI{}, fmt.Errorf("parse uri: %w", err)
	}
	if u.Scheme != "otpauth" {
		return URI{}, fmt.Errorf("parse uri: scheme must be \"otpauth\", got %q", u.Scheme)
	}

	var otpType string
	switch u.Host {
	case "totp":
		otpType = "totp"
	case "hotp":
		otpType = "hotp"
	default:
		return URI{}, fmt.Errorf("parse uri: invalid type %q", u.Host)
	}

	// Label is the URL-decoded path without its leading slash.
	// A "issuer:account" prefix is split on the first colon.
	label, err := url.PathUnescape(strings.TrimPrefix(u.Path, "/"))
	if err != nil {
		return URI{}, fmt.Errorf("parse uri: invalid label: %w", err)
	}
	var issuer, account string
	if idx := strings.IndexByte(label, ':'); idx >= 0 {
		issuer = label[:idx]
		account = strings.TrimSpace(label[idx+1:])
	} else {
		account = label
	}

	params := u.Query()

	secretStr := params.Get("secret")
	if secretStr == "" {
		return URI{}, errors.New("parse uri: secret is required")
	}
	secret, err := base32NoPad.DecodeString(strings.ToUpper(secretStr))
	if err != nil {
		return URI{}, fmt.Errorf("parse uri: invalid secret: %w", err)
	}

	// Issuer query param takes precedence over the label prefix.
	if q := params.Get("issuer"); q != "" {
		issuer = q
	}

	algorithm := "SHA1"
	if a := params.Get("algorithm"); a != "" {
		algorithm = strings.ToUpper(a)
		if _, err := hashFuncByName(algorithm); err != nil {
			return URI{}, fmt.Errorf("parse uri: %w", err)
		}
	}

	digits := uint(6)
	if d := params.Get("digits"); d != "" {
		n, err := strconv.ParseUint(d, 10, 64)
		if err != nil || n == 0 {
			return URI{}, errors.New("parse uri: invalid digits")
		}
		digits = uint(n)
	}

	result := URI{
		Type:      otpType,
		Issuer:    issuer,
		Account:   account,
		Secret:    secret,
		Algorithm: algorithm,
		Digits:    digits,
	}

	switch otpType {
	case "totp":
		result.Period = DefaultTimeStepSeconds
		if p := params.Get("period"); p != "" {
			n, err := strconv.ParseInt(p, 10, 64)
			if err != nil || n <= 0 {
				return URI{}, errors.New("parse uri: period must be a positive integer")
			}
			result.Period = n
		}

	case "hotp":
		c := params.Get("counter")
		if c == "" {
			return URI{}, errors.New("parse uri: counter is required for hotp")
		}
		n, err := strconv.ParseUint(c, 10, 64)
		if err != nil {
			return URI{}, fmt.Errorf("parse uri: invalid counter: %w", err)
		}
		result.Counter = n
	}

	return result, nil
}

// FormatURI encodes a URI as an otpauth:// string.
// Default values (SHA1, 6 digits, 30-second period) are omitted from the
// output. URI.Secret is base32-encoded without padding.
func FormatURI(u URI) (string, error) {
	if err := u.validate(); err != nil {
		return "", fmt.Errorf("format uri: %w", err)
	}

	label := url.PathEscape(u.Account)
	if u.Issuer != "" {
		label = url.PathEscape(u.Issuer) + ":" + label
	}

	params := url.Values{}
	params.Set("secret", base32NoPad.EncodeToString(u.Secret))

	if u.Issuer != "" {
		params.Set("issuer", u.Issuer)
	}

	if alg := strings.ToUpper(u.Algorithm); alg != "" && alg != "SHA1" {
		params.Set("algorithm", alg)
	}

	if u.Digits != 0 && u.Digits != 6 {
		params.Set("digits", strconv.FormatUint(uint64(u.Digits), 10))
	}

	switch u.Type {
	case "totp":
		if u.Period != 0 && u.Period != DefaultTimeStepSeconds {
			params.Set("period", strconv.FormatInt(u.Period, 10))
		}
	case "hotp":
		params.Set("counter", strconv.FormatUint(u.Counter, 10))
	}

	return "otpauth://" + string(u.Type) + "/" + label + "?" + params.Encode(), nil
}
