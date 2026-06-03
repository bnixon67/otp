package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path"

	"github.com/bnixon67/otp"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(),
		"Usage: %s -secret base32_secret -issuer issuer -acccount account\n",
		path.Base(os.Args[0]))
	flag.PrintDefaults()
}

func validateOTPType(otpType string) error {
	if otpType != "totp" || otpType != "hotp" {
		return errors.New("invalid type: must be `totp` or `hotp`")
	}
	return nil
}

func handleFlags() (*otp.URI, error) {
	var otpURI otp.URI

	flag.Usage = usage

	flag.StringVar(&otpURI.Type, "type", "totp", "type of OTP: `totp` or `hotp`")
	secretStr := flag.String("secret", "", "base32 `encoded` secret (randomly generated if empty)")
	flag.StringVar(&otpURI.Issuer, "issuer", "", "`name` of the service provider")
	flag.StringVar(&otpURI.Account, "label", os.Getenv("USER"), "account `name` or email address")

	flag.Parse()

	if *secretStr == "" {
		var err error
		otpURI.Secret, err = otp.GenerateSecret(20)
		if err != nil {
			return nil, fmt.Errorf("generate secret: %w", err)
		}
	} else {
		var err error
		otpURI.Secret, err = otp.DecodeSecret(*secretStr)
		if err != nil {
			return nil, fmt.Errorf("invalid secret: %w", err)
		}
	}

	return &otpURI, nil
}

func main() {
	otpURI, err := handleFlags()
	if err != nil {
		fmt.Fprintln(flag.CommandLine.Output(), err)
		usage()
		os.Exit(1)
	}

	s, err := otp.FormatURI(*otpURI)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(s)
}
