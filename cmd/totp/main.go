// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package main

import (
	"crypto/sha1" // skipcq: GSC-G505
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"hash"
	"os"
	"path"
	"strings"
	"time"

	"github.com/bnixon67/otp"
)

const timeFormat = time.RFC3339

func parseTime(timeString string) (time.Time, error) {
	return time.Parse(timeFormat, timeString)
}

func hashFunction(hashName string) (func() hash.Hash, error) {
	switch strings.ToLower(hashName) {
	case "sha1":
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	}
	return nil, errors.New("invalid hash name")
}

func printTOTP(totp string, parsedTime time.Time, digits uint, hashName string) {
	fmt.Printf("%s %v digits=%d hash=%s\n",
		totp, parsedTime.Format(timeFormat), digits, hashName)
}

func runTOTP(secret string, digits uint, timeString, hashName string) error {
	if secret == "" {
		return errors.New("secret is required")
	}

	data, err := otp.DecodeSecret(secret)
	if err != nil {
		return fmt.Errorf("invalid secret: %w", err)
	}

	parsedTime, err := parseTime(timeString)
	if err != nil {
		return err
	}

	hashFunc, err := hashFunction(hashName)
	if err != nil {
		return err
	}

	opts := otp.TOTPOptions{Digits: digits, HashFunc: hashFunc}
	totp, err := otp.GenerateTOTP(data, parsedTime, opts)
	if err != nil {
		return err
	}

	printTOTP(totp, parsedTime, digits, hashName)

	return nil
}

func usage(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	fmt.Fprintf(os.Stderr, "Usage: %s -secret base32_secret -digits number -time time -hash function\n", path.Base(os.Args[0]))
	flag.PrintDefaults()
}

func main() {
	secret := flag.String("secret", "", "Base32 encoded secret")
	digits := flag.Uint("digits", 6, "Number of digits")
	timeString := flag.String("time", time.Now().Format(timeFormat), "Timestamp for OTP (default: now)")
	hashName := flag.String("hash", "sha1", "Hash function (sha1, sha256, sha512)")
	flag.Parse()

	err := runTOTP(*secret, *digits, *timeString, *hashName)
	if err != nil {
		usage(err)
		os.Exit(1)
	}
}
