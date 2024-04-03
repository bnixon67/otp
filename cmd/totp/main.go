// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
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

func parseFlags() (secret string, digits uint, timeString, hash string) {
	flag.StringVar(&secret, "secret", "", "Base32 encoded secret")
	flag.UintVar(&digits, "digits", 6, "Number of digits")
	flag.StringVar(&timeString, "time", time.Now().Format(timeFormat), "Timestamp for OTP (default: now)")
	flag.StringVar(&hash, "hash", "sha1", "Hash function (sha1, sha256, sha512)")
	flag.Parse()
	return
}

func validateSecret(secret string) error {
	if secret == "" {
		return errors.New("secret flag is required")
	}
	return nil
}

func parseTime(timeString string) (time.Time, error) {
	return time.Parse(timeFormat, timeString)
}

func decodeSecret(secret string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(secret)
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

func printErrorAndExit(err error, exitCode int) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
	fmt.Printf("Usage: %s -secret base32_secret -digits number -time time -hash function\n", path.Base(os.Args[0]))
	flag.PrintDefaults()
	os.Exit(exitCode)
}

func printTOTP(totp string, parsedTime time.Time, digits uint, hashName string) {
	fmt.Printf("%s %v digits=%d hash=%s\n",
		totp, parsedTime.Format(timeFormat), digits, hashName)
}

func main() {
	secret, digits, timeString, hashName := parseFlags()

	if err := validateSecret(secret); err != nil {
		printErrorAndExit(err, 1)
	}

	parsedTime, err := parseTime(timeString)
	if err != nil {
		printErrorAndExit(err, 2)
	}

	data, err := decodeSecret(secret)
	if err != nil {
		printErrorAndExit(err, 3)
	}

	hashFunc, err := hashFunction(hashName)
	if err != nil {
		printErrorAndExit(err, 4)
	}

	totp, err := otp.GenerateTOTP(data, parsedTime, digits, hashFunc)
	if err != nil {
		printErrorAndExit(err, 5)
	}

	printTOTP(totp, parsedTime, digits, hashName)
}
