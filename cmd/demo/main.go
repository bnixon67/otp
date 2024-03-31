// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package main

import (
	"crypto/sha1" // skipcq: GSC-G505
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"time"

	"github.com/bnixon67/otp"
)

func main() {
	// Example of HOTP from RFC 4226
	key := []byte("12345678901234567890")
	digits := uint(6)
	fmt.Println("Count\tHOTP")
	for count := range uint64(10) {
		hotp, err := otp.GenerateHOTP(key, count, digits)
		if err != nil {
			fmt.Println("Error generating OTP:", err)
			return
		}
		fmt.Printf("%d\t%s\n", count, hotp)
	}

	fmt.Println()

	// Example of TOTP from RFC 6238
	fmt.Println("Time\t\t\t\tTOTP\t\tMode")
	totp("1970-01-01 00:00:59", "SHA1")
	totp("1970-01-01 00:00:59", "SHA256")
	totp("1970-01-01 00:00:59", "SHA512")
}

type hashConstructor func() hash.Hash

func totp(timeStr, hash string) {
	layout := "2006-01-02 15:04:05"
	time, err := time.Parse(layout, timeStr)
	if err != nil {
		fmt.Println(err)
		return
	}

	var key []byte
	var hashFunc hashConstructor

	switch hash {
	case "SHA1":
		key = []byte("12345678901234567890")
		hashFunc = sha1.New
	case "SHA256":
		key = []byte("12345678901234567890123456789012")
		hashFunc = sha256.New
	case "SHA512":
		key = []byte("1234567890123456789012345678901234567890123456789012345678901234")
		hashFunc = sha512.New
	}

	totp, err := otp.GenerateTOTP(key, time, 8, hashFunc)
	if err != nil {
		fmt.Println("Could not generate TOTP")
		return
	}

	fmt.Printf("%s\t%s\t%s\n", time, totp, hash)
}
