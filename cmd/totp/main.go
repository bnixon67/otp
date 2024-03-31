// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package main

import (
	"encoding/base32"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/bnixon67/otp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Usage: %s BASE32_ENCODED_SECRET\n", path.Base(os.Args[0]))
		os.Exit(1)
	}

	secret := os.Args[1]

	// Decode the Base32 encoded secret
	data, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Printf("Failed to decode the secret: %v\n", err)
		os.Exit(2)
	}

	totp, err := otp.GenerateTOTP(data, time.Now(), uint(6), nil)
	if err != nil {
		fmt.Printf("Failed to generate TOTP: %v\n", err)
		os.Exit(2)
	}

	fmt.Println(totp)
}
