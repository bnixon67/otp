package main

import (
	"fmt"
	"log"

	"github.com/bnixon67/otp"
)

// hotpExample demonstrates HOTP generation using the RFC 4226 test vectors.
func hotpExample() {
	key := []byte("12345678901234567890")
	const digits = uint(6)

	fmt.Println("Count\tHOTP")
	for count := range uint64(10) {
		hotp, err := otp.GenerateHOTP(key, count, digits)
		if err != nil {
			log.Fatalf("GenerateHOTP(count=%d): %v", count, err)
		}
		fmt.Printf("%d\t%s\n", count, hotp)
	}
}
