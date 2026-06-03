package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
	"time"

	"github.com/bnixon67/otp"
)

// totpAlgorithm has the secret and hash function for a TOTP algorithm variant.
type totpAlgorithm struct {
	secret   string
	hashFunc func() hash.Hash
}

// totpTestVector holds a single RFC 6238 TOTP test vector.
type totpTestVector struct {
	utcTime  string
	expected string
	algo     string
}

var totpAlgorithms = map[string]totpAlgorithm{
	"SHA1": {
		secret:   "12345678901234567890",
		hashFunc: sha1.New,
	},
	"SHA256": {
		secret:   "12345678901234567890123456789012",
		hashFunc: sha256.New,
	},
	"SHA512": {
		secret:   "1234567890123456789012345678901234567890123456789012345678901234",
		hashFunc: sha512.New,
	},
}

var totpTestVectors = []totpTestVector{
	{"1970-01-01 00:00:59", "94287082", "SHA1"},
	{"1970-01-01 00:00:59", "46119246", "SHA256"},
	{"1970-01-01 00:00:59", "90693936", "SHA512"},
	{"2005-03-18 01:58:29", "07081804", "SHA1"},
	{"2005-03-18 01:58:29", "68084774", "SHA256"},
	{"2005-03-18 01:58:29", "25091201", "SHA512"},
	{"2005-03-18 01:58:31", "14050471", "SHA1"},
	{"2005-03-18 01:58:31", "67062674", "SHA256"},
	{"2005-03-18 01:58:31", "99943326", "SHA512"},
	{"2009-02-13 23:31:30", "89005924", "SHA1"},
	{"2009-02-13 23:31:30", "91819424", "SHA256"},
	{"2009-02-13 23:31:30", "93441116", "SHA512"},
	{"2033-05-18 03:33:20", "69279037", "SHA1"},
	{"2033-05-18 03:33:20", "90698825", "SHA256"},
	{"2033-05-18 03:33:20", "38618901", "SHA512"},
	{"2603-10-11 11:33:20", "65353130", "SHA1"},
	{"2603-10-11 11:33:20", "77737706", "SHA256"},
	{"2603-10-11 11:33:20", "47863826", "SHA512"},
}

const timeLayout = "2006-01-02 15:04:05"

// totpExample demonstrates TOTP generation and validation using RFC 6238 test vectors.
func totpExample() {
	const digits = uint(8)
	const window = 1

	fmt.Printf("%-22s %-10s %-8s %-8s %s\n", "UTC Time", "Generated", "Expected", "Algo", "Valid (Counter)")

	for _, v := range totpTestVectors {
		algo, ok := totpAlgorithms[v.algo]
		if !ok {
			log.Fatalf("unknown TOTP algorithm: %s", v.algo)
		}

		t, err := time.Parse(timeLayout, v.utcTime)
		if err != nil {
			log.Fatalf("time.Parse(%q): %v", v.utcTime, err)
		}

		secret := []byte(algo.secret)
		opts := otp.TOTPOptions{Digits: digits, HashFunc: algo.hashFunc}

		generated, err := otp.GenerateTOTP(secret, t, opts)
		if err != nil {
			log.Fatalf("GenerateTOTP(%s, %s): %v", v.utcTime, v.algo, err)
		}

		matched, counter, err := otp.ValidateTOTP(secret, v.expected, t, window, opts)
		if err != nil {
			log.Fatalf("ValidateTOTP(%s, %s): %v", v.utcTime, v.algo, err)
		}

		fmt.Printf("%-22s %-10s %-8s %-8s %v (%d)\n",
			v.utcTime, generated, v.expected, v.algo, matched, counter)
	}
}
