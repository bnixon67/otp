// Copyright 2024 Bill Nixon. All rights reserved.
// Use of this source code is governed by the license found in the LICENSE file.

package main

import (
	"fmt"
)

func main() {
	fmt.Println("=== HOTP (RFC 4226) ===")
	hotpExample()

	fmt.Println()

	fmt.Println("=== TOTP (RFC 6238) ===")
	totpExample()
}
