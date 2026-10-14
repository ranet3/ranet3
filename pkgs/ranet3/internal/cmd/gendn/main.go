// SPDX-FileCopyrightText: 2026 Nick Cao
// SPDX-License-Identifier: MIT

// gendn prints the strongSwan "asn1dn:#hex" identity string for a given
// organization/common-name/serial-number triple, using the exact same DER
// encoding the ike package uses for IDi/IDr payloads. Used to build test
// swanctl.conf fixtures and to help operators mirror ranet's identity
// scheme when configuring a strongSwan responder by hand.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	"ranet3.com/pkgs/ranet3/identity"
)

func main() {
	org := flag.String("org", "", "organization")
	cn := flag.String("cn", "", "common name")
	serial := flag.String("serial", "", "serial number")
	flag.Parse()
	id, err := identity.From(*org, *cn, *serial)
	if err != nil {
		log.Fatal(err)
	}
	dn, err := id.DN()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("asn1dn:#%s\n", hex.EncodeToString(dn))
}
