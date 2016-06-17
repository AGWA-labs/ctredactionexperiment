// Copyright (C) 2016 Opsmate, Inc.
//
// This Source Code Form is subject to the terms of the Mozilla
// Public License, v. 2.0. If a copy of the MPL was not distributed
// with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This software is distributed WITHOUT A WARRANTY OF ANY KIND.
// See the Mozilla Public License for details.

package main

import (
	"io/ioutil"
	"os"
	"fmt"
)

func main() {
	certBytes, _ := ioutil.ReadAll(os.Stdin)
	cert, err := ParseCertificate(certBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parsing certificate failed: %s\n", err)
		os.Exit(1)
	}

	tbs, err := cert.ParseTBSCertificate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Parsing TBSCertificate failed: %s\n", err)
		os.Exit(1)
	}

	precertTBS, err := ReconstructPrecertTBS(tbs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Reconstructing pre-cert TBSCertificate failed: %s\n", err)
		os.Exit(1)
	}

	os.Stdout.Write(precertTBS.Raw)
}
