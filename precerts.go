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
	"encoding/asn1"
)

var (
	oidExtensionAuthorityKeyId	= []int{2, 5, 29, 35}
	oidExtensionSCT			= []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidExtensionCTPoison		= []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
)

func ReconstructPrecertTBS (tbs *TBSCertificate) (*TBSCertificate, error) {
	precertTBS := TBSCertificate{
		Version:		tbs.Version,
		SerialNumber:		tbs.SerialNumber,
		SignatureAlgorithm:	tbs.SignatureAlgorithm,
		Issuer:			tbs.Issuer,
		Validity:		tbs.Validity,
		Subject:		tbs.Subject,
		PublicKey:		tbs.PublicKey,
		UniqueId:		tbs.UniqueId,
		SubjectUniqueId:	tbs.SubjectUniqueId,
		Extensions:		make([]Extension, 0, len(tbs.Extensions)),
	}

	for _, ext := range tbs.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionSCT):
		default:
			precertTBS.Extensions = append(precertTBS.Extensions, ext)
		}
	}

	var err error
	precertTBS.Raw, err = asn1.Marshal(precertTBS)
	return &precertTBS, err
}
