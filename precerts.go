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
	"errors"
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"crypto/sha256"
)

var (
	oidExtensionAuthorityKeyId	= []int{2, 5, 29, 35}
	oidExtensionSCT			= []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	oidExtensionCTPoison		= []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	oidExtensionRedactedSANs	= []int{1, 3, 6, 1, 4, 1, 46450, 5, 123, 1}
	oidExtensionRedactedLabelSalt	= []int{1, 3, 6, 1, 4, 1, 46450, 5, 123, 2}
)

func hashLabel (label []byte, redactedLabelSalt []byte) []byte {
	hash := sha256.New()
	hash.Write(redactedLabelSalt)
	hash.Write(label)
	return []byte(hex.EncodeToString(hash.Sum(nil)))
}

func verifyDNSRedaction (dnsName []byte, redactedDNSName []byte, redactedLabelSalt []byte) error {
	// TODO: check for over-redaction (e.g. ?.com)
	labels := bytes.Split(dnsName, []byte{'.'})
	redactedLabels := bytes.Split(redactedDNSName, []byte{'.'})

	if len(labels) != len(redactedLabels) {
		return errors.New("Redacted and unredacted DNS name have different number of labels")
	}

	for i := range labels {
		label := labels[i]
		redactedLabel := redactedLabels[i]

		if len(redactedLabel) > 0 && redactedLabel[0] == '?' {
			if bytes.Equal(label, []byte{'*'}) {
				return errors.New("Wildcard label was redacted")
			}
			if !bytes.Equal(redactedLabel[1:], hashLabel(label, redactedLabelSalt)) {
				return errors.New("Redacted label does not match")
			}
		} else {
			if !bytes.Equal(redactedLabel, label) {
				return errors.New("Unredacted label does not match")
			}
		}
	}
	return nil
}

func verifyRedaction (sansBytes []byte, redactedSANsBytes []byte, redactedLabelSalt []byte) error {
	sans, err := parseSANExtension(nil, sansBytes)
	if err != nil {
		return err
	}

	redactedSANs, err := parseSANExtension(nil, redactedSANsBytes)
	if err != nil {
		return err
	}

	if len(sans) != len(redactedSANs) {
		return errors.New("SANs extension and Redacted SANs extension have different lengths")
	}

	for i := range sans {
		san := sans[i]
		redactedSAN := redactedSANs[i]
		if san.Type != redactedSAN.Type {
			return errors.New("SAN and corresponding redacted SAN have different types")
		}
		switch san.Type {
		case sanDNSName:
			if err := verifyDNSRedaction(san.Value, redactedSAN.Value, redactedLabelSalt); err != nil {
				return err
			}
		default:
			if !bytes.Equal(san.Value, redactedSAN.Value) {
				return errors.New("Non-DNS SAN has different value in Redacted SANs extension")
			}
		}
	}

	return nil
}

func ReconstructPrecertTBS (tbs *TBSCertificate) (*TBSCertificate, error) {
	var sans []byte
	var redactedSANs []byte
	var redactedLabelSalt []byte

	for _, ext := range tbs.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionSubjectAltName):
			sans = ext.Value
		case ext.Id.Equal(oidExtensionRedactedSANs):
			redactedSANs = ext.Value
		case ext.Id.Equal(oidExtensionRedactedLabelSalt):
			redactedLabelSalt = ext.Value
		}
	}

	if redactedSANs != nil {
		if sans == nil {
			return nil, errors.New("Certificate contains redacted SAN extension but no SAN extension")
		}
		if redactedLabelSalt == nil {
			return nil, errors.New("Certificate contains redacted SAN extension but no redacted label salt extension")
		}
		if err := verifyRedaction(sans, redactedSANs, redactedLabelSalt); err != nil {
			return nil, err
		}
	}

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
		case ext.Id.Equal(oidExtensionRedactedLabelSalt):
		case ext.Id.Equal(oidExtensionSubjectAltName):
			if redactedSANs == nil {
				precertTBS.Extensions = append(precertTBS.Extensions, ext)
			}
		default:
			precertTBS.Extensions = append(precertTBS.Extensions, ext)
		}
	}

	var err error
	precertTBS.Raw, err = asn1.Marshal(precertTBS)
	return &precertTBS, err
}
