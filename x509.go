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
	"fmt"
	"errors"
	"encoding/asn1"
)

var (
	oidExtensionSubjectAltName	= asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints	= asn1.ObjectIdentifier{2, 5, 29, 19}
	oidCountry		        = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization			= asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit		= asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName			= asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber			= asn1.ObjectIdentifier{2, 5, 4, 5}
	oidLocality			= asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince			= asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress		= asn1.ObjectIdentifier{2, 5, 4, 9}
	oidPostalCode			= asn1.ObjectIdentifier{2, 5, 4, 17}
)

type Extension struct {
	Id		asn1.ObjectIdentifier
	Critical	bool `asn1:"optional"`
	Value		[]byte
}

const (
	sanOtherName		= 0
	sanRfc822Name		= 1
	sanDNSName		= 2
	sanX400Address		= 3
	sanDirectoryName	= 4
	sanEdiPartyName		= 5
	sanURI			= 6
	sanIPAddress		= 7
	sanRegisteredID		= 8
)
type SubjectAltName struct {
	Type		int
	Value		[]byte
}

type RDNSequence []RelativeDistinguishedNameSET
type RelativeDistinguishedNameSET []AttributeTypeAndValue
type AttributeTypeAndValue struct {
	Type	asn1.ObjectIdentifier
	Value	asn1.RawValue
}

type TBSCertificate struct {
	Raw			asn1.RawContent

	Version			int		`asn1:"optional,explicit,default:1,tag:0"`
	SerialNumber		asn1.RawValue
	SignatureAlgorithm	asn1.RawValue
	Issuer			asn1.RawValue
	Validity		asn1.RawValue
	Subject			asn1.RawValue
	PublicKey		asn1.RawValue
	UniqueId		asn1.BitString	`asn1:"optional,tag:1"`
	SubjectUniqueId		asn1.BitString	`asn1:"optional,tag:2"`
	Extensions		[]Extension	`asn1:"optional,explicit,tag:3"`
}

type Certificate struct {
	Raw			asn1.RawContent

	TBSCertificate		asn1.RawValue
	SignatureAlgorithm	asn1.RawValue
	SignatureValue		asn1.RawValue
}


func ParseTBSCertificate (tbsBytes []byte) (*TBSCertificate, error) {
	var tbs TBSCertificate
	if rest, err := asn1.Unmarshal(tbsBytes, &tbs); err != nil {
		return nil, errors.New("failed to parse TBS: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after TBS: %v", rest)
	}
	return &tbs, nil
}

func ParseCertificate (certBytes []byte) (*Certificate, error) {
	var cert Certificate
	if rest, err := asn1.Unmarshal(certBytes, &cert); err != nil {
		return nil, errors.New("failed to parse certificate: " + err.Error())
	} else if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after certificate: %v", rest)
	}
	return &cert, nil
}

func (cert *Certificate) GetRawTBSCertificate () []byte {
	return cert.TBSCertificate.FullBytes
}

func (cert *Certificate) ParseTBSCertificate () (*TBSCertificate, error) {
	return ParseTBSCertificate(cert.GetRawTBSCertificate())
}

func parseSANExtension (sans []SubjectAltName, value []byte) ([]SubjectAltName, error) {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(value, &seq); err != nil {
		return nil, errors.New("failed to parse subjectAltName extension: " + err.Error())
	} else if len(rest) != 0 {
		// Don't complain if the SAN is followed by exactly one zero byte,
		// which is a common error.
		if !(len(rest) == 1 && rest[0] == 0) {
			return nil, fmt.Errorf("trailing data in subjectAltName extension: %v", rest)
		}
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return nil, errors.New("failed to parse subjectAltName extension: bad SAN sequence")
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var val asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &val)
		if err != nil {
			return nil, errors.New("failed to parse subjectAltName extension item: " + err.Error())
		}
		sans = append(sans, SubjectAltName{Type: val.Tag, Value: val.Bytes})
	}

	return sans, nil
}

