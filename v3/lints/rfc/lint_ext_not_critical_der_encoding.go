package rfc

/*
 * ZLint Copyright 2023 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

import (
	encoding_asn1 "encoding/asn1"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3/lint"
	"github.com/zmap/zlint/v3/util"
)

type extNotCriticalOmitsDefault struct{}

func init() {
	lint.RegisterLint(&lint.Lint{
		Name:          "e_ext_not_critical_omits_default",
		Description:   "The DER encoding of SET or SEQUENCE components whose value is the DEFAULT omit the component from the encoded certificate or CRL.",
		Citation:      "RFC 5280: Appendix B",
		Source:        lint.RFC5280,
		EffectiveDate: util.RFC5280Date,
		Lint:          NewExtNotCriticalOmitsDefault,
	})
}

func NewExtNotCriticalOmitsDefault() lint.LintInterface {
	return &extNotCriticalOmitsDefault{}
}

func (l *extNotCriticalOmitsDefault) CheckApplies(c *x509.Certificate) bool {
	return len(c.Extensions) > 0
}

func (l *extNotCriticalOmitsDefault) Execute(c *x509.Certificate) *lint.LintResult {
	der := cryptobyte.String(c.RawTBSCertificate)
	var tbs cryptobyte.String
	// TBSCertificate  ::=  SEQUENCE  {
	if !der.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate"}
	}

	//   version         [0]  EXPLICIT Version DEFAULT v1,
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.version"}
	}

	//   serialNumber         CertificateSerialNumber,
	if !tbs.SkipASN1(cryptobyte_asn1.INTEGER) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.serialNumber"}
	}

	//   signature            AlgorithmIdentifier,
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.signature"}
	}

	//   issuer               Name,
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.issuer"}
	}

	//   validity             Validity,
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.validity"}
	}

	//   subject              Name,
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.subject"}
	}

	//   subjectPublicKeyInfo SubjectPublicKeyInfo,
	if !tbs.SkipASN1(cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.subjectPublicKeyInfo"}
	}

	//   issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(1).ContextSpecific()) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.issuerUniqueID"}
	}

	//   subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(2).ContextSpecific()) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.subjectUniqueID"}
	}

	//   extensions      [3]  EXPLICIT Extensions OPTIONAL
	var extensions cryptobyte.String
	var present bool
	if !tbs.ReadOptionalASN1(&extensions, &present, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.extensions"}
	}
	// }

	if !present {
		return &lint.LintResult{Status: lint.Pass}
	}

	// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
	if !extensions.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) {
		return &lint.LintResult{Status: lint.Fatal, Details: "error reading tbsCertificate.extensions"}
	}

	var invalid []string
	for !extensions.Empty() {
		var ext cryptobyte.String
		// Extension  ::=  SEQUENCE  {
		if !extensions.ReadASN1(&ext, cryptobyte_asn1.SEQUENCE) {
			return &lint.LintResult{Status: lint.Fatal, Details: "error reading extension"}
		}

		//   extnID      OBJECT IDENTIFIER,
		var oid encoding_asn1.ObjectIdentifier
		if !ext.ReadASN1ObjectIdentifier(&oid) {
			return &lint.LintResult{Status: lint.Fatal, Details: "error reading extension.extnID"}
		}

		//   critical    BOOLEAN DEFAULT FALSE,
		if ext.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
			var critical bool
			if !ext.ReadASN1Boolean(&critical) {
				return &lint.LintResult{Status: lint.Fatal, Details: "error reading extension.critical"}
			}
			// BOOLEAN { FALSE } is invalid DER. Default values must be omitted.
			if !critical {
				invalid = append(invalid, oid.String())
			}
		}

		//   extnValue   OCTET STRING
		if !ext.SkipASN1(cryptobyte_asn1.OCTET_STRING) {
			return &lint.LintResult{Status: lint.Fatal, Details: "error reading extension.extnValue"}
		}
		// }
	}

	if len(invalid) > 0 {
		return &lint.LintResult{
			Status:  lint.Error,
			Details: fmt.Sprintf("The following extensions encode the default value of critical: %s", strings.Join(invalid, ", ")),
		}
	}

	return &lint.LintResult{Status: lint.Pass}
}
