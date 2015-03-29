package dkim

import "strings"

func (v *VerifiedEmail) CanonHeaders() string {
	var canonHeaders []string
	for _, header := range append(v.Headers, v.Signature.canonHeader) {
		canonHeaders = append(canonHeaders, v.Signature.canon.header(header))
	}
	return strings.Join(canonHeaders, "")
}

func (v *VerifiedEmail) ExtractHeader(name string) []string {
	return extractHeaders(v.Headers, []string{name})
}
