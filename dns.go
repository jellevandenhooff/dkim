package dkim

import (
	"errors"
	"strings"

	"github.com/miekg/dns"
)

// A DNSClient can look up TXT records.
type DNSClient interface {
	LookupTxt(hostname string) ([]string, error)
}

// SimpleDNSClient uses miekg/dns to look up TXT records, and supports falling
// back to TCP for big records.
//
// Exists because Go's built-in DNS client has problems with some TXT records.
type SimpleDNSClient struct {
	Server string
}

// LookupTxt queries the underlying server for TXT records for the given
// hostname.
func (s *SimpleDNSClient) LookupTxt(hostname string) ([]string, error) {
	// build the DNS query
	m := new(dns.Msg)
	m.SetQuestion(hostname, dns.TypeTXT)

	// try getting over UDP
	c := new(dns.Client)
	r, _, e := c.Exchange(m, s.Server)
	if e != nil {
		return nil, e
	}

	if r.Truncated {
		// try again with TCP for large messages
		c.Net = "tcp"
		r, _, e = c.Exchange(m, s.Server)
		if e != nil {
			return nil, e
		}
	}

	// parse TXT answers into strings
	var res []string
	for _, answer := range r.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok {
			return nil, errors.New("expected TXT")
		}
		// concatenate each multi-part answer into a single string
		res = append(res, strings.Join(txt.Txt, ""))
	}
	return res, nil
}
