package dkim

import "testing"

func TestRelaxBody(t *testing.T) {
	if relaxBody("") != "" {
		t.Error("empty body is relax special case")
	}
	if relaxBody(" \ta  \r\n b  c \r\n\r\n") != " a\r\n b c\r\n" {
		t.Error("relax should trim lines and collapse spaces")
	}
}

func TestRelaxHeader(t *testing.T) {
	if relaxHeader("foo : bar\r\n") != "foo:bar\r\n" {
		t.Error("spaces around : should be removed")
	}
	if relaxHeader("foo:bar \t   baz \t \r\n") != "foo:bar baz\r\n" {
		t.Error("spaces should be collapsed")
	}
	if relaxHeader("fOO:bAR\r\n") != "foo:bAR\r\n" {
		t.Error("name should be lowercased")
	}
	if relaxHeader("foo\r\n bar : bar\r\n baz\r\n") != "foo bar:bar baz\r\n" {
		t.Error("crlfs in the middle should be gone")
	}

}
