package dkim

import (
	"errors"
	"strings"
	"testing"
)

type fakeDnsClient struct {
	results map[string][]string
}

func (c *fakeDnsClient) LookupTxt(hostname string) ([]string, error) {
	if result, found := c.results[hostname]; found {
		return result, nil
	} else {
		return nil, errors.New("hostname not found")
	}
}

var client = &fakeDnsClient{
	results: map[string][]string{
		"google._domainkey.vandenhooff.name.": []string{
			`v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCl2Qrp5KF1uJnQSO0YuwInVPISQRrUciXtg/5hnQl6ed+UmYvWreLyuiyaiSd9X9Zu+aZQoeKm67HCxSMpC6G2ar0NludsXW69QdfzUpB5I6fzaLW8rl/RyeGkiQ3D66kvadK1wlNfUI7Dt9WtnUs8AFz/15xvODzgTMFJDiAcAwIDAQAB`,
		},
	},
}

func fixupNewlines(s string) string {
	return strings.Replace(s, "\n", "\r\n", -1)
}

var complete = fixupNewlines(`Received: by igcau2 with SMTP id au2so61978408igc.0
        for <1v443yp1p8@keytree.io>; Sun, 29 Mar 2015 19:39:21 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=vandenhooff.name; s=google;
        h=mime-version:from:date:message-id:subject:to:content-type;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ/6odRnmm
         +TGraJoXyKu2WwVl2auHW6Hug/9QBWg6JIQrUl3TLK5Z07IZHpqBFrXjqV/fd6Yl/1+L
         ZSaJ9lwo6YW6LvwoAq4AUwPDZqXeak7i5pj2U=
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20130820;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to
         :content-type;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=mIJDzFjZy3jMNQQHSn7ADick4AjIHaACjpSCxUFbDvL2i7qhIq8SXSE5uOb8bW31tf
         qKL1xvrKq8vl/YymkSpTTsY+nrQ1DCcLH0sVLXWmw3AbiaXpViCFUKGMGaZyj12Xqe4x
         jZzBEIwOpN2z/f0QDvSyRb5gq+wBRIQkay6XEI2orDrP9SrfdhiMmwNaxtDBuWI6ollS
         X3vRh0zdZxTfYIBIzHZjmgn+gwUR2d/qk5sioT64JMwEvZjbWsUF2JC8Sim3tif1Z04L
         4JpItJhazY95XgZRaae25JvgCh9rtOE7WyHjHVhek/hy7SH1dZgxa9h2u7bjSwz2iHQt
         eUZA==
X-Gm-Message-State: ALoCoQk+KvRer9AfNQDS5M2p+aje/xg2vMBICDyzBfrFJKkaM7SLGYu5umi6GDbCSbE8AJPoKSgK
X-Received: by 10.107.148.198 with SMTP id w189mr46794537iod.14.1427683161411;
        Sun, 29 Mar 2015 19:39:21 -0700 (PDT)
Return-Path: <jelle@vandenhooff.name>
Received: from mail-ie0-f172.google.com (mail-ie0-f172.google.com. [209.85.223.172])
        by mx.google.com with ESMTPSA id s7sm6539499ioi.15.2015.03.29.19.39.19
        for <1v443yp1p8@keytree.io>
        (version=TLSv1.2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 29 Mar 2015 19:39:19 -0700 (PDT)
Received: by iedm5 with SMTP id m5so106639486ied.3
        for <1v443yp1p8@keytree.io>; Sun, 29 Mar 2015 19:39:19 -0700 (PDT)
X-Received: by 10.42.89.72 with SMTP id f8mr58735189icm.24.1427683158995; Sun,
 29 Mar 2015 19:39:18 -0700 (PDT)
MIME-Version: 1.0
Received: by 10.50.3.72 with HTTP; Sun, 29 Mar 2015 19:39:03 -0700 (PDT)
From: Jelle van den Hooff <jelle@vandenhooff.name>
Date: Sun, 29 Mar 2015 22:39:03 -0400
Message-ID: <CAP=Jqubpoizbfg+Fb_+ycEkhqrgMBE=qozKrRubUuimQ717wKw@mail.gmail.com>
Subject: vnsy7km1hn4crbyp0h32m3932p38qtgbhpxf9mp01s6w40mvk2jg
To: 1v443yp1p8@keytree.io
Content-Type: text/plain; charset=UTF-8


`)

var justSignature = fixupNewlines(`DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=vandenhooff.name; s=google;
        h=mime-version:from:date:message-id:subject:to:content-type;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ/6odRnmm
         +TGraJoXyKu2WwVl2auHW6Hug/9QBWg6JIQrUl3TLK5Z07IZHpqBFrXjqV/fd6Yl/1+L
         ZSaJ9lwo6YW6LvwoAq4AUwPDZqXeak7i5pj2U=
`)

func TestComplete(t *testing.T) {
	var email *VerifiedEmail
	var err error

	if email, err = ParseAndVerify(complete, Complete, client); err != nil {
		t.Errorf("expected success; got %s", err)
	}

	if email.CanonHeaders() != headersOnly {
		t.Errorf("unexpected canonical form")
	}

	if email.Signature.Domain != "vandenhooff.name" {
		t.Errorf("expected vandenhooff.name as domain; got %s", email.Signature.Domain)
	}

	from := email.ExtractHeader("from")
	if len(from) != 1 || from[0] != "From: Jelle van den Hooff <jelle@vandenhooff.name>\r\n" {
		t.Errorf("strange from header")
	}

	withBrokenSignature := strings.Replace(complete, "NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ", "foobar", 1)
	if complete == withBrokenSignature {
		t.Fatalf("broken test; tried to kill signature but could not find it")
	}

	if _, err := ParseAndVerify(withBrokenSignature, Complete, client); err.Error() != "no valid DKIM signature" {
		t.Errorf("expected no valid DKIM signature; got %s", err)
	}

	if _, err := ParseAndVerify(complete+"foobar", Complete, client); err.Error() != "body hash does not match" {
		t.Errorf("expected failing body hash; got %s", err)
	}

	if _, err := ParseAndVerify(justSignature, Complete, client); err.Error() != "no valid DKIM signature" {
		t.Errorf("expected no valid DKIM signature; got %s", err)
	}

	if _, err := ParseAndVerify(justSignature+justSignature, Complete, client); err.Error() != "multiple DKIM headers" {
		t.Errorf("expected multiple DKIM headers; got %s", err)
	}

	if _, err := ParseAndVerify("", Complete, client); err.Error() != "no DKIM header found" {
		t.Errorf("expected no DKIM header found; got %s", err)
	}
}

var headersOnly = fixupNewlines(`mime-version:1.0
from:Jelle van den Hooff <jelle@vandenhooff.name>
date:Sun, 29 Mar 2015 22:39:03 -0400
message-id:<CAP=Jqubpoizbfg+Fb_+ycEkhqrgMBE=qozKrRubUuimQ717wKw@mail.gmail.com>
subject:vnsy7km1hn4crbyp0h32m3932p38qtgbhpxf9mp01s6w40mvk2jg
to:1v443yp1p8@keytree.io
content-type:text/plain; charset=UTF-8
dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=vandenhooff.name; s=google; h=mime-version:from:date:message-id:subject:to:content-type; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ/6odRnmm+TGraJoXyKu2WwVl2auHW6Hug/9QBWg6JIQrUl3TLK5Z07IZHpqBFrXjqV/fd6Yl/1+LZSaJ9lwo6YW6LvwoAq4AUwPDZqXeak7i5pj2U=`)

func TestHeadersOnly(t *testing.T) {
	var email *VerifiedEmail
	var err error

	if email, err = ParseAndVerify(headersOnly, HeadersOnly, client); err != nil {
		t.Errorf("expected success; got %s", err)
	}

	if email, err = ParseAndVerify(headersOnly+"\r\n\r\n\r\nfoo bar", HeadersOnly, client); err != nil {
		t.Errorf("expected success; got %s", err)
	}

	if email.CanonHeaders() != headersOnly {
		t.Errorf("unexpected canonical form")
	}
}
