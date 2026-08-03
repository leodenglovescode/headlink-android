// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package notelemetry

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTransportRefusesEverything pins the guarantee that Headlink uploads no
// telemetry, including to the host logtail is configured with upstream.
func TestTransportRefusesEverything(t *testing.T) {
	for _, target := range []string{
		"https://log.tailscale.io/c/tailnode.log.tailscale.io",
		"http://127.0.0.1/anything",
		"https://example.com/",
	} {
		req, err := http.NewRequest("POST", target, nil)
		if err != nil {
			t.Fatalf("NewRequest(%q): %v", target, err)
		}
		resp, err := Transport{}.RoundTrip(req)
		if err == nil {
			t.Errorf("RoundTrip(%q) succeeded; it must always fail", target)
		}
		if resp != nil {
			t.Errorf("RoundTrip(%q) returned a response; it must return none", target)
		}
	}
}

// TestTransportNeverDials proves the refusal happens before any socket is
// opened: a request aimed at a live server must not reach it.
func TestTransportNeverDials(t *testing.T) {
	reached := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached <- struct{}{}
	}))
	defer srv.Close()

	c := &http.Client{Transport: Transport{}}
	if _, err := c.Post(srv.URL, "application/json", nil); err == nil {
		t.Fatal("POST succeeded; the transport must refuse it")
	}
	select {
	case <-reached:
		t.Fatal("the request reached the server; the transport dialed when it must not")
	default:
	}
}

// TestTransportFailsRatherThanFakingSuccess guards the specific failure mode
// that would lose logs: logtail drops buffered lines once a POST reports
// success, so a synthetic 200 would discard the on-device log rather than
// merely withhold the upload.
func TestTransportFailsRatherThanFakingSuccess(t *testing.T) {
	req, err := http.NewRequest("POST", "https://log.tailscale.io/c/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := Transport{}.RoundTrip(req)
	if resp != nil {
		t.Fatalf("got a response %+v; logtail would treat it as delivered", resp)
	}
	if err != ErrDisabled {
		t.Fatalf("err = %v, want ErrDisabled", err)
	}
}
