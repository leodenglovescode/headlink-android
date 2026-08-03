// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package notelemetry supplies the HTTP transport Headlink gives to logtail.
//
// Headlink sends no telemetry. Upstream configures logtail to upload client
// logs and client metrics to log.tailscale.io, enabled by default; a private
// Headscale deployment has no use for that and no relationship with the party
// receiving it.
//
// The upload is switched off in two independent ways, because one of them is a
// setting and settings can be flipped:
//
//  1. logtail.Config.Disabled is set in libtailscale, which is logtail's own
//     kill switch and suppresses even its internal "logtail started" banner.
//  2. Its HTTP client is given the Transport below, which fails every request
//     without opening a socket.
//
// The second is what makes the guarantee structural rather than a matter of
// configuration. logtail is still constructed, because it is also the local log
// sink — it owns stderr and the on-disk filch buffer, and backend.go and net.go
// log through it — so removing it would take local logging with it. What is
// removed is its ability to reach the network at all.
//
// This lives in its own package rather than in libtailscale because
// libtailscale requires the Android NDK to build and so is excluded from
// `make go-test`; a guarantee worth making is worth testing on every run.
package notelemetry

import (
	"errors"
	"net/http"
)

// ErrDisabled is returned in place of every attempted log upload.
var ErrDisabled = errors.New("headlink: remote log upload is disabled")

// Transport is an http.RoundTripper that refuses every request. It never
// dials, so a request cannot leak even a DNS lookup or a TCP SYN.
type Transport struct{}

// RoundTrip implements http.RoundTripper by always failing.
//
// It returns an error rather than a synthetic success on purpose: logtail
// treats a 2xx as "delivered" and drops the buffered lines, so a fake success
// would silently discard the local log instead of keeping it on the device.
func (Transport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, ErrDisabled
}
