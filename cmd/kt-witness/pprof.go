package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"time"
)

// The profiling endpoint.
//
// # Why it exists
//
// This project has repeatedly reasoned about where its CPU goes by inference —
// reading `ps` output, attributing a 563% main process to Proton's tree rebuild,
// and concluding the sweep was starved. Capping Proton's parallelism did drop
// total CPU by 5.8 cores, which corroborates the guess, but corroboration is not
// measurement. A profile answers the question directly instead of plausibly.
//
// # Why it is on its own listener
//
// NOT on the main mux. That mux serves the monitoring endpoint, and the
// monitoring endpoint is now reachable over the tailnet — mounting pprof there
// would publish full goroutine dumps and let anyone who can reach the witness
// start a thirty-second CPU profile on it. The debug surface and the product
// surface have different audiences and belong on different sockets.
//
// The address is unpublished in compose, so it is reachable from the container
// network and the host and from nowhere else. That is deliberate: an operator
// with a shell can profile, and the internet cannot.
//
// # Why it is off by default
//
// Profiling endpoints are the kind of thing that gets switched on to diagnose
// something and then quietly stays on for years. Requiring it to be named in
// the config makes leaving it enabled a decision someone made rather than one
// nobody noticed.

// startPprof serves net/http/pprof on addr, if addr is set.
func startPprof(ctx context.Context, addr string, log *slog.Logger) {
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	// Registered explicitly rather than by importing for the side effect: the
	// blank import wires these onto http.DefaultServeMux, which is a global that
	// something else could later serve by accident. Naming them keeps the debug
	// surface on the socket that was chosen for it.
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Not fatal. Profiling is a diagnostic convenience; the witness's job is
		// to cosign, and refusing to start because a debug socket is taken would
		// trade the product for the tooling.
		log.Warn("pprof listener unavailable; continuing without it",
			"addr", addr, "err", err)
		return
	}
	log.Info("pprof enabled", "addr", addr,
		"note", "debug surface, deliberately not on the monitoring listener")

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() { _ = srv.Serve(ln) }()
}
