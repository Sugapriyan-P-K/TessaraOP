// Command tessaraopd serves a policy bundle as an HTTP decision point.
//
// It is the onboarding path for stacks that are not Go: point a proxy at
// /v1/authz, or call /v1/decision directly, and no application code changes.
//
//	tessaraopd -bundle policies.json -addr :8181
//
// Endpoints, and which integrations use them, are documented in package
// pdpserver. The short version:
//
//	/v1/decision            native JSON, full request and decision
//	/v1/authz               Envoy ext_authz, NGINX auth_request, Traefik
//	                        ForwardAuth, HAProxy, Caddy forward_auth
//	/v1/data/tessaraop      drop-in for an existing OPA client
//	/v1/attributes          the attribute registry, as onboarding docs
//	/healthz /readyz /metrics /v1/info /v1/reload
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/suga/tessaraop/pkg/tessaraop"
	"github.com/suga/tessaraop/pkg/tessaraop/pdpserver"
)

func main() {
	var (
		bundlePath = flag.String("bundle", "", "path to the policy bundle (required)")
		addr       = flag.String("addr", ":8181", "listen address")
		cacheSize  = flag.Int("cache", 8192, "decision cache entries (0 disables)")
		algorithm  = flag.String("alg", "deny-overrides",
			"deny-overrides | permit-overrides | first-applicable")
		defaultTenant = flag.String("tenant", "",
			"tenant to assume when a request names none")
		trustedHops = flag.Int("trusted-proxy-hops", 0,
			"proxies you operate, counted from the right of X-Forwarded-For; 0 ignores the header")
		strictAttrs = flag.Bool("strict-attributes", false,
			"reject policies referencing attributes outside the registry")
		reloadToken = flag.String("reload-token", "",
			"require this token in X-Tessaraop-Token on /v1/reload")
		auditLog = flag.Bool("audit", false,
			"log one line per decision to stderr")
		checkOnly = flag.Bool("check", false,
			"lint the bundle and exit; non-zero status if it has errors")
		readTimeout  = flag.Duration("read-timeout", 5*time.Second, "HTTP read timeout")
		writeTimeout = flag.Duration("write-timeout", 10*time.Second, "HTTP write timeout")
		shutdownWait = flag.Duration("shutdown-grace", 10*time.Second,
			"how long to let in-flight requests finish on shutdown")
	)
	flag.Parse()

	logger := log.New(os.Stderr, "tessaraopd ", log.LstdFlags|log.Lmsgprefix)

	if *bundlePath == "" {
		logger.Println("error: -bundle is required")
		flag.Usage()
		os.Exit(2)
	}

	lintOpt := tessaraop.LintOptions{StrictAttributes: *strictAttrs}

	// Lint first and always, so the diagnostics are reported once with the file
	// in hand rather than surfacing as a load error with less context.
	diags, err := tessaraop.LintBundleFile(*bundlePath, lintOpt)
	if err != nil {
		logger.Printf("error: cannot read %s: %v", *bundlePath, err)
		os.Exit(1)
	}
	for _, d := range diags {
		logger.Printf("%s", d)
	}
	if errs := tessaraop.Errors(diags); len(errs) > 0 {
		logger.Printf("error: bundle has %d error(s); refusing to start", len(errs))
		os.Exit(1)
	}
	if *checkOnly {
		logger.Printf("ok: %s passed lint with %d warning(s)", *bundlePath, len(diags))
		return
	}

	pdp, _, err := tessaraop.OpenBundle(*bundlePath, tessaraop.Config{
		Algorithm: tessaraop.Algorithm(*algorithm),
		CacheSize: *cacheSize,
		Lint:      lintOpt,
	})
	if err != nil {
		logger.Printf("error: %v", err)
		os.Exit(1)
	}

	info := pdp.Info()
	logger.Printf("loaded %s: %d policies, %d rules, %d tenants, %d shards, algorithm %s",
		*bundlePath, info.Policies, info.Rules, info.Tenants, info.Shards, info.Algorithm)

	cfg := pdpserver.Config{
		PDP:              pdp,
		BundlePath:       *bundlePath,
		DefaultTenant:    *defaultTenant,
		TrustedProxyHops: *trustedHops,
		ReloadToken:      *reloadToken,
	}
	if *auditLog {
		cfg.OnDecision = func(req tessaraop.Request, d tessaraop.Decision) {
			logger.Printf("decision tenant=%q scope=%q effect=%s policy=%s rule=%s rules_scanned=%d cache=%v",
				req.TenantID, req.Scope, d.Effect, d.MatchedPolicyID, d.MatchedRuleID,
				d.RulesScanned, d.CacheHit)
		}
	}

	srv, warnings, err := pdpserver.New(cfg)
	if err != nil {
		logger.Printf("error: %v", err)
		os.Exit(1)
	}
	for _, warning := range warnings {
		logger.Printf("warning: %s", warning)
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv,
		ReadHeaderTimeout: *readTimeout,
		ReadTimeout:       *readTimeout,
		WriteTimeout:      *writeTimeout,
	}

	// SIGHUP reloads, which is how policy ships without a restart. Doing it here
	// rather than only over HTTP means a deployment that writes the file and
	// signals the process needs no network path to the admin endpoint at all.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			d, err := pdp.LoadBundleFile(*bundlePath)
			for _, diag := range d {
				logger.Printf("reload: %s", diag)
			}
			if err != nil {
				logger.Printf("reload failed, keeping the previous policy set: %v", err)
				continue
			}
			logger.Printf("reloaded: generation %d, %d rules",
				pdp.Generation(), pdp.Info().Rules)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		logger.Printf("listening on %s", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Printf("error: %v", err)
			os.Exit(1)
		}
	}()

	<-stop
	logger.Printf("shutting down, allowing %v for in-flight requests", *shutdownWait)
	ctx, cancel := context.WithTimeout(context.Background(), *shutdownWait)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
	fmt.Fprintln(os.Stderr)
}
