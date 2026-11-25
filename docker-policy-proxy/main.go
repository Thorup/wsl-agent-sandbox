package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

func loadPolicyFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pol Policy
	if err := json.Unmarshal(data, &pol); err != nil {
		return nil, err
	}
	return &pol, nil
}

func resolveUpstreamSocket(explicit string) string {
	if explicit != "" {
		return explicit
	}
	candidates := []string{
		"/run/box-root/mnt-wsl/box-binds/dd-upstream.sock",
		"/run/box-root/mnt-wsl/docker-desktop/shared-sockets/guest-services/docker.sock",
		"/run/box-root/mnt-wsl/docker-desktop/shared-sockets/guest-services/docker.proxy.sock",
		"/run/box-root/mnt-wsl/docker-desktop/shared-sockets/host-services/docker.sock",
		"/run/box-root/mnt-wsl/docker-desktop/run/docker.sock",
		"/run/box-root/mnt-wsl/docker-desktop-data/run/docker.sock",
		"/run/box-root/mnt-wsl/docker-desktop/docker.sock",
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && (st.Mode()&os.ModeSocket != 0) {
			return c
		}
	}
	return candidates[0]
}

func main() {
	listenSocket := flag.String("listen", "/run/docker-policy/docker.sock", "Unix socket path to listen on")
	upstreamSocket := flag.String("upstream", "", "Upstream Docker Desktop Unix socket path (auto-discovered if empty)")
	policyPath := flag.String("policy", "/etc/wsl-agent-sandbox/docker-policy.json", "Path to compiled Docker policy JSON")
	socketGroup := flag.String("group", "agent-docker", "Group owner for the listening Unix socket")
	flag.Parse()

	logger := log.New(os.Stdout, "[docker-policy-proxy] ", log.LstdFlags)

	pol, err := loadPolicyFile(*policyPath)
	if err != nil {
		logger.Fatalf("failed loading policy %q: %v", *policyPath, err)
	}

	logger.Printf("starting proxy listen=%s upstream=%s mappings=%d enabled=%v", *listenSocket, resolveUpstreamSocket(*upstreamSocket), len(pol.BindMappings), pol.Enabled)

	if err := os.MkdirAll(filepath.Dir(*listenSocket), 0o755); err != nil {
		logger.Fatalf("failed creating socket directory: %v", err)
	}
	_ = os.Remove(*listenSocket)

	ln, err := net.Listen("unix", *listenSocket)
	if err != nil {
		logger.Fatalf("failed listening on %s: %v", *listenSocket, err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(*listenSocket)
	}()

	if *socketGroup != "" {
		if grp, err := user.LookupGroup(*socketGroup); err == nil {
			if gid, err := strconv.Atoi(grp.Gid); err == nil {
				if err := os.Chown(*listenSocket, 0, gid); err != nil {
					logger.Printf("warning: chown socket group %s failed: %v", *socketGroup, err)
				}
			}
		} else {
			logger.Printf("warning: group %s not found: %v", *socketGroup, err)
		}
	}
	if err := os.Chmod(*listenSocket, 0o660); err != nil {
		logger.Fatalf("failed chmod 0660 on %s: %v", *listenSocket, err)
	}

	proxy := NewPolicyProxy(*upstreamSocket, pol, logger)
	defer proxy.Close()
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 30 * time.Second,
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			if sig == syscall.SIGHUP {
				next, err := loadPolicyFile(*policyPath)
				if err != nil {
					logger.Printf("ERROR reloading policy on SIGHUP: %v", err)
					continue
				}
				proxy.UpdatePolicy(next)
				logger.Printf("reloaded policy mappings=%d enabled=%v", len(next.BindMappings), next.Enabled)
				continue
			}
			logger.Printf("shutting down on signal %v", sig)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			return
		}
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
