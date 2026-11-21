package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"
)

const maxInspectBodyBytes = 10 * 1024 * 1024 // 10 MiB max JSON body for container/volume/exec create

// PolicyProxy mediates HTTP/1.1 + Upgrade (101 hijack / h2c) requests to an upstream
// Docker Engine Unix domain socket while enforcing a Policy.
type PolicyProxy struct {
	upstreamSocket string
	policy         atomic.Pointer[Policy]
	reverseProxy   *httputil.ReverseProxy
	logger         *log.Logger
}

func NewPolicyProxy(upstreamSocket string, initial *Policy, logger *log.Logger) *PolicyProxy {
	if logger == nil {
		logger = log.Default()
	}
	pp := &PolicyProxy{
		upstreamSocket: upstreamSocket,
		logger:         logger,
	}
	pp.policy.Store(initial)

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			target := resolveUpstreamSocket(pp.upstreamSocket)
			return d.DialContext(ctx, "unix", target)
		},
		DisableCompression: true,
	}

	targetURL, _ := url.Parse("http://docker")
	rp := httputil.NewSingleHostReverseProxy(targetURL)
	rp.Transport = transport
	rp.FlushInterval = -1 // Critical for streaming Docker logs, events, build output, and hijacks.
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		pp.logger.Printf("UPSTREAM_ERROR method=%s path=%s err=%v", r.Method, r.URL.Path, err)
		writeDockerJSONError(w, http.StatusBadGateway, "upstream Docker Desktop socket unreachable: "+err.Error())
	}
	pp.reverseProxy = rp
	return pp
}

func (pp *PolicyProxy) UpdatePolicy(next *Policy) {
	pp.policy.Store(next)
}

func (pp *PolicyProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pol := pp.policy.Load()
	if pol == nil {
		writeDockerJSONError(w, http.StatusServiceUnavailable, "docker policy not loaded")
		return
	}

	if err := pol.CheckEndpoint(r.Method, r.URL.Path, r.URL.Query()); err != nil {
		pp.logger.Printf("DENY method=%s path=%s reason=%v", r.Method, r.URL.Path, err)
		writeDockerJSONError(w, http.StatusForbidden, err.Error())
		return
	}

	if needsJSONBodyInspection(r.Method, r.URL.Path) {
		limited := io.LimitReader(r.Body, maxInspectBodyBytes+1)
		bodyBytes, err := io.ReadAll(limited)
		_ = r.Body.Close()
		if err != nil {
			writeDockerJSONError(w, http.StatusBadRequest, "failed reading request body: "+err.Error())
			return
		}
		if len(bodyBytes) > maxInspectBodyBytes {
			writeDockerJSONError(w, http.StatusRequestEntityTooLarge, "request JSON body exceeds proxy inspection limit")
			return
		}

		newBody, modified, err := pol.ProcessJSONBody(r.Method, r.URL.Path, bodyBytes)
		if err != nil {
			var pe *PolicyError
			if errors.As(err, &pe) {
				pp.logger.Printf("DENY method=%s path=%s reason=%s", r.Method, r.URL.Path, pe.Reason)
				writeDockerJSONError(w, http.StatusForbidden, pe.Error())
				return
			}
			pp.logger.Printf("ERROR method=%s path=%s err=%v", r.Method, r.URL.Path, err)
			writeDockerJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if modified {
			pp.logger.Printf("REWRITE method=%s path=%s bytes=%d->%d", r.Method, r.URL.Path, len(bodyBytes), len(newBody))
		}
		r.Body = io.NopCloser(bytes.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		r.TransferEncoding = nil
		r.Header.Del("Transfer-Encoding")
		r.Header.Set("Content-Length", strconvItoa(len(newBody)))
	}

	pp.reverseProxy.ServeHTTP(w, r)
}

func needsJSONBodyInspection(method, rawPath string) bool {
	if method != http.MethodPost {
		return false
	}
	norm := NormalizeAPIPath(rawPath)
	switch {
	case norm == "/containers/create":
		return true
	case norm == "/volumes/create":
		return true
	case hasPrefixSuffix(norm, "/containers/", "/update"):
		return true
	case hasPrefixSuffix(norm, "/containers/", "/exec"):
		return true
	default:
		return false
	}
}

func hasPrefixSuffix(s, prefix, suffix string) bool {
	return len(s) >= len(prefix)+len(suffix) && s[:len(prefix)] == prefix && s[len(s)-len(suffix):] == suffix
}

func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func writeDockerJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
}
