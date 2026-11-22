package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

const maxInspectBodyBytes = 10 * 1024 * 1024 // 10 MiB max JSON body for container/volume/exec create

// PolicyProxy mediates HTTP/1.1 + Upgrade (101 hijack / h2c) requests to an upstream
// Docker Engine Unix domain socket while enforcing a Policy.
type PolicyProxy struct {
	upstreamSocket string
	policy         atomic.Pointer[Policy]
	bindManager    *EphemeralMountManager
	reverseProxy   *httputil.ReverseProxy
	upstreamClient *http.Client
	logger         *log.Logger
	ctx            context.Context
	cancel         context.CancelFunc
	wakeCh         chan struct{}
}

func NewPolicyProxy(upstreamSocket string, initial *Policy, logger *log.Logger) *PolicyProxy {
	if logger == nil {
		logger = log.Default()
	}
	bm := NewEphemeralMountManager(nil)
	if initial != nil {
		initial.bindManager = bm
		if initial.EphemeralBindRoot != "" {
			bm.CleanupStale(initial.EphemeralBindRoot)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	pp := &PolicyProxy{
		upstreamSocket: upstreamSocket,
		bindManager:    bm,
		logger:         logger,
		ctx:            ctx,
		cancel:         cancel,
		wakeCh:         make(chan struct{}, 1),
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
	pp.upstreamClient = &http.Client{Transport: transport}
	if initial != nil {
		initial.networkChecker = pp.checkNetworkInternal
	}
	go pp.reconcileLoop()
	return pp
}

func (pp *PolicyProxy) checkNetworkInternal(nameOrID string) (bool, error) {
	reqCtx, cancel := context.WithTimeout(pp.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/networks/"+url.PathEscape(nameOrID), nil)
	if err != nil {
		return false, err
	}
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("upstream /networks/%s returned status %d", nameOrID, resp.StatusCode)
	}
	var netInfo struct {
		Internal bool `json:"Internal"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&netInfo); err != nil {
		return false, err
	}
	return netInfo.Internal, nil
}

func (pp *PolicyProxy) Close() {
	if pp.cancel != nil {
		pp.cancel()
	}
}

func (pp *PolicyProxy) wakeReconciler() {
	select {
	case pp.wakeCh <- struct{}{}:
	default:
	}
}

func (pp *PolicyProxy) reconcileActiveContainers() {
	if !pp.bindManager.HasTracked() {
		return
	}
	reqCtx, cancel := context.WithTimeout(pp.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/containers/json?all=1", nil)
	if err != nil {
		return
	}
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var list []struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4*1024*1024)).Decode(&list); err != nil {
		return
	}
	active := make(map[string]bool, len(list))
	for _, c := range list {
		if c.ID != "" {
			active[c.ID] = true
		}
	}
	pp.bindManager.CleanupAbsent(active)
}

func (pp *PolicyProxy) watchDestroyEvents() {
	eventsURL := "http://docker/events?filters=" + url.QueryEscape(`{"type":["container"],"event":["destroy"]}`)
	req, err := http.NewRequestWithContext(pp.ctx, http.MethodGet, eventsURL, nil)
	if err != nil {
		return
	}
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if !pp.bindManager.HasTracked() {
			return
		}
		var ev struct {
			Type   string `json:"Type"`
			Action string `json:"Action"`
			Actor  struct {
				ID string `json:"ID"`
			} `json:"Actor"`
		}
		if json.Unmarshal(scanner.Bytes(), &ev) == nil {
			if (ev.Type == "container" || ev.Type == "") && ev.Action == "destroy" && ev.Actor.ID != "" {
				pp.bindManager.CleanupContainer(ev.Actor.ID)
			}
		}
	}
}

func (pp *PolicyProxy) reconcileLoop() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		if !pp.bindManager.HasTracked() {
			select {
			case <-pp.ctx.Done():
				return
			case <-pp.wakeCh:
			}
			continue
		}
		pp.watchDestroyEvents()
		pp.reconcileActiveContainers()
		if !pp.bindManager.HasTracked() {
			continue
		}
		select {
		case <-pp.ctx.Done():
			return
		case <-pp.wakeCh:
		case <-ticker.C:
		}
	}
}

func (pp *PolicyProxy) UpdatePolicy(next *Policy) {
	if next != nil {
		if next.bindManager == nil {
			next.bindManager = pp.bindManager
		}
		if next.networkChecker == nil {
			next.networkChecker = pp.checkNetworkInternal
		}
	}
	pp.policy.Store(next)
}

type statusCaptureWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *statusCaptureWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCaptureWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.body.Len() < 64*1024 {
		w.body.Write(p)
	}
	return w.ResponseWriter.Write(p)
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

	var ephemeralTargets []string
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

		newBody, modified, targets, err := pol.ProcessJSONBodyWithMounts(r.Method, r.URL.Path, bodyBytes)
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
		ephemeralTargets = targets

		if modified {
			pp.logger.Printf("REWRITE method=%s path=%s bytes=%d->%d", r.Method, r.URL.Path, len(bodyBytes), len(newBody))
		}
		r.Body = io.NopCloser(bytes.NewReader(newBody))
		r.ContentLength = int64(len(newBody))
		r.TransferEncoding = nil
		r.Header.Del("Transfer-Encoding")
		r.Header.Set("Content-Length", strconvItoa(len(newBody)))
	}

	if len(ephemeralTargets) > 0 {
		capW := &statusCaptureWriter{ResponseWriter: w}
		pp.reverseProxy.ServeHTTP(capW, r)
		tracked := false
		if capW.status >= 200 && capW.status < 300 {
			var resp struct {
				ID string `json:"Id"`
			}
			if json.Unmarshal(capW.body.Bytes(), &resp) == nil && resp.ID != "" {
				pp.bindManager.Track(resp.ID, r.URL.Query().Get("name"), ephemeralTargets)
				pp.wakeReconciler()
				tracked = true
			}
		}
		if !tracked {
			pp.bindManager.CleanupTargets(ephemeralTargets)
		}
		return
	}

	norm := NormalizeAPIPath(r.URL.Path)
	if r.Method == http.MethodPost && norm == "/containers/prune" {
		capW := &statusCaptureWriter{ResponseWriter: w}
		pp.reverseProxy.ServeHTTP(capW, r)
		if capW.status >= 200 && capW.status < 300 {
			var pruneResp struct {
				ContainersDeleted []string `json:"ContainersDeleted"`
			}
			if json.Unmarshal(capW.body.Bytes(), &pruneResp) == nil {
				for _, cid := range pruneResp.ContainersDeleted {
					pp.bindManager.CleanupContainer(cid)
				}
			}
			pp.reconcileActiveContainers()
		}
		return
	}

	pp.reverseProxy.ServeHTTP(w, r)

	if r.Method == http.MethodDelete && strings.HasPrefix(norm, "/containers/") {
		rest := strings.TrimPrefix(norm, "/containers/")
		if cid, _, _ := strings.Cut(rest, "/"); cid != "" {
			pp.bindManager.CleanupContainer(cid)
		}
	}
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
	case norm == "/networks/create":
		return true
	case hasPrefixSuffix(norm, "/networks/", "/connect"):
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
