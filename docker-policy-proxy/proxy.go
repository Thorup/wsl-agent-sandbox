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
	"sync"
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
	execMu         sync.RWMutex
	trackedExecs   map[string]bool
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
		trackedExecs:   make(map[string]bool),
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
		pp.wirePolicyCheckers(initial)
	}
	go pp.reconcileLoop()
	return pp
}

func (pp *PolicyProxy) wirePolicyCheckers(p *Policy) {
	if p.networkChecker == nil {
		p.networkChecker = pp.checkNetworkInternal
	}
	if p.volumeEnsurer == nil {
		p.volumeEnsurer = func(volName string) error {
			return pp.ensureVolumeOwned(volName, p.DistroName)
		}
	}
	if p.containerOwnerChecker == nil {
		p.containerOwnerChecker = func(cid string) error {
			return pp.checkContainerOwned(cid, p.DistroName)
		}
	}
	if p.networkOwnerChecker == nil {
		p.networkOwnerChecker = func(netRef string) error {
			return pp.checkNetworkOwnedOrBuiltin(netRef, p.DistroName, p.ForceInternalNetwork)
		}
	}
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

func (pp *PolicyProxy) trackExec(id string) {
	if id == "" {
		return
	}
	pp.execMu.Lock()
	if pp.trackedExecs == nil {
		pp.trackedExecs = make(map[string]bool)
	}
	pp.trackedExecs[id] = true
	pp.execMu.Unlock()
}

func (pp *PolicyProxy) isTrackedExec(id string) bool {
	pp.execMu.RLock()
	ok := pp.trackedExecs[id]
	pp.execMu.RUnlock()
	return ok
}

func (pp *PolicyProxy) checkContainerOwned(idOrName, distro string) error {
	if distro == "" {
		return nil
	}
	reqCtx, cancel := context.WithTimeout(pp.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/containers/"+url.PathEscape(idOrName)+"/json", nil)
	if err != nil {
		return err
	}
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return deny("failed verifying ownership of container %q: %v", idOrName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return deny("failed verifying ownership of container %q (upstream status %d)", idOrName, resp.StatusCode)
	}
	var info struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&info); err != nil {
		return deny("failed decoding container %q metadata: %v", idOrName, err)
	}
	if info.Config.Labels[sandboxDistroLabel] != distro {
		return deny("container %q belongs to host/another environment and is isolated by docker-policy-proxy", idOrName)
	}
	return nil
}

func (pp *PolicyProxy) inspectVolumeLabels(volName string) (exists bool, labels map[string]string, err error) {
	reqCtx, cancel := context.WithTimeout(pp.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/volumes/"+url.PathEscape(volName), nil)
	if err != nil {
		return false, nil, err
	}
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil, fmt.Errorf("upstream /volumes/%s returned status %d", volName, resp.StatusCode)
	}
	var info struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&info); err != nil {
		return false, nil, err
	}
	return true, info.Labels, nil
}

func (pp *PolicyProxy) checkVolumeOwned(volName, distro string) error {
	if distro == "" {
		return nil
	}
	exists, labels, err := pp.inspectVolumeLabels(volName)
	if err != nil {
		return deny("failed verifying ownership of volume %q: %v", volName, err)
	}
	if !exists {
		return nil
	}
	if labels[sandboxDistroLabel] != distro {
		return deny("volume %q belongs to host/another environment and is isolated by docker-policy-proxy", volName)
	}
	return nil
}

func (pp *PolicyProxy) ensureVolumeOwned(volName, distro string) error {
	if distro == "" {
		return nil
	}
	exists, labels, err := pp.inspectVolumeLabels(volName)
	if err != nil {
		return deny("failed verifying ownership of volume %q: %v", volName, err)
	}
	if exists {
		if labels[sandboxDistroLabel] != distro {
			return deny("volume %q belongs to host/another environment and is isolated by docker-policy-proxy", volName)
		}
		return nil
	}
	// Pre-create implicit named volume stamped with sandbox ownership label.
	payload, err := json.Marshal(map[string]any{
		"Name": volName,
		"Labels": map[string]string{
			sandboxDistroLabel: distro,
		},
	})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(pp.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, "http://docker/volumes/create", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return deny("failed creating labeled volume %q: %v", volName, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return deny("failed creating labeled volume %q (upstream status %d)", volName, resp.StatusCode)
	}
	return nil
}

func (pp *PolicyProxy) checkNetworkOwnedOrBuiltin(netRef, distro string, forceInternal bool) error {
	if distro == "" {
		return nil
	}
	lt := strings.ToLower(strings.TrimSpace(netRef))
	if lt == "none" || (!forceInternal && (lt == "bridge" || lt == "default" || lt == "")) {
		return nil
	}
	reqCtx, cancel := context.WithTimeout(pp.ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, "http://docker/networks/"+url.PathEscape(netRef), nil)
	if err != nil {
		return err
	}
	resp, err := pp.upstreamClient.Do(req)
	if err != nil {
		return deny("failed verifying ownership of network %q: %v", netRef, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return deny("failed verifying ownership of network %q (upstream status %d)", netRef, resp.StatusCode)
	}
	var info struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024*1024)).Decode(&info); err != nil {
		return deny("failed decoding network %q metadata: %v", netRef, err)
	}
	if info.Labels[sandboxDistroLabel] != distro {
		return deny("network %q belongs to host/another environment and is isolated by docker-policy-proxy", netRef)
	}
	return nil
}

func injectLabelFilter(r *http.Request, distro string) error {
	q := r.URL.Query()
	filtersMap := map[string]any{}
	if rawFilters := q.Get("filters"); rawFilters != "" {
		if err := json.Unmarshal([]byte(rawFilters), &filtersMap); err != nil {
			return deny("invalid filters query parameter: %v", err)
		}
	}
	wantLabel := sandboxDistroLabel + "=" + distro
	if existing, ok := filtersMap["label"]; ok && existing != nil {
		switch tv := existing.(type) {
		case []any:
			filtersMap["label"] = append(tv, wantLabel)
		case map[string]any:
			tv[wantLabel] = true
			filtersMap["label"] = tv
		default:
			filtersMap["label"] = []string{wantLabel}
		}
	} else {
		filtersMap["label"] = []string{wantLabel}
	}
	encoded, err := json.Marshal(filtersMap)
	if err != nil {
		return fmt.Errorf("marshaling label filter: %w", err)
	}
	q.Set("filters", string(encoded))
	r.URL.RawQuery = q.Encode()
	return nil
}

func (pp *PolicyProxy) enforceTenantIsolation(r *http.Request, norm string, pol *Policy) error {
	if pol.DistroName == "" {
		return nil
	}
	switch {
	case norm == "/containers/json" ||
		(r.Method == http.MethodPost && norm == "/containers/prune") ||
		norm == "/volumes" ||
		(r.Method == http.MethodPost && norm == "/volumes/prune") ||
		norm == "/networks" ||
		(r.Method == http.MethodPost && norm == "/networks/prune") ||
		norm == "/events":
		return injectLabelFilter(r, pol.DistroName)
	case strings.HasPrefix(norm, "/containers/"):
		rest := strings.TrimPrefix(norm, "/containers/")
		cid, _, _ := strings.Cut(rest, "/")
		if cid != "" && cid != "create" && cid != "json" && cid != "prune" {
			return pp.checkContainerOwned(cid, pol.DistroName)
		}
	case norm == "/commit":
		if cid := r.URL.Query().Get("container"); cid != "" {
			return pp.checkContainerOwned(cid, pol.DistroName)
		}
	case strings.HasPrefix(norm, "/exec/"):
		rest := strings.TrimPrefix(norm, "/exec/")
		execID, _, _ := strings.Cut(rest, "/")
		if execID != "" && !pp.isTrackedExec(execID) {
			return deny("exec instance %q is not owned by this sandbox", execID)
		}
	case strings.HasPrefix(norm, "/volumes/"):
		rest := strings.TrimPrefix(norm, "/volumes/")
		volName, _, _ := strings.Cut(rest, "/")
		if volName != "" && volName != "create" && volName != "prune" {
			return pp.checkVolumeOwned(volName, pol.DistroName)
		}
	case strings.HasPrefix(norm, "/networks/"):
		rest := strings.TrimPrefix(norm, "/networks/")
		netRef, _, _ := strings.Cut(rest, "/")
		if netRef != "" && netRef != "create" && netRef != "prune" {
			return pp.checkNetworkOwnedOrBuiltin(netRef, pol.DistroName, pol.ForceInternalNetwork)
		}
	}
	return nil
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
		pp.wirePolicyCheckers(next)
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

	norm := NormalizeAPIPath(r.URL.Path)
	if err := pp.enforceTenantIsolation(r, norm, pol); err != nil {
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

	if pol.DistroName != "" && r.Method == http.MethodPost && hasPrefixSuffix(norm, "/containers/", "/exec") {
		capW := &statusCaptureWriter{ResponseWriter: w}
		pp.reverseProxy.ServeHTTP(capW, r)
		if capW.status >= 200 && capW.status < 300 {
			var resp struct {
				ID string `json:"Id"`
			}
			if json.Unmarshal(capW.body.Bytes(), &resp) == nil && resp.ID != "" {
				pp.trackExec(resp.ID)
			}
		}
		return
	}

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
