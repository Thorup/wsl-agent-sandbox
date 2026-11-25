package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func setupTestEnv(t *testing.T) (*PolicyProxy, string, string, *map[string]any, func()) {
	t.Helper()

	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home-agent")
	sharedRO := filepath.Join(tmp, "shared-docs")
	outsideDir := filepath.Join(tmp, "outside-secret")
	if err := os.MkdirAll(filepath.Join(homeDir, "project"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sharedRO, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, filepath.Join(homeDir, "link-to-outside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/run/desktop/mnt/host/c", filepath.Join(homeDir, "dangling-win-link")); err != nil {
		t.Fatal(err)
	}

	upstreamSock := filepath.Join(tmp, "upstream.sock")
	proxySock := filepath.Join(tmp, "proxy.sock")

	var lastReceived map[string]any
	upstreamMux := http.NewServeMux()
	upstreamMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Header.Get("Upgrade"), "tcp") {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", 500)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = rw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
			_ = rw.Flush()
			// Echo one line over raw hijacked stream
			line, err := rw.ReadString('\n')
			if err == nil {
				_, _ = rw.WriteString("ECHO:" + line)
				_ = rw.Flush()
			}
			return
		}
		if r.Body != nil {
			b, _ := io.ReadAll(r.Body)
			if len(b) > 0 {
				var m map[string]any
				if json.Unmarshal(b, &m) == nil {
					lastReceived = m
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Id":"test123","Status":"ok"}`))
	})

	upLn, err := net.Listen("unix", upstreamSock)
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &http.Server{Handler: upstreamMux}
	go func() { _ = upSrv.Serve(upLn) }()

	pol := &Policy{
		Enabled:       true,
		AllowBuildKit: true,
		AllowCapAdd:   []string{},
		DenyEndpoints: []string{"/plugins", "/swarm", "/services", "/nodes", "/secrets", "/configs", "/tasks"},
		BindMappings: []BindMapping{
			{GuestPrefix: homeDir, DaemonPrefix: "/mnt/wsl/box-binds/test/home-agent", ReadOnly: false},
			{GuestPrefix: sharedRO, DaemonPrefix: "/mnt/wsl/box-binds/test/shared/docs", ReadOnly: true},
		},
	}

	proxy := NewPolicyProxy(upstreamSock, pol, log.New(io.Discard, "", 0))
	pLn, err := net.Listen("unix", proxySock)
	if err != nil {
		t.Fatal(err)
	}
	pSrv := &http.Server{Handler: proxy}
	go func() { _ = pSrv.Serve(pLn) }()

	cleanup := func() {
		proxy.Close()
		_ = pSrv.Close()
		_ = upSrv.Close()
	}
	return proxy, proxySock, tmp, &lastReceived, cleanup
}

func unixHTTPClient(sock string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
}

func postJSON(t *testing.T, client *http.Client, urlPath string, payload any) *http.Response {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post("http://docker"+urlPath, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAllowedOperationsAndBindRewrite(t *testing.T) {
	_, sock, tmp, lastReceived, cleanup := setupTestEnv(t)
	defer cleanup()
	client := unixHTTPClient(sock)

	// 1. Ping & Version
	for _, p := range []string{"/_ping", "/v1.47/version", "/v1.47/containers/json"} {
		resp, err := client.Get("http://docker" + p)
		if err != nil {
			t.Fatalf("GET %s failed: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s expected 200, got %d", p, resp.StatusCode)
		}
	}

	// 2. Allowed bind mount inside homeDir + read-only enforcement on sharedRO + named volume
	projPath := filepath.Join(tmp, "home-agent", "project")
	docsPath := filepath.Join(tmp, "shared-docs")
	payload := map[string]any{
		"Image": "alpine",
		"HostConfig": map[string]any{
			"Binds": []string{
				projPath + ":/app:rw",
				docsPath + ":/docs:rw",
				"my_named_vol:/data",
			},
			"Mounts": []map[string]any{
				{
					"Type":     "bind",
					"Source":   docsPath,
					"Target":   "/docs2",
					"ReadOnly": false,
				},
			},
		},
	}
	resp := postJSON(t, client, "/v1.47/containers/create", payload)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid bind mounts, got %d: %s", resp.StatusCode, string(body))
	}

	hc := (*lastReceived)["HostConfig"].(map[string]any)
	binds := hc["Binds"].([]any)
	if binds[0] != "/mnt/wsl/box-binds/test/home-agent/project:/app:rw" {
		t.Fatalf("unexpected rewritten home bind: %v", binds[0])
	}
	if binds[1] != "/mnt/wsl/box-binds/test/shared/docs:/docs:ro" {
		t.Fatalf("expected RO enforcement on shared bind, got: %v", binds[1])
	}
	if binds[2] != "my_named_vol:/data" {
		t.Fatalf("named volume should pass unchanged, got: %v", binds[2])
	}
	mounts := hc["Mounts"].([]any)
	m0 := mounts[0].(map[string]any)
	if m0["Source"] != "/mnt/wsl/box-binds/test/shared/docs" || m0["ReadOnly"] != true {
		t.Fatalf("expected rewritten RO Mount object, got: %+v", m0)
	}
}

func TestBlockedEscapeVectors(t *testing.T) {
	_, sock, tmp, _, cleanup := setupTestEnv(t)
	defer cleanup()
	client := unixHTTPClient(sock)

	homeDir := filepath.Join(tmp, "home-agent")

	cases := []struct {
		name    string
		path    string
		payload map[string]any
	}{
		{
			name: "privileged container",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Privileged": true},
			},
		},
		{
			name: "lowercase hostconfig privileged bypass attempt",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"hostconfig": map[string]any{"privileged": true},
			},
		},
		{
			name: "case-colliding HostConfig keys",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{},
				"hostconfig": map[string]any{"Privileged": true},
			},
		},
		{
			name: "docker desktop Windows host bind",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{"/run/desktop/mnt/host/c:/host"}},
			},
		},
		{
			name: "WSL mnt/c bind",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{"/mnt/c:/host"}},
			},
		},
		{
			name: "Windows C: drive bind",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{`C:\Users:/host`}},
			},
		},
		{
			name: "etc bind",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{"/etc:/host"}},
			},
		},
		{
			name: "docker socket bind",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{"/var/run/docker.sock:/var/run/docker.sock"}},
			},
		},
		{
			name: "dot-dot path traversal",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{homeDir + "/../outside-secret:/host"}},
			},
		},
		{
			name: "symlink escape to outside dir",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{filepath.Join(homeDir, "link-to-outside") + ":/host"}},
			},
		},
		{
			name: "cross-VM dangling symlink to /run/desktop/mnt/host/c",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Binds": []string{filepath.Join(homeDir, "dangling-win-link") + ":/host"}},
			},
		},
		{
			name: "Mount object bind outside prefix",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image": "alpine",
				"HostConfig": map[string]any{
					"Mounts": []map[string]any{
						{"Type": "bind", "Source": "/run/desktop/mnt/host/c", "Target": "/host"},
					},
				},
			},
		},
		{
			name: "Mount object shared propagation",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image": "alpine",
				"HostConfig": map[string]any{
					"Mounts": []map[string]any{
						{
							"Type":        "bind",
							"Source":      filepath.Join(homeDir, "project"),
							"Target":      "/app",
							"BindOptions": map[string]any{"Propagation": "rshared"},
						},
					},
				},
			},
		},
		{
			name: "CAP_SYS_ADMIN",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"CapAdd": []string{"SYS_ADMIN"}},
			},
		},
		{
			name: "CAP_ALL",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"CapAdd": []string{"ALL"}},
			},
		},
		{
			name: "pid=host",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"PidMode": "host"},
			},
		},
		{
			name: "net=host",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"NetworkMode": "host"},
			},
		},
		{
			name: "ipc=host",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"IpcMode": "host"},
			},
		},
		{
			name: "seccomp=unconfined",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"SecurityOpt": []string{"seccomp=unconfined"}},
			},
		},
		{
			name: "devices mount",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"Devices": []map[string]any{{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda"}}},
			},
		},
		{
			name: "ExtraHosts host-gateway",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"ExtraHosts": []string{"win:host-gateway"}},
			},
		},
		{
			name: "MaskedPaths empty override",
			path: "/v1.47/containers/create",
			payload: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"MaskedPaths": []string{}},
			},
		},
		{
			name: "malicious volume create host bind",
			path: "/v1.47/volumes/create",
			payload: map[string]any{
				"Name":   "evilvol",
				"Driver": "local",
				"DriverOpts": map[string]any{
					"type":   "none",
					"o":      "bind",
					"device": "/run/desktop/mnt/host/c",
				},
			},
		},
		{
			name: "privileged exec",
			path: "/v1.47/containers/abc/exec",
			payload: map[string]any{
				"Cmd":        []string{"sh"},
				"Privileged": true,
			},
		},
		{
			name:    "plugins endpoint denied",
			path:    "/v1.47/plugins/pull",
			payload: map[string]any{},
		},
		{
			name:    "swarm endpoint denied",
			path:    "/v1.47/swarm/init",
			payload: map[string]any{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := postJSON(t, client, tc.path, tc.payload)
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s: expected 403 Forbidden, got %d (body: %s)", tc.name, resp.StatusCode, string(body))
			}
		})
	}
}

func TestUpgradeHijackStream(t *testing.T) {
	_, sock, _, _, cleanup := setupTestEnv(t)
	defer cleanup()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "POST /v1.47/containers/abc/attach?stream=1&stdin=1&stdout=1 HTTP/1.1\r\n" +
		"Host: docker\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: tcp\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 Switching Protocols, got: %q", statusLine)
	}
	// Drain response headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}

	// Send payload over hijacked raw stream and verify echo
	if _, err := conn.Write([]byte("hello-docker-hijack\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "ECHO:hello-docker-hijack\n" {
		t.Fatalf("unexpected hijack echo: %q", reply)
	}
}

type mockBindRecord struct {
	target   string
	ino      uint64
	isDir    bool
	readOnly bool
}

type mockBindMounter struct {
	mu        sync.Mutex
	bound     []mockBindRecord
	unmounted []string
}

func (m *mockBindMounter) BindFD(fd int, target string, isDir bool, readOnly bool) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	m.mu.Lock()
	m.bound = append(m.bound, mockBindRecord{
		target:   target,
		ino:      st.Ino,
		isDir:    isDir,
		readOnly: readOnly,
	})
	m.mu.Unlock()
	return nil
}

func (m *mockBindMounter) UnmountAndRemove(target string) error {
	m.mu.Lock()
	m.unmounted = append(m.unmounted, target)
	m.mu.Unlock()
	return nil
}

func (m *mockBindMounter) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bound), len(m.unmounted)
}

func TestBindPinningTOCTOUMitigation(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home-agent")
	sharedRO := filepath.Join(tmp, "shared-ro")
	outsideDir := filepath.Join(tmp, "outside")
	ephRoot := filepath.Join(tmp, "ephemeral")
	projDir := filepath.Join(homeDir, "proj")
	for _, d := range []string{projDir, sharedRO, outsideDir, ephRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	var origStat syscall.Stat_t
	if err := syscall.Stat(projDir, &origStat); err != nil {
		t.Fatal(err)
	}

	mounter := &mockBindMounter{}
	bm := NewEphemeralMountManager(mounter)
	pol := &Policy{
		Enabled:             true,
		EphemeralBindRoot:   ephRoot,
		EphemeralDaemonRoot: "/run/desktop/mnt/host/wsl/box-binds/test/ephemeral",
		BindMappings: []BindMapping{
			{GuestPrefix: homeDir, DaemonPrefix: "/daemon/home", ReadOnly: false},
			{GuestPrefix: sharedRO, DaemonPrefix: "/daemon/shared", ReadOnly: true},
		},
		bindManager: bm,
	}

	// 1. Allowed bind pins the original inode via openat(O_NOFOLLOW) and rewrites to ephemeralDaemonRoot.
	body, _ := json.Marshal(map[string]any{
		"Image": "alpine",
		"HostConfig": map[string]any{
			"Binds": []string{projDir + ":/app", sharedRO + ":/ro:rw"},
		},
	})
	newBody, modified, targets, err := pol.ProcessJSONBodyWithMounts(http.MethodPost, "/containers/create", body)
	if err != nil {
		t.Fatalf("expected allowed binds to succeed, got: %v", err)
	}
	if !modified || len(targets) != 2 || len(mounter.bound) != 2 {
		t.Fatalf("expected 2 pinned ephemeral mounts, got modified=%v targets=%d bound=%d", modified, len(targets), len(mounter.bound))
	}
	if mounter.bound[0].ino != origStat.Ino || mounter.bound[0].readOnly {
		t.Fatalf("unexpected first pinned mount: %+v (expected ino=%d ro=false)", mounter.bound[0], origStat.Ino)
	}
	if !mounter.bound[1].readOnly {
		t.Fatalf("expected sharedRO ephemeral mount to force readOnly=true")
	}

	// Simulate post-validation symlink swap: even if projDir is now replaced with a symlink
	// to outsideDir, the already-pinned inode (mounter.bound[0].ino) was the original dir,
	// and any subsequent create attempt is immediately rejected by O_NOFOLLOW.
	if err := os.RemoveAll(projDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideDir, projDir); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := pol.ProcessJSONBodyWithMounts(http.MethodPost, "/containers/create", body); err == nil {
		t.Fatalf("expected symlink-swapped path to be rejected by openat(O_NOFOLLOW)")
	}

	// 2. Verify container tracking and cleanup on full ID, name, short ID, and absent reconciliation.
	var parsed map[string]any
	if err := json.Unmarshal(newBody, &parsed); err != nil {
		t.Fatal(err)
	}
	bm.Track("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "/my-box", targets)
	bm.CleanupContainer("my-box")
	if len(mounter.unmounted) != 2 {
		t.Fatalf("expected 2 ephemeral mounts unmounted by container name, got %d", len(mounter.unmounted))
	}

	bm.Track("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff", "", []string{"/eph/short"})
	bm.CleanupContainer("112233445566")
	if len(mounter.unmounted) != 3 {
		t.Fatalf("expected short-ID prefix cleanup to unmount /eph/short, got %d", len(mounter.unmounted))
	}

	// 3. Read-only prefix must NOT create non-existent subdirectories via Mkdirat.
	roMissing := filepath.Join(sharedRO, "missing-subdir")
	roBody, _ := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Binds": []string{roMissing + ":/ro"}},
	})
	if _, _, _, err := pol.ProcessJSONBodyWithMounts(http.MethodPost, "/containers/create", roBody); err == nil {
		t.Fatalf("expected missing subdir under read-only prefix to fail instead of calling Mkdirat")
	}
	if _, statErr := os.Stat(roMissing); !os.IsNotExist(statErr) {
		t.Fatalf("expected missing subdir under read-only prefix not to be created, statErr=%v", statErr)
	}

	// 4. FIFO special file must fail immediately (O_NONBLOCK) without hanging.
	fifoPath := filepath.Join(homeDir, "my-fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	fifoBody, _ := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Binds": []string{fifoPath + ":/fifo"}},
	})
	if _, _, _, err := pol.ProcessJSONBodyWithMounts(http.MethodPost, "/containers/create", fifoBody); err == nil {
		t.Fatalf("expected FIFO bind source to be rejected")
	}

	// 5. UnmountAndRemove must use os.Remove (never os.RemoveAll) so non-empty target contents survive on EINVAL.
	nonEmpty := filepath.Join(tmp, "keep-contents")
	if err := os.MkdirAll(nonEmpty, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(nonEmpty, "precious.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (linuxBindMounter{}).UnmountAndRemove(nonEmpty); err == nil {
		t.Fatalf("expected UnmountAndRemove on non-empty directory to fail instead of deleting contents")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("UnmountAndRemove deleted precious file inside directory: %v", err)
	}
}

func TestEphemeralCleanupOnEmptyIDAndPruneAndMissing(t *testing.T) {
	tmp := t.TempDir()
	homeDir := filepath.Join(tmp, "home-agent")
	ephRoot := filepath.Join(tmp, "ephemeral")
	for _, d := range []string{filepath.Join(homeDir, "proj"), ephRoot} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	upstreamSock := filepath.Join(tmp, "upstream.sock")
	proxySock := filepath.Join(tmp, "proxy.sock")
	var stateMu sync.Mutex
	returnEmptyID := false
	activeContainers := []map[string]any{}
	eventCh := make(chan string, 4)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1.47/containers/create", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		empty := returnEmptyID
		stateMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if empty {
			_, _ = w.Write([]byte(`{"Warnings":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"Id":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}`))
	})
	mux.HandleFunc("/v1.47/containers/prune", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		activeContainers = nil
		stateMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ContainersDeleted":["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"]}`))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		stateMu.Lock()
		list := append([]map[string]any(nil), activeContainers...)
		stateMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		select {
		case <-r.Context().Done():
		case ev := <-eventCh:
			_, _ = w.Write([]byte(ev + "\n"))
		}
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	upLn, err := net.Listen("unix", upstreamSock)
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &http.Server{Handler: mux}
	go func() { _ = upSrv.Serve(upLn) }()
	defer upSrv.Close()

	mounter := &mockBindMounter{}
	pol := &Policy{
		Enabled:             true,
		EphemeralBindRoot:   ephRoot,
		EphemeralDaemonRoot: "/daemon/ephemeral",
		BindMappings: []BindMapping{
			{GuestPrefix: homeDir, DaemonPrefix: "/daemon/home", ReadOnly: false},
		},
	}
	proxy := NewPolicyProxy(upstreamSock, pol, log.New(io.Discard, "", 0))
	proxy.bindManager.mounter = mounter
	pLn, err := net.Listen("unix", proxySock)
	if err != nil {
		t.Fatal(err)
	}
	pSrv := &http.Server{Handler: proxy}
	go func() { _ = pSrv.Serve(pLn) }()
	defer func() {
		proxy.Close()
		_ = pSrv.Close()
	}()

	client := unixHTTPClient(proxySock)
	createPayload := map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Binds": []string{filepath.Join(homeDir, "proj") + ":/app"}},
	}

	// 1. 2xx response without Id must immediately clean up ephemeral targets.
	stateMu.Lock()
	returnEmptyID = true
	stateMu.Unlock()
	resp := postJSON(t, client, "/v1.47/containers/create", createPayload)
	resp.Body.Close()
	if b, u := mounter.counts(); b != 1 || u != 1 {
		t.Fatalf("expected empty-Id 2xx create to unmount immediately; bound=%d unmounted=%d", b, u)
	}

	// 2. Normal create followed by POST /containers/prune must clean up tracked container.
	stateMu.Lock()
	returnEmptyID = false
	activeContainers = []map[string]any{{"Id": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}
	stateMu.Unlock()
	resp = postJSON(t, client, "/v1.47/containers/create?name=pruneme", createPayload)
	resp.Body.Close()
	if !proxy.bindManager.HasTracked() {
		t.Fatalf("expected tracked container after create")
	}
	resp = postJSON(t, client, "/v1.47/containers/prune", map[string]any{})
	resp.Body.Close()
	if proxy.bindManager.HasTracked() {
		t.Fatalf("expected POST /containers/prune to clean up tracked ephemeral mounts")
	}
	if _, u := mounter.counts(); u != 2 {
		t.Fatalf("expected 2 unmounted targets total after prune, got %d", u)
	}

	// 3. AutoRemove (--rm) destroy event on /events must automatically clean up ephemeral mounts.
	resp = postJSON(t, client, "/v1.47/containers/create?name=rmme", createPayload)
	resp.Body.Close()
	if !proxy.bindManager.HasTracked() {
		t.Fatalf("expected tracked container before AutoRemove destroy event")
	}
	eventCh <- `{"Type":"container","Action":"destroy","Actor":{"ID":"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}}`
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && proxy.bindManager.HasTracked() {
		time.Sleep(20 * time.Millisecond)
	}
	if proxy.bindManager.HasTracked() {
		t.Fatalf("expected /events container destroy to clean up tracked ephemeral mounts")
	}
	if _, u := mounter.counts(); u != 3 {
		t.Fatalf("expected 3 unmounted targets total after AutoRemove event, got %d", u)
	}
}

func boolPtr(b bool) *bool { return &b }

func TestPortBindingsAndInternalNetworkPolicy(t *testing.T) {
	// 1. Default forceLoopbackPortBindings=true rewrites empty HostIp -> 127.0.0.1 and blocks 0.0.0.0
	pol := &Policy{Enabled: true}
	body, _ := json.Marshal(map[string]any{
		"Image": "alpine",
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{
				"80/tcp": []map[string]any{{"HostPort": "8080"}},
			},
		},
	})
	rewritten, modified, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", body)
	if err != nil || !modified {
		t.Fatalf("expected loopback HostIp rewrite, got err=%v modified=%v", err, modified)
	}
	if !strings.Contains(string(rewritten), `"127.0.0.1"`) {
		t.Fatalf("expected HostIp 127.0.0.1 in rewritten payload: %s", string(rewritten))
	}

	badIPBody, _ := json.Marshal(map[string]any{
		"Image": "alpine",
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{
				"80/tcp": []map[string]any{{"HostIp": "0.0.0.0", "HostPort": "8080"}},
			},
		},
	})
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", badIPBody); err == nil {
		t.Fatalf("expected 0.0.0.0 HostIp to be denied when forceLoopbackPortBindings=true")
	}

	// 2. allowedPublishedPorts allowlist
	polAllowed := &Policy{Enabled: true, AllowedPublishedPorts: []int{8080}}
	if _, _, err := polAllowed.ProcessJSONBody(http.MethodPost, "/containers/create", body); err != nil {
		t.Fatalf("expected allowlisted port 8080 to pass, got %v", err)
	}
	badPortBody, _ := json.Marshal(map[string]any{
		"Image": "alpine",
		"HostConfig": map[string]any{
			"PortBindings": map[string]any{
				"80/tcp": []map[string]any{{"HostIp": "127.0.0.1", "HostPort": "9090"}},
			},
		},
	})
	if _, _, err := polAllowed.ProcessJSONBody(http.MethodPost, "/containers/create", badPortBody); err == nil {
		t.Fatalf("expected non-allowlisted port 9090 to be denied")
	}

	// 3. allowPortBindings=false denies PortBindings and PublishAllPorts
	polNoPorts := &Policy{Enabled: true, AllowPortBindings: boolPtr(false)}
	if _, _, err := polNoPorts.ProcessJSONBody(http.MethodPost, "/containers/create", body); err == nil {
		t.Fatalf("expected PortBindings to be denied when allowPortBindings=false")
	}

	// 4. PublishAllPorts=true must be denied when forceLoopbackPortBindings=true (default)
	pubAllBody, _ := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"PublishAllPorts": true},
	})
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", pubAllBody); err == nil {
		t.Fatalf("expected PublishAllPorts=true to be denied when forceLoopbackPortBindings=true")
	}
	polNonLoopback := &Policy{Enabled: true, ForceLoopbackPortBindings: boolPtr(false)}
	if _, _, err := polNonLoopback.ProcessJSONBody(http.MethodPost, "/containers/create", pubAllBody); err != nil {
		t.Fatalf("expected PublishAllPorts=true to be allowed when forceLoopbackPortBindings=false, got: %v", err)
	}

	// 5. forceInternalNetwork=true blocks bridge, container:*, non-internal networks, NetworkingConfig, and /networks/*/connect
	polInternal := &Policy{
		Enabled:              true,
		ForceInternalNetwork: true,
		networkChecker: func(name string) (bool, error) {
			return name == "safe-internal", nil
		},
	}
	for _, nm := range []string{"bridge", "container:other", "custom-external"} {
		badNMBody, _ := json.Marshal(map[string]any{
			"Image":      "alpine",
			"HostConfig": map[string]any{"NetworkMode": nm},
		})
		if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/containers/create", badNMBody); err == nil {
			t.Fatalf("expected NetworkMode=%q to be denied when forceInternalNetwork=true", nm)
		}
	}
	okNMBody, _ := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"NetworkMode": "safe-internal"},
	})
	if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/containers/create", okNMBody); err != nil {
		t.Fatalf("expected verified internal network to be allowed, got %v", err)
	}
	badEpNoHC, _ := json.Marshal(map[string]any{
		"Image":            "alpine",
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{"bridge": map[string]any{}}},
	})
	if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/containers/create", badEpNoHC); err == nil {
		t.Fatalf("expected NetworkingConfig.EndpointsConfig.bridge without HostConfig to be denied")
	}
	okEpNoHC, _ := json.Marshal(map[string]any{
		"Image":            "alpine",
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{"safe-internal": map[string]any{}}},
	})
	if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/containers/create", okEpNoHC); err != nil {
		t.Fatalf("expected verified internal NetworkingConfig.EndpointsConfig to be allowed, got %v", err)
	}
	defaultCliPayload, _ := json.Marshal(map[string]any{
		"Image":            "alpine",
		"HostConfig":       map[string]any{"NetworkMode": "default"},
		"NetworkingConfig": map[string]any{"EndpointsConfig": map[string]any{"default": map[string]any{}}},
	})
	defOut, defMod, err := polInternal.ProcessJSONBody(http.MethodPost, "/containers/create", defaultCliPayload)
	if err != nil || !defMod || !strings.Contains(string(defOut), `"NetworkMode":"none"`) || strings.Contains(string(defOut), `"default"`) {
		t.Fatalf("expected Docker 29 default EndpointsConfig to rewrite cleanly to NetworkMode=none, got err=%v mod=%v body=%s", err, defMod, string(defOut))
	}
	if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/networks/bridge/connect", []byte(`{"Container":"abc"}`)); err == nil {
		t.Fatalf("expected POST /networks/bridge/connect to be denied")
	}
	if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/networks/custom-external/connect", []byte(`{"Container":"abc"}`)); err == nil {
		t.Fatalf("expected POST /networks/custom-external/connect to be denied")
	}
	if _, _, err := polInternal.ProcessJSONBody(http.MethodPost, "/networks/safe-internal/connect", []byte(`{"Container":"abc"}`)); err != nil {
		t.Fatalf("expected POST /networks/safe-internal/connect to be allowed, got %v", err)
	}
	netCreateBody, _ := json.Marshal(map[string]any{"Name": "test-net"})
	netOut, netMod, err := polInternal.ProcessJSONBody(http.MethodPost, "/networks/create", netCreateBody)
	if err != nil || !netMod || !strings.Contains(string(netOut), `"Internal":true`) {
		t.Fatalf("expected /networks/create to inject Internal:true, got err=%v mod=%v body=%s", err, netMod, string(netOut))
	}
}

func TestResourceLimitsAndRegistryAllowlist(t *testing.T) {
	pol := &Policy{
		Enabled: true,
		DefaultLimits: ResourceLimits{
			MemoryBytes: 512 * 1024 * 1024,
			NanoCpus:    1_000_000_000,
			PidsLimit:   128,
		},
		MaxLimits: ResourceLimits{
			MemoryBytes: 1024 * 1024 * 1024,
			NanoCpus:    2_000_000_000,
			PidsLimit:   256,
		},
		AllowedRegistries: []string{"docker.io", "ghcr.io", "localhost:5000"},
	}

	// 1. Injects default limits when HostConfig is omitted
	createBody, _ := json.Marshal(map[string]any{"Image": "alpine:latest"})
	out, mod, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", createBody)
	if err != nil || !mod {
		t.Fatalf("expected default limits injection, got err=%v mod=%v", err, mod)
	}
	if !strings.Contains(string(out), `"Memory":536870912`) || !strings.Contains(string(out), `"PidsLimit":128`) {
		t.Fatalf("missing injected limits in: %s", string(out))
	}

	// 2. Rejects Memory exceeding maxLimits on create and update
	tooBigBody, _ := json.Marshal(map[string]any{
		"Image":      "ghcr.io/org/app@sha256:abcdef",
		"HostConfig": map[string]any{"Memory": 2 * 1024 * 1024 * 1024},
	})
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", tooBigBody); err == nil {
		t.Fatalf("expected Memory > maxLimits to be denied on create")
	}
	updateTooBig, _ := json.Marshal(map[string]any{"PidsLimit": 999})
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/abc/update", updateTooBig); err == nil {
		t.Fatalf("expected PidsLimit > maxLimits to be denied on update")
	}

	// 3. Registry allowlist edge cases (aliases, raw digests, fromSrc, duplicate params, /images/load)
	for _, allowedImg := range []string{"alpine", "library/ubuntu:24.04", "registry.hub.docker.com/library/alpine", "ghcr.io/org/img:v1", "localhost:5000/test:1", "ghcr.io/org/img@sha256:1234"} {
		b, _ := json.Marshal(map[string]any{"Image": allowedImg})
		if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", b); err != nil {
			t.Fatalf("expected image %q to be allowed, got: %v", allowedImg, err)
		}
		if err := pol.CheckEndpoint(http.MethodPost, "/images/create", map[string][]string{"fromImage": {allowedImg}}); err != nil {
			t.Fatalf("expected pull %q to be allowed, got: %v", allowedImg, err)
		}
	}
	for _, blockedImg := range []string{"quay.io/coreos/etcd:v3", "evil.example.com:8443/malware:latest", "sha256:0123456789abcdef"} {
		b, _ := json.Marshal(map[string]any{"Image": blockedImg})
		if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", b); err == nil {
			t.Fatalf("expected image %q to be denied", blockedImg)
		}
		if err := pol.CheckEndpoint(http.MethodPost, "/images/create", map[string][]string{"fromImage": {blockedImg}}); err == nil {
			t.Fatalf("expected pull %q to be denied", blockedImg)
		}
	}
	if err := pol.CheckEndpoint(http.MethodPost, "/images/create", map[string][]string{"fromSrc": {"https://evil.example.com/rootfs.tar"}}); err == nil {
		t.Fatalf("expected /images/create?fromSrc=... to be denied when allowedRegistries is set")
	}
	if err := pol.CheckEndpoint(http.MethodPost, "/images/create", map[string][]string{"fromImage": {"docker.io/alpine", "evil.com/backdoor"}}); err == nil {
		t.Fatalf("expected duplicate fromImage parameter pollution to be denied")
	}
	if err := pol.CheckEndpoint(http.MethodPost, "/images/load", map[string][]string{}); err == nil {
		t.Fatalf("expected POST /images/load to be denied when allowedRegistries is set")
	}

	// 4. Realistic Docker CLI payload (Memory=0, NanoCpus=0, MemorySwap=0) injects defaults before maxLimits check
	cliPayload, _ := json.Marshal(map[string]any{
		"Image": "alpine",
		"HostConfig": map[string]any{
			"Memory":     0,
			"NanoCpus":   0,
			"MemorySwap": 0,
			"CpuQuota":   0,
			"CpuPeriod":  0,
		},
	})
	cliOut, cliMod, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", cliPayload)
	if err != nil || !cliMod {
		t.Fatalf("expected realistic Docker CLI payload with zeros to inject defaults cleanly, got err=%v mod=%v", err, cliMod)
	}
	if !strings.Contains(string(cliOut), `"Memory":536870912`) || !strings.Contains(string(cliOut), `"NanoCpus":1000000000`) || !strings.Contains(string(cliOut), `"PidsLimit":128`) {
		t.Fatalf("expected default limits injected over zeros: %s", string(cliOut))
	}

	// 5. maxLimits without defaultLimits still caps containers when fields are omitted or 0
	polMaxOnly := &Policy{
		Enabled: true,
		MaxLimits: ResourceLimits{
			MemoryBytes: 1024 * 1024 * 1024,
			NanoCpus:    2_000_000_000,
			PidsLimit:   256,
		},
	}
	maxOnlyBody, _ := json.Marshal(map[string]any{
		"Image":      "alpine",
		"HostConfig": map[string]any{"Memory": 0, "NanoCpus": 0},
	})
	maxOut, maxMod, err := polMaxOnly.ProcessJSONBody(http.MethodPost, "/containers/create", maxOnlyBody)
	if err != nil || !maxMod {
		t.Fatalf("expected maxLimits-only policy to inject max caps on 0/unset fields, got err=%v mod=%v", err, maxMod)
	}
	if !strings.Contains(string(maxOut), `"Memory":1073741824`) || !strings.Contains(string(maxOut), `"PidsLimit":256`) {
		t.Fatalf("expected maxLimits caps injected: %s", string(maxOut))
	}
	maxNoHCOut, maxNoHCMod, err := polMaxOnly.ProcessJSONBody(http.MethodPost, "/containers/create", []byte(`{"Image":"alpine"}`))
	if err != nil || !maxNoHCMod || !strings.Contains(string(maxNoHCOut), `"Memory":1073741824`) {
		t.Fatalf("expected maxLimits-only policy to inject caps when HostConfig omitted, got err=%v mod=%v body=%s", err, maxNoHCMod, string(maxNoHCOut))
	}

	// 6. Update allows 0 ("unchanged"), rejects negative (-1), and rejects > maxLimits
	updateOk, _ := json.Marshal(map[string]any{"Memory": 256 * 1024 * 1024, "NanoCpus": 0, "PidsLimit": 0})
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/abc/update", updateOk); err != nil {
		t.Fatalf("expected /update with valid Memory and 0 NanoCpus to pass, got %v", err)
	}
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/abc/update", []byte(`{"PidsLimit":-1}`)); err == nil {
		t.Fatalf("expected /update PidsLimit=-1 (unlimited) to be denied")
	}

	// 7. MemorySwap, CpuQuota/CpuPeriod bypasses, and float edge cases
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", []byte(`{"Image":"alpine","HostConfig":{"MemorySwap":-1}}`)); err == nil {
		t.Fatalf("expected MemorySwap=-1 to be denied")
	}
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", []byte(`{"Image":"alpine","HostConfig":{"CpuQuota":500000,"CpuPeriod":100000}}`)); err == nil {
		t.Fatalf("expected CpuQuota/CpuPeriod=5 CPUs (> max 2 CPUs) to be denied")
	}
	quotaOkBody, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", []byte(`{"Image":"alpine","HostConfig":{"CpuQuota":50000,"CpuPeriod":100000,"NanoCpus":0}}`))
	if err != nil {
		t.Fatalf("expected valid CpuQuota <= maxLimits to be allowed, got %v", err)
	}
	if strings.Contains(string(quotaOkBody), `"NanoCpus":1000000000`) {
		t.Fatalf("did not expect NanoCpus injection alongside explicit CpuQuota: %s", string(quotaOkBody))
	}
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", []byte(`{"Image":"alpine","HostConfig":{"Memory":1.5}}`)); err == nil {
		t.Fatalf("expected non-integer float Memory to be rejected")
	}
	if _, _, err := pol.ProcessJSONBody(http.MethodPost, "/containers/create", []byte(`{"Image":"alpine","HostConfig":{"Memory":1e25}}`)); err == nil {
		t.Fatalf("expected overflowing float Memory to be rejected")
	}
}

func TestBuildKitDisabledWithNetworkOrRegistryRestrictions(t *testing.T) {
	endpoints := []string{"/grpc", "/session", "/v1.47/grpc", "/v1.47/session"}

	// Allowed when AllowBuildKit is true and neither ForceInternalNetwork nor AllowedRegistries is set.
	polOpen := &Policy{
		Enabled:       true,
		AllowBuildKit: true,
	}
	for _, ep := range endpoints {
		if err := polOpen.CheckEndpoint(http.MethodPost, ep, nil); err != nil {
			t.Fatalf("expected %s to be allowed when no network/registry restrictions are active, got %v", ep, err)
		}
	}

	// Denied when ForceInternalNetwork is true, even if AllowBuildKit is true.
	polInternal := &Policy{
		Enabled:              true,
		AllowBuildKit:        true,
		ForceInternalNetwork: true,
	}
	for _, ep := range endpoints {
		if err := polInternal.CheckEndpoint(http.MethodPost, ep, nil); err == nil {
			t.Fatalf("expected %s to be denied when ForceInternalNetwork is true", ep)
		}
	}

	// Denied when AllowedRegistries is non-empty, even if AllowBuildKit is true.
	polRegistries := &Policy{
		Enabled:           true,
		AllowBuildKit:     true,
		AllowedRegistries: []string{"docker.io"},
	}
	for _, ep := range endpoints {
		if err := polRegistries.CheckEndpoint(http.MethodPost, ep, nil); err == nil {
			t.Fatalf("expected %s to be denied when AllowedRegistries is non-empty", ep)
		}
	}
}

func TestLegacyBuildWithForceInternalNetwork(t *testing.T) {
	pol := &Policy{
		Enabled:              true,
		ForceInternalNetwork: true,
	}

	// Missing networkmode must be denied.
	if err := pol.CheckEndpoint(http.MethodPost, "/build", nil); err == nil {
		t.Fatalf("expected POST /build without networkmode to be denied when ForceInternalNetwork is true")
	}

	// Non-none networkmode must be denied.
	if err := pol.CheckEndpoint(http.MethodPost, "/build", map[string][]string{"networkmode": {"bridge"}}); err == nil {
		t.Fatalf("expected POST /build with networkmode=bridge to be denied when ForceInternalNetwork is true")
	}

	// networkmode=none must be allowed.
	if err := pol.CheckEndpoint(http.MethodPost, "/build", map[string][]string{"networkmode": {"none"}}); err != nil {
		t.Fatalf("expected POST /build with networkmode=none to be allowed, got %v", err)
	}
}

func TestBlockedVolumesFromCgroupParentOomKillDisable(t *testing.T) {
	pol := &Policy{Enabled: true}
	cases := []struct {
		name string
		path string
		body map[string]any
	}{
		{
			name: "VolumesFrom",
			path: "/containers/create",
			body: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"VolumesFrom": []string{"other"}},
			},
		},
		{
			name: "CgroupParent",
			path: "/containers/create",
			body: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"CgroupParent": "/custom"},
			},
		},
		{
			name: "OomKillDisable",
			path: "/containers/create",
			body: map[string]any{
				"Image":      "alpine",
				"HostConfig": map[string]any{"OomKillDisable": true},
			},
		},
		{
			name: "UpdateCgroupParent",
			path: "/containers/c1/update",
			body: map[string]any{"CgroupParent": "/custom"},
		},
	}
	for _, tc := range cases {
		raw, _ := json.Marshal(tc.body)
		if _, _, err := pol.ProcessJSONBody(http.MethodPost, tc.path, raw); err == nil {
			t.Fatalf("expected %s to be denied", tc.name)
		}
	}

	// Verify HTTP 403 via PolicyProxy
	tmp := t.TempDir()
	upSock := filepath.Join(tmp, "up.sock")
	ln, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	pp := NewPolicyProxy(upSock, &Policy{Enabled: true}, log.New(io.Discard, "", 0))
	defer pp.Close()
	pxSock := filepath.Join(tmp, "px.sock")
	pxLn, err := net.Listen("unix", pxSock)
	if err != nil {
		t.Fatal(err)
	}
	pxSrv := &http.Server{Handler: pp}
	go func() { _ = pxSrv.Serve(pxLn) }()
	defer pxSrv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", pxSock)
			},
		},
	}
	for _, tc := range cases {
		raw, _ := json.Marshal(tc.body)
		resp, err := client.Post("http://docker"+tc.path, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s request failed: %v", tc.name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 for %s, got %d", tc.name, resp.StatusCode)
		}
	}
}

func TestCrossTenantLabelIsolation(t *testing.T) {
	tmp := t.TempDir()
	upSock := filepath.Join(tmp, "upstream.sock")
	pxSock := filepath.Join(tmp, "proxy.sock")

	const distro = "wsl-agent-sandbox"

	var mu sync.Mutex
	volumes := map[string]map[string]string{
		"host_vol":    {},
		"sandbox_vol": {sandboxDistroLabel: distro},
	}
	networks := map[string]map[string]string{
		"host_net":    {},
		"sandbox_net": {sandboxDistroLabel: distro},
	}
	var lastContainerCreateLabels map[string]any
	var lastVolumeCreateLabels map[string]any
	var lastNetworkCreateLabels map[string]any
	recordedFilters := map[string]string{}

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		if lbls, ok := body["Labels"].(map[string]any); ok {
			lastContainerCreateLabels = lbls
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"sandbox_c"}`))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/containers/json"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Id":"sandbox_c"}]`))
	})
	mux.HandleFunc("/containers/prune", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/containers/prune"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ContainersDeleted":[]}`))
	})
	mux.HandleFunc("/containers/host_c/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/host_c/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"host_c","Config":{"Labels":{}}}`))
			return
		}
		t.Errorf("unexpected upstream call to host_c: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/containers/host_c", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream DELETE/call to host_c: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/containers/sandbox_c/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/containers/sandbox_c/json":
			_, _ = w.Write([]byte(`{"Id":"sandbox_c","Config":{"Labels":{"com.wsl-agent-sandbox.distro":"wsl-agent-sandbox"}}}`))
		case "/containers/sandbox_c/exec":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"exec_sandbox_1"}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	})
	mux.HandleFunc("/containers/sandbox_c", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/commit", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"sha256:abc"}`))
	})
	mux.HandleFunc("/exec/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/volumes/create", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name   string            `json:"Name"`
			Labels map[string]string `json:"Labels"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		lastVolumeCreateLabels = map[string]any{}
		for k, v := range body.Labels {
			lastVolumeCreateLabels[k] = v
		}
		if body.Name != "" {
			volumes[body.Name] = body.Labels
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Name":"` + body.Name + `"}`))
	})
	mux.HandleFunc("/volumes/prune", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/volumes/prune"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/volumes/", func(w http.ResponseWriter, r *http.Request) {
		volName := strings.TrimPrefix(r.URL.Path, "/volumes/")
		mu.Lock()
		lbls, exists := volumes[volName]
		mu.Unlock()
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": volName, "Labels": lbls})
	})
	mux.HandleFunc("/volumes", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/volumes"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Volumes":[]}`))
	})
	mux.HandleFunc("/networks/create", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		if lbls, ok := body["Labels"].(map[string]any); ok {
			lastNetworkCreateLabels = lbls
		}
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"Id":"sandbox_net"}`))
	})
	mux.HandleFunc("/networks/prune", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/networks/prune"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	mux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, "/networks/")
		netName, _, _ := strings.Cut(rest, "/")
		mu.Lock()
		lbls, exists := networks[netName]
		mu.Unlock()
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": netName, "Labels": lbls})
	})
	mux.HandleFunc("/networks", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/networks"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		recordedFilters["/events"] = r.URL.Query().Get("filters")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	upLn, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &http.Server{Handler: mux}
	go func() { _ = upSrv.Serve(upLn) }()
	defer upSrv.Close()

	pol := &Policy{
		Enabled:    true,
		DistroName: distro,
	}
	pp := NewPolicyProxy(upSock, pol, log.New(io.Discard, "", 0))
	defer pp.Close()

	pxLn, err := net.Listen("unix", pxSock)
	if err != nil {
		t.Fatal(err)
	}
	pxSrv := &http.Server{Handler: pp}
	go func() { _ = pxSrv.Serve(pxLn) }()
	defer pxSrv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", pxSock)
			},
		},
	}

	doReq := func(method, path string, body string) int {
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, "http://docker"+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 1. Creation endpoints inject and overwrite spoofed sandbox distro label.
	if code := doReq(http.MethodPost, "/containers/create", `{"Image":"alpine","Labels":{"com.wsl-agent-sandbox.distro":"evil","foo":"bar"}}`); code != http.StatusCreated {
		t.Fatalf("expected 201 on container create, got %d", code)
	}
	if lastContainerCreateLabels[sandboxDistroLabel] != distro || lastContainerCreateLabels["foo"] != "bar" {
		t.Fatalf("expected injected container label, got %#v", lastContainerCreateLabels)
	}
	if code := doReq(http.MethodPost, "/volumes/create", ``); code != http.StatusCreated {
		t.Fatalf("expected 201 on empty-body volume create, got %d", code)
	}
	if lastVolumeCreateLabels[sandboxDistroLabel] != distro {
		t.Fatalf("expected injected volume label, got %#v", lastVolumeCreateLabels)
	}
	if code := doReq(http.MethodPost, "/networks/create", `{"Name":"sandbox_net","Labels":{"com.wsl-agent-sandbox.distro":"spoof"}}`); code != http.StatusCreated {
		t.Fatalf("expected 201 on network create (ForceInternalNetwork=false), got %d", code)
	}
	if lastNetworkCreateLabels[sandboxDistroLabel] != distro {
		t.Fatalf("expected injected network label, got %#v", lastNetworkCreateLabels)
	}

	// 2. Host container operations must return 403; sandbox container operations succeed.
	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/containers/host_c/json", ""},
		{http.MethodPost, "/containers/host_c/exec", `{"Cmd":["sh"]}`},
		{http.MethodGet, "/containers/host_c/archive?path=/etc/passwd", ""},
		{http.MethodDelete, "/containers/host_c", ""},
		{http.MethodPost, "/commit?container=host_c", ""},
	} {
		if code := doReq(tc.method, tc.path, tc.body); code != http.StatusForbidden {
			t.Fatalf("expected 403 for %s %s, got %d", tc.method, tc.path, code)
		}
	}

	if code := doReq(http.MethodGet, "/containers/sandbox_c/json", ""); code != http.StatusOK {
		t.Fatalf("expected 200 for sandbox_c inspect, got %d", code)
	}
	if code := doReq(http.MethodGet, "/containers/sandbox_c/archive?path=/tmp", ""); code != http.StatusOK {
		t.Fatalf("expected 200 for sandbox_c archive, got %d", code)
	}
	if code := doReq(http.MethodPost, "/commit?container=sandbox_c", ""); code != http.StatusCreated {
		t.Fatalf("expected 201 for sandbox_c commit, got %d", code)
	}
	if code := doReq(http.MethodDelete, "/containers/sandbox_c", ""); code != http.StatusNoContent {
		t.Fatalf("expected 204 for sandbox_c delete, got %d", code)
	}

	// 3. Untracked exec IDs return 403; exec IDs created on sandbox_c succeed.
	if code := doReq(http.MethodPost, "/exec/untracked_exec_id/start", `{}`); code != http.StatusForbidden {
		t.Fatalf("expected 403 for untracked exec start, got %d", code)
	}
	if code := doReq(http.MethodPost, "/containers/sandbox_c/exec", `{"Cmd":["id"]}`); code != http.StatusCreated {
		t.Fatalf("expected 201 for sandbox_c exec create, got %d", code)
	}
	if code := doReq(http.MethodPost, "/exec/exec_sandbox_1/start", `{}`); code != http.StatusOK {
		t.Fatalf("expected 200 for tracked exec start, got %d", code)
	}

	// 4. List/prune/events endpoints receive injected label filter.
	for _, ep := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/containers/json"},
		{http.MethodPost, "/containers/prune"},
		{http.MethodGet, "/volumes"},
		{http.MethodPost, "/volumes/prune"},
		{http.MethodGet, "/networks"},
		{http.MethodPost, "/networks/prune"},
		{http.MethodGet, "/events"},
	} {
		if code := doReq(ep.method, ep.path, ""); code != http.StatusOK {
			t.Fatalf("expected 200 for %s %s, got %d", ep.method, ep.path, code)
		}
		got := recordedFilters[ep.path]
		if !strings.Contains(got, sandboxDistroLabel+"="+distro) {
			t.Fatalf("expected label filter on %s, got %q", ep.path, got)
		}
	}

	// 5. Volume ownership: host_vol denied (403), sandbox_vol and new implicit volume allowed.
	if code := doReq(http.MethodPost, "/containers/create", `{"Image":"alpine","HostConfig":{"Binds":["host_vol:/data"]}}`); code != http.StatusForbidden {
		t.Fatalf("expected 403 when mounting host_vol via Binds, got %d", code)
	}
	if code := doReq(http.MethodPost, "/containers/create", `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Source":"host_vol","Target":"/data"}]}}`); code != http.StatusForbidden {
		t.Fatalf("expected 403 when mounting host_vol via Mounts, got %d", code)
	}
	if code := doReq(http.MethodGet, "/volumes/host_vol", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on GET /volumes/host_vol, got %d", code)
	}
	if code := doReq(http.MethodGet, "/volumes/sandbox_vol", ""); code != http.StatusOK {
		t.Fatalf("expected 200 on GET /volumes/sandbox_vol, got %d", code)
	}
	if code := doReq(http.MethodPost, "/containers/create", `{"Image":"alpine","HostConfig":{"Binds":["sandbox_vol:/data"]}}`); code != http.StatusCreated {
		t.Fatalf("expected 201 when mounting sandbox_vol, got %d", code)
	}
	if code := doReq(http.MethodPost, "/containers/create", `{"Image":"alpine","HostConfig":{"Binds":["new_implicit_vol:/data"]}}`); code != http.StatusCreated {
		t.Fatalf("expected 201 when mounting new implicit named volume, got %d", code)
	}
	mu.Lock()
	implicitLbls := volumes["new_implicit_vol"]
	mu.Unlock()
	if implicitLbls[sandboxDistroLabel] != distro {
		t.Fatalf("expected new_implicit_vol to be pre-created with sandbox label, got %#v", implicitLbls)
	}

	// 6. Network ownership: host_net denied (403), sandbox_net allowed.
	if code := doReq(http.MethodGet, "/networks/host_net", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on GET /networks/host_net, got %d", code)
	}
	if code := doReq(http.MethodPost, "/networks/host_net/connect", `{"Container":"sandbox_c"}`); code != http.StatusForbidden {
		t.Fatalf("expected 403 on POST /networks/host_net/connect, got %d", code)
	}
	if code := doReq(http.MethodGet, "/networks/sandbox_net", ""); code != http.StatusOK {
		t.Fatalf("expected 200 on GET /networks/sandbox_net, got %d", code)
	}
}

func TestTenantIsolationHardening(t *testing.T) {
	sockDir, err := os.MkdirTemp("/tmp", "dpp-iso2-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sockDir)

	upSock := filepath.Join(sockDir, "up.sock")
	pxSock := filepath.Join(sockDir, "px.sock")
	const distro = "wsl-agent-sandbox"

	var mu sync.Mutex
	var lastCreateRaw []byte

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/create", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			lastCreateRaw = b
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Id":"sandbox_c"}`))
			return
		}
		t.Errorf("unexpected non-POST /containers/create forwarded upstream: %s", r.Method)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/containers/create/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/create/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Id":"host_named_create","Config":{"Labels":{}}}`))
			return
		}
		t.Errorf("unexpected upstream call to host container named 'create': %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/containers/host_c/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"host_c","Config":{"Labels":{}}}`))
	})
	mux.HandleFunc("/containers/sandbox_c/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Id":"sandbox_c","Config":{"Labels":{"com.wsl-agent-sandbox.distro":"wsl-agent-sandbox"}}}`))
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/networks/bridge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Name":"bridge","Labels":{},"Containers":{"host_c":{}}}`))
	})
	mux.HandleFunc("/networks/bridge/connect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/networks/bridge/disconnect", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/exec/preexisting_sandbox_exec/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"preexisting_sandbox_exec","ContainerID":"sandbox_c"}`))
	})
	mux.HandleFunc("/exec/preexisting_sandbox_exec/start", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/exec/preexisting_host_exec/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ID":"preexisting_host_exec","ContainerID":"host_c"}`))
	})
	mux.HandleFunc("/exec/preexisting_host_exec/start", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected upstream start on host exec")
		w.WriteHeader(http.StatusOK)
	})

	upLn, err := net.Listen("unix", upSock)
	if err != nil {
		t.Fatal(err)
	}
	upSrv := &http.Server{Handler: mux}
	go func() { _ = upSrv.Serve(upLn) }()
	defer upSrv.Close()

	pol := &Policy{
		Enabled:       true,
		DistroName:    distro,
		DefaultLimits: ResourceLimits{PidsLimit: 64},
	}
	pp := NewPolicyProxy(upSock, pol, log.New(io.Discard, "", 0))
	defer pp.Close()

	pxLn, err := net.Listen("unix", pxSock)
	if err != nil {
		t.Fatal(err)
	}
	pxSrv := &http.Server{Handler: pp}
	go func() { _ = pxSrv.Serve(pxLn) }()
	defer pxSrv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", pxSock)
			},
		},
	}
	doReqCT := func(method, path, ct, body string) int {
		t.Helper()
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, "http://docker"+path, rdr)
		if err != nil {
			t.Fatal(err)
		}
		if ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 1. All container:<id> namespace modes enforce tenant ownership.
	for _, nsField := range []string{"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode", "NetworkMode"} {
		badBody := `{"Image":"alpine","HostConfig":{"` + nsField + `":"container:host_c"}}`
		if code := doReqCT(http.MethodPost, "/containers/create", "application/json", badBody); code != http.StatusForbidden {
			t.Fatalf("expected 403 for %s=container:host_c, got %d", nsField, code)
		}
		okBody := `{"Image":"alpine","HostConfig":{"` + nsField + `":"container:sandbox_c"}}`
		if code := doReqCT(http.MethodPost, "/containers/create", "application/json", okBody); code != http.StatusCreated {
			t.Fatalf("expected 201 for %s=container:sandbox_c, got %d", nsField, code)
		}
	}

	// 2. Form-encoded Content-Type smuggling is blocked (403).
	if code := doReqCT(http.MethodPost, "/commit", "application/x-www-form-urlencoded", "container=host_c"); code != http.StatusForbidden {
		t.Fatalf("expected 403 for form-smuggled /commit, got %d", code)
	}

	// 3. Lowercase null keys ("labels": null, "hostconfig": null) do not produce duplicate case-colliding keys;
	//    anonymous volume mounts receive VolumeOptions.Labels[sandboxDistroLabel].
	caseBody := `{"Image":"alpine","labels":null,"hostconfig":null}`
	if code := doReqCT(http.MethodPost, "/containers/create", "application/json", caseBody); code != http.StatusCreated {
		t.Fatalf("expected 201 on lowercase null keys, got %d", code)
	}
	mu.Lock()
	rawCopy := append([]byte(nil), lastCreateRaw...)
	mu.Unlock()
	if _, err := decodeStrictObject(rawCopy); err != nil {
		t.Fatalf("rewritten JSON produced duplicate case-colliding keys: %v (%s)", err, string(rawCopy))
	}

	anonVolBody := `{"Image":"alpine","HostConfig":{"Mounts":[{"Type":"volume","Target":"/cache"}]}}`
	if code := doReqCT(http.MethodPost, "/containers/create", "application/json", anonVolBody); code != http.StatusCreated {
		t.Fatalf("expected 201 on anonymous volume mount, got %d", code)
	}
	mu.Lock()
	anonRaw := string(lastCreateRaw)
	mu.Unlock()
	if !strings.Contains(anonRaw, `"com.wsl-agent-sandbox.distro":"`+distro+`"`) || !strings.Contains(anonRaw, `"VolumeOptions"`) {
		t.Fatalf("expected anonymous volume mount to receive sandbox label in VolumeOptions: %s", anonRaw)
	}

	// 4. ?filters=null does not panic and returns 200.
	if code := doReqCT(http.MethodGet, "/containers/json?filters=null", "", ""); code != http.StatusOK {
		t.Fatalf("expected 200 on ?filters=null, got %d", code)
	}

	// 5. Host container named "create" cannot be deleted or started via reserved-segment skip.
	if code := doReqCT(http.MethodDelete, "/containers/create", "", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on DELETE /containers/create (host container named 'create'), got %d", code)
	}
	if code := doReqCT(http.MethodPost, "/containers/create/start", "", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on POST /containers/create/start, got %d", code)
	}

	// 6. GET /system/df and GET /networks/bridge are blocked (403); connect/disconnect on bridge checks container ownership.
	if code := doReqCT(http.MethodGet, "/system/df", "", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on GET /system/df under DistroName isolation, got %d", code)
	}
	if code := doReqCT(http.MethodGet, "/networks/bridge", "", ""); code != http.StatusForbidden {
		t.Fatalf("expected 403 on GET /networks/bridge, got %d", code)
	}
	if code := doReqCT(http.MethodPost, "/networks/bridge/disconnect", "application/json", `{"Container":"host_c"}`); code != http.StatusForbidden {
		t.Fatalf("expected 403 disconnecting host_c from bridge, got %d", code)
	}
	if code := doReqCT(http.MethodPost, "/networks/bridge/disconnect", "application/json", `{"Container":"sandbox_c"}`); code != http.StatusOK {
		t.Fatalf("expected 200 disconnecting sandbox_c from bridge, got %d", code)
	}

	// 7. Exec inspection fallback handles proxy restarts cleanly while blocking host execs.
	if code := doReqCT(http.MethodPost, "/exec/preexisting_sandbox_exec/start", "application/json", `{}`); code != http.StatusOK {
		t.Fatalf("expected 200 on preexisting sandbox exec via /exec/{id}/json fallback, got %d", code)
	}
	if code := doReqCT(http.MethodPost, "/exec/preexisting_host_exec/start", "application/json", `{}`); code != http.StatusForbidden {
		t.Fatalf("expected 403 on preexisting host exec, got %d", code)
	}
}
