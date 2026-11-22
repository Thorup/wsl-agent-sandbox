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
