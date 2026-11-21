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
	"testing"
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
