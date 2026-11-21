package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// BindMapping maps an allowed Linux path prefix inside the WSL distro to the
// corresponding root-only mirror path under /mnt/wsl that docker-desktop sees.
type BindMapping struct {
	GuestPrefix  string `json:"guestPrefix"`
	DaemonPrefix string `json:"daemonPrefix"`
	ReadOnly     bool   `json:"readOnly"`
}

// Policy defines the Docker API containment rules loaded from JSON.
type Policy struct {
	Enabled       bool          `json:"enabled"`
	AllowBuildKit bool          `json:"allowBuildKit"`
	AllowCapAdd   []string      `json:"allowCapAdd"`
	DenyEndpoints []string      `json:"denyEndpoints"`
	BindMappings  []BindMapping `json:"bindMappings"`
}

var (
	apiVersionPrefixRe = regexp.MustCompile(`^/v[0-9]+\.[0-9]+(/|$)`)
	namedVolumeRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
	windowsDriveRe     = regexp.MustCompile(`^[A-Za-z]:[/\\]`)

	// Capabilities that are ALWAYS denied regardless of config.
	hardDeniedCaps = map[string]bool{
		"ALL":                true,
		"SYS_ADMIN":          true,
		"SYS_PTRACE":         true,
		"SYS_MODULE":         true,
		"SYS_RAWIO":          true,
		"SYS_BOOT":           true,
		"SYS_CHROOT":         true,
		"DAC_OVERRIDE":       true,
		"DAC_READ_SEARCH":    true,
		"NET_ADMIN":          true,
		"BPF":                true,
		"PERFMON":            true,
		"MKNOD":              true,
		"MAC_ADMIN":          true,
		"MAC_OVERRIDE":       true,
		"SYSLOG":             true,
		"AUDIT_CONTROL":      true,
		"AUDIT_WRITE":        true,
		"WAKE_ALARM":         true,
		"BLOCK_SUSPEND":      true,
		"CHECKPOINT_RESTORE": true,
	}

	allowedEndpointPrefixes = []string{
		"/_ping",
		"/version",
		"/info",
		"/events",
		"/system/df",
		"/auth",
		"/containers",
		"/images",
		"/networks",
		"/volumes",
		"/exec",
		"/commit",
		"/build",
	}

	buildKitEndpointPrefixes = []string{
		"/grpc",
		"/session",
	}
)

// PolicyError indicates a request was explicitly rejected by security policy.
type PolicyError struct {
	Reason string
}

func (e *PolicyError) Error() string {
	return "docker-policy-proxy blocked request: " + e.Reason
}

func deny(format string, args ...any) error {
	return &PolicyError{Reason: fmt.Sprintf(format, args...)}
}

// NormalizeAPIPath strips the optional /vX.YY version prefix and cleans the path.
func NormalizeAPIPath(rawPath string) string {
	if rawPath == "" {
		return "/"
	}
	cleaned := path.Clean(rawPath)
	if loc := apiVersionPrefixRe.FindStringIndex(cleaned); loc != nil {
		rest := cleaned[loc[1]:]
		if rest == "" {
			return "/"
		}
		if !strings.HasPrefix(rest, "/") {
			rest = "/" + rest
		}
		return path.Clean(rest)
	}
	return cleaned
}

// CheckEndpoint verifies that the request path and method are allowed by policy.
func (p *Policy) CheckEndpoint(method, rawPath string, query map[string][]string) error {
	if !p.Enabled {
		return deny("docker access is disabled by policy")
	}
	if strings.Contains(rawPath, "..") {
		return deny("path traversal in URL %q", rawPath)
	}
	norm := NormalizeAPIPath(rawPath)

	// Explicit denylist first.
	for _, denied := range p.DenyEndpoints {
		d := path.Clean(denied)
		if norm == d || strings.HasPrefix(norm, d+"/") {
			return deny("endpoint %q is denied by policy", norm)
		}
	}

	// BuildKit endpoints require allowBuildKit.
	for _, bk := range buildKitEndpointPrefixes {
		if norm == bk || strings.HasPrefix(norm, bk+"/") {
			if !p.AllowBuildKit {
				return deny("BuildKit endpoint %q is disabled by policy", norm)
			}
			return nil
		}
	}

	// Default-deny: must match allowed prefix list.
	allowed := false
	for _, prefix := range allowedEndpointPrefixes {
		if norm == prefix || strings.HasPrefix(norm, prefix+"/") {
			allowed = true
			break
		}
	}
	if !allowed {
		return deny("endpoint %q is not in the allowlist", norm)
	}

	// Legacy /build query-parameter checks.
	if method == http.MethodPost && norm == "/build" {
		for k, vals := range query {
			lk := strings.ToLower(k)
			for _, v := range vals {
				lv := strings.ToLower(strings.TrimSpace(v))
				if lk == "networkmode" && (lv == "host" || strings.HasPrefix(lv, "host:") || strings.HasPrefix(lv, "ns:")) {
					return deny("build networkmode %q is forbidden", v)
				}
				if lk == "securityopt" && isDangerousSecurityOpt(v) {
					return deny("build securityopt %q is forbidden", v)
				}
			}
		}
	}

	return nil
}

// ProcessJSONBody validates and optionally rewrites the JSON request body for
// security-critical endpoints. Returns (newBody, modified, err).
func (p *Policy) ProcessJSONBody(method, rawPath string, body []byte) ([]byte, bool, error) {
	if method != http.MethodPost {
		return body, false, nil
	}
	norm := NormalizeAPIPath(rawPath)

	switch {
	case norm == "/containers/create":
		return p.processContainerCreate(body)
	case strings.HasPrefix(norm, "/containers/") && strings.HasSuffix(norm, "/update"):
		return p.processContainerUpdate(body)
	case strings.HasPrefix(norm, "/containers/") && strings.HasSuffix(norm, "/exec"):
		return p.processContainerExec(body)
	case norm == "/volumes/create":
		return p.processVolumeCreate(body)
	default:
		return body, false, nil
	}
}

func decodeStrictObject(body []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(body))) == 0 {
		return map[string]any{}, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, deny("invalid JSON payload: %v", err)
	}
	if err := rejectCaseCollisions(obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// rejectCaseCollisions prevents JSON parser-differential bypasses where a client
// sends both "HostConfig" and "hostconfig" (Go's struct decoder is case-insensitive).
func rejectCaseCollisions(v any) error {
	switch tv := v.(type) {
	case map[string]any:
		seen := make(map[string]string, len(tv))
		for k, child := range tv {
			lk := strings.ToLower(k)
			if prev, exists := seen[lk]; exists {
				return deny("duplicate case-colliding JSON keys %q and %q", prev, k)
			}
			seen[lk] = k
			if err := rejectCaseCollisions(child); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range tv {
			if err := rejectCaseCollisions(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func getKeyCI(m map[string]any, name string) (string, any, bool) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return k, v, true
		}
	}
	return "", nil, false
}

func asBool(v any) (bool, bool) {
	if v == nil {
		return false, true
	}
	b, ok := v.(bool)
	return b, ok
}

func asString(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

func asStringSlice(v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func (p *Policy) processContainerCreate(body []byte) ([]byte, bool, error) {
	obj, err := decodeStrictObject(body)
	if err != nil {
		return nil, false, err
	}
	hcKey, hcRaw, hasHC := getKeyCI(obj, "HostConfig")
	if !hasHC || hcRaw == nil {
		return body, false, nil
	}
	hc, ok := hcRaw.(map[string]any)
	if !ok {
		return nil, false, deny("HostConfig must be a JSON object")
	}

	modified, err := p.validateAndRewriteHostConfig(hc)
	if err != nil {
		return nil, false, err
	}
	if !modified {
		return body, false, nil
	}
	obj[hcKey] = hc
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, fmt.Errorf("re-marshaling container create body: %w", err)
	}
	return out, true, nil
}

func (p *Policy) processContainerUpdate(body []byte) ([]byte, bool, error) {
	obj, err := decodeStrictObject(body)
	if err != nil {
		return nil, false, err
	}
	// Block device/cgroup/privileged escalations on update.
	for _, forbidden := range []string{"Devices", "DeviceCgroupRules", "DeviceRequests", "Privileged"} {
		if _, val, ok := getKeyCI(obj, forbidden); ok && !isEmptyValue(val) {
			return nil, false, deny("container update field %q is forbidden", forbidden)
		}
	}
	return body, false, nil
}

func (p *Policy) processContainerExec(body []byte) ([]byte, bool, error) {
	obj, err := decodeStrictObject(body)
	if err != nil {
		return nil, false, err
	}
	if _, val, ok := getKeyCI(obj, "Privileged"); ok {
		b, valid := asBool(val)
		if !valid {
			return nil, false, deny("exec Privileged must be a boolean")
		}
		if b {
			return nil, false, deny("privileged docker exec is forbidden")
		}
	}
	return body, false, nil
}

func (p *Policy) processVolumeCreate(body []byte) ([]byte, bool, error) {
	obj, err := decodeStrictObject(body)
	if err != nil {
		return nil, false, err
	}
	if _, drvRaw, ok := getKeyCI(obj, "Driver"); ok && drvRaw != nil {
		drv, valid := asString(drvRaw)
		if !valid {
			return nil, false, deny("volume Driver must be a string")
		}
		if drv != "" && !strings.EqualFold(drv, "local") {
			return nil, false, deny("volume driver %q is forbidden (only local is allowed)", drv)
		}
	}
	if _, optsRaw, ok := getKeyCI(obj, "DriverOpts"); ok && optsRaw != nil {
		opts, valid := optsRaw.(map[string]any)
		if !valid {
			return nil, false, deny("volume DriverOpts must be an object")
		}
		if err := checkVolumeDriverOpts(opts); err != nil {
			return nil, false, err
		}
	}
	return body, false, nil
}

func checkVolumeDriverOpts(opts map[string]any) error {
	for k := range opts {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "device" || lk == "o" || lk == "type" || lk == "addr" {
			return deny("volume driver option %q is forbidden (prevents host bind mount escape)", k)
		}
	}
	return nil
}

func (p *Policy) validateAndRewriteHostConfig(hc map[string]any) (bool, error) {
	modified := false

	// 1. Privileged
	if _, val, ok := getKeyCI(hc, "Privileged"); ok {
		b, valid := asBool(val)
		if !valid {
			return false, deny("HostConfig.Privileged must be a boolean")
		}
		if b {
			return false, deny("privileged containers are forbidden")
		}
	}

	// 2. Host namespaces (PID, IPC, UTS, Userns, Cgroupns, Network)
	for _, nsField := range []string{"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode", "NetworkMode"} {
		if _, val, ok := getKeyCI(hc, nsField); ok && val != nil {
			mode, valid := asString(val)
			if !valid {
				return false, deny("HostConfig.%s must be a string", nsField)
			}
			lm := strings.ToLower(strings.TrimSpace(mode))
			if lm == "host" || strings.HasPrefix(lm, "host:") || strings.HasPrefix(lm, "ns:") {
				return false, deny("HostConfig.%s=%q is forbidden", nsField, mode)
			}
		}
	}

	// 3. Capabilities (CapAdd)
	if _, val, ok := getKeyCI(hc, "CapAdd"); ok && val != nil {
		caps, valid := asStringSlice(val)
		if !valid {
			return false, deny("HostConfig.CapAdd must be a string array")
		}
		for _, c := range caps {
			normCap := strings.ToUpper(strings.TrimSpace(c))
			normCap = strings.TrimPrefix(normCap, "CAP_")
			if hardDeniedCaps[normCap] {
				return false, deny("capability %q is hard-denied by policy", c)
			}
			if !p.isCapAllowed(normCap) {
				return false, deny("capability %q is not in allowCapAdd", c)
			}
		}
	}

	// 4. Devices, DeviceCgroupRules, DeviceRequests, Sysctls, OomKillDisable
	for _, field := range []string{"Devices", "DeviceCgroupRules", "DeviceRequests", "Sysctls"} {
		if _, val, ok := getKeyCI(hc, field); ok && !isEmptyValue(val) {
			return false, deny("HostConfig.%s is forbidden", field)
		}
	}

	// 5. MaskedPaths / ReadonlyPaths overrides
	for _, field := range []string{"MaskedPaths", "ReadonlyPaths"} {
		if _, val, ok := getKeyCI(hc, field); ok && val != nil {
			return false, deny("overriding HostConfig.%s is forbidden", field)
		}
	}

	// 6. SecurityOpt
	if _, val, ok := getKeyCI(hc, "SecurityOpt"); ok && val != nil {
		opts, valid := asStringSlice(val)
		if !valid {
			return false, deny("HostConfig.SecurityOpt must be a string array")
		}
		for _, opt := range opts {
			if isDangerousSecurityOpt(opt) {
				return false, deny("SecurityOpt %q is forbidden", opt)
			}
		}
	}

	// 7. ExtraHosts (block host-gateway and host.docker.internal)
	if _, val, ok := getKeyCI(hc, "ExtraHosts"); ok && val != nil {
		hosts, valid := asStringSlice(val)
		if !valid {
			return false, deny("HostConfig.ExtraHosts must be a string array")
		}
		for _, h := range hosts {
			lh := strings.ToLower(strings.TrimSpace(h))
			if strings.Contains(lh, "host-gateway") || strings.Contains(lh, "host.docker.internal") {
				return false, deny("ExtraHosts entry %q is forbidden", h)
			}
		}
	}

	// 8. Binds ([]string)
	if bKey, val, ok := getKeyCI(hc, "Binds"); ok && val != nil {
		binds, valid := asStringSlice(val)
		if !valid {
			return false, deny("HostConfig.Binds must be a string array")
		}
		newBinds := make([]any, 0, len(binds))
		for _, b := range binds {
			rewritten, changed, err := p.validateAndRewriteBindSpec(b)
			if err != nil {
				return false, err
			}
			if changed {
				modified = true
			}
			newBinds = append(newBinds, rewritten)
		}
		if modified {
			hc[bKey] = newBinds
		}
	}

	// 9. Mounts ([]object)
	if mKey, val, ok := getKeyCI(hc, "Mounts"); ok && val != nil {
		arr, valid := val.([]any)
		if !valid {
			return false, deny("HostConfig.Mounts must be an array")
		}
		for i, item := range arr {
			mObj, ok := item.(map[string]any)
			if !ok {
				return false, deny("HostConfig.Mounts[%d] must be an object", i)
			}
			changed, err := p.validateAndRewriteMountObj(mObj)
			if err != nil {
				return false, err
			}
			if changed {
				modified = true
			}
		}
		if modified {
			hc[mKey] = arr
		}
	}

	return modified, nil
}

func (p *Policy) isCapAllowed(normCap string) bool {
	for _, a := range p.AllowCapAdd {
		na := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(a)), "CAP_")
		if na == normCap {
			return true
		}
	}
	return false
}

func isDangerousSecurityOpt(opt string) bool {
	lo := strings.ToLower(strings.TrimSpace(opt))
	lo = strings.ReplaceAll(lo, " ", "")
	dangerous := []string{
		"unconfined",
		"label=disable",
		"label:disable",
		"no-new-privileges=false",
		"no-new-privileges:false",
		"no-new-privileges=0",
		"no-new-privileges:0",
	}
	for _, d := range dangerous {
		if strings.Contains(lo, d) {
			return true
		}
	}
	return false
}

func isEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	switch tv := v.(type) {
	case bool:
		return !tv
	case string:
		return strings.TrimSpace(tv) == ""
	case []any:
		return len(tv) == 0
	case map[string]any:
		return len(tv) == 0
	default:
		return false
	}
}

// validateAndRewriteBindSpec parses a Docker Binds entry (source:dest[:opts]).
func (p *Policy) validateAndRewriteBindSpec(spec string) (string, bool, error) {
	if strings.TrimSpace(spec) == "" {
		return "", false, deny("empty bind specification")
	}
	// Reject Windows drive paths immediately (e.g. C:\foo:/bar or c:/foo:/bar).
	if windowsDriveRe.MatchString(spec) || strings.HasPrefix(spec, `\\`) {
		return "", false, deny("Windows host bind path %q is forbidden", spec)
	}

	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", false, deny("invalid bind specification %q", spec)
	}
	src := parts[0]
	dst := parts[1]
	opts := ""
	if len(parts) == 3 {
		opts = parts[2]
	}

	// Named Docker volume (no path separators, no dots-only).
	if !strings.ContainsAny(src, `/\`) && namedVolumeRe.MatchString(src) {
		return spec, false, nil
	}

	rewrittenSrc, forceRO, err := p.validateAndTranslateHostPath(src)
	if err != nil {
		return "", false, err
	}

	// Validate mount propagation options if present.
	newOpts, err := sanitizeBindOptions(opts, forceRO)
	if err != nil {
		return "", false, err
	}

	var rebuilt string
	if newOpts != "" {
		rebuilt = rewrittenSrc + ":" + dst + ":" + newOpts
	} else {
		rebuilt = rewrittenSrc + ":" + dst
	}
	return rebuilt, rebuilt != spec, nil
}

func sanitizeBindOptions(opts string, forceRO bool) (string, error) {
	var tokens []string
	hasRO := false
	if strings.TrimSpace(opts) != "" {
		for _, tok := range strings.Split(opts, ",") {
			t := strings.TrimSpace(tok)
			if t == "" {
				continue
			}
			lt := strings.ToLower(t)
			// Block mount propagation that could leak/affect host mounts.
			if lt == "shared" || lt == "rshared" || lt == "slave" || lt == "rslave" {
				return "", deny("bind mount propagation %q is forbidden", t)
			}
			if forceRO && lt == "rw" {
				continue
			}
			if lt == "ro" {
				hasRO = true
			}
			tokens = append(tokens, t)
		}
	}
	if forceRO && !hasRO {
		tokens = append(tokens, "ro")
	}
	return strings.Join(tokens, ","), nil
}

func (p *Policy) validateAndRewriteMountObj(m map[string]any) (bool, error) {
	_, typeRaw, _ := getKeyCI(m, "Type")
	mType, valid := asString(typeRaw)
	if !valid {
		return false, deny("Mount.Type must be a string")
	}
	lt := strings.ToLower(strings.TrimSpace(mType))
	if lt == "" {
		lt = "volume"
	}

	switch lt {
	case "tmpfs":
		return false, nil
	case "volume":
		if _, vOptsRaw, ok := getKeyCI(m, "VolumeOptions"); ok && vOptsRaw != nil {
			vOpts, ok := vOptsRaw.(map[string]any)
			if !ok {
				return false, deny("Mount.VolumeOptions must be an object")
			}
			if _, drvCfgRaw, ok := getKeyCI(vOpts, "DriverConfig"); ok && drvCfgRaw != nil {
				drvCfg, ok := drvCfgRaw.(map[string]any)
				if !ok {
					return false, deny("Mount.VolumeOptions.DriverConfig must be an object")
				}
				if _, nameRaw, ok := getKeyCI(drvCfg, "Name"); ok && nameRaw != nil {
					name, ok := asString(nameRaw)
					if !ok || (name != "" && !strings.EqualFold(name, "local")) {
						return false, deny("volume mount driver %q is forbidden", name)
					}
				}
				if _, optsRaw, ok := getKeyCI(drvCfg, "Options"); ok && optsRaw != nil {
					opts, ok := optsRaw.(map[string]any)
					if !ok {
						return false, deny("Mount.VolumeOptions.DriverConfig.Options must be an object")
					}
					if err := checkVolumeDriverOpts(opts); err != nil {
						return false, err
					}
				}
			}
		}
		return false, nil
	case "bind":
		srcKey, srcRaw, hasSrc := getKeyCI(m, "Source")
		if !hasSrc || srcRaw == nil {
			return false, deny("bind mount missing Source")
		}
		src, ok := asString(srcRaw)
		if !ok || strings.TrimSpace(src) == "" {
			return false, deny("bind mount Source must be a non-empty string")
		}
		if _, bOptsRaw, ok := getKeyCI(m, "BindOptions"); ok && bOptsRaw != nil {
			bOpts, ok := bOptsRaw.(map[string]any)
			if !ok {
				return false, deny("Mount.BindOptions must be an object")
			}
			if _, propRaw, ok := getKeyCI(bOpts, "Propagation"); ok && propRaw != nil {
				prop, ok := asString(propRaw)
				if !ok {
					return false, deny("Mount.BindOptions.Propagation must be a string")
				}
				lp := strings.ToLower(strings.TrimSpace(prop))
				if lp != "" && lp != "private" && lp != "rprivate" {
					return false, deny("bind mount propagation %q is forbidden", prop)
				}
			}
		}

		rewritten, forceRO, err := p.validateAndTranslateHostPath(src)
		if err != nil {
			return false, err
		}
		changed := false
		if rewritten != src {
			m[srcKey] = rewritten
			changed = true
		}
		if forceRO {
			roKey, roRaw, hasRO := getKeyCI(m, "ReadOnly")
			if !hasRO {
				m["ReadOnly"] = true
				changed = true
			} else {
				roVal, _ := asBool(roRaw)
				if !roVal {
					m[roKey] = true
					changed = true
				}
			}
		}
		return changed, nil
	default:
		return false, deny("mount type %q is forbidden", mType)
	}
}

// validateAndTranslateHostPath enforces strict containment on bind mount paths:
//  1. Must be an absolute POSIX path with no Windows drive/UNC prefix and no ".." segments.
//  2. Must fall under an explicitly configured BindMapping.GuestPrefix.
//  3. Walks every path component from GuestPrefix downward using os.Lstat,
//     rejecting ANY symlink (prevents both local symlink escapes and cross-VM
//     dangling symlinks targeting /run/desktop/mnt/host/c), sockets, devices, and FIFOs.
//  4. Translates GuestPrefix -> DaemonPrefix so docker-desktop accesses the root-mirrored path.
func (p *Policy) validateAndTranslateHostPath(rawSrc string) (string, bool, error) {
	if windowsDriveRe.MatchString(rawSrc) || strings.Contains(rawSrc, `\`) {
		return "", false, deny("Windows host path %q is forbidden", rawSrc)
	}
	if !strings.HasPrefix(rawSrc, "/") {
		return "", false, deny("bind mount source %q must be an absolute Linux path", rawSrc)
	}
	for _, seg := range strings.Split(rawSrc, "/") {
		if seg == ".." {
			return "", false, deny("path traversal in bind mount source %q is forbidden", rawSrc)
		}
	}

	cleaned := path.Clean(rawSrc)

	// Match longest allowed GuestPrefix first.
	var matched *BindMapping
	for i := range p.BindMappings {
		bm := &p.BindMappings[i]
		gp := path.Clean(bm.GuestPrefix)
		if cleaned == gp || strings.HasPrefix(cleaned, gp+"/") {
			if matched == nil || len(gp) > len(path.Clean(matched.GuestPrefix)) {
				matched = bm
			}
		}
	}
	if matched == nil {
		return "", false, deny("bind mount source %q is outside allowed prefixes", cleaned)
	}

	gp := path.Clean(matched.GuestPrefix)
	rel := strings.TrimPrefix(cleaned, gp)
	rel = strings.TrimPrefix(rel, "/")

	if err := verifyNoSymlinkOrSpecial(gp, rel); err != nil {
		return "", false, err
	}

	dp := path.Clean(matched.DaemonPrefix)
	if rel == "" {
		return dp, matched.ReadOnly, nil
	}
	return path.Join(dp, rel), matched.ReadOnly, nil
}

// verifyNoSymlinkOrSpecial walks from root through each component of rel using
// os.Lstat to reject symlinks, sockets, devices, and named pipes.
// If a leaf/subpath does not yet exist on disk, all existing ancestors must be
// real directories (no symlinks).
func verifyNoSymlinkOrSpecial(root, rel string) error {
	// Ensure root itself exists and is a directory (not a symlink).
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return deny("allowed bind root %q is not accessible: %v", root, err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return deny("allowed bind root %q is not a real directory", root)
	}

	if rel == "" {
		return nil
	}

	cur := root
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Non-existent subpath under verified real directory is allowed
				// (Docker may create a directory on bind), as long as no remaining
				// components can traverse out (already checked for "..").
				return nil
			}
			return deny("cannot inspect bind mount path %q: %v", cur, err)
		}
		mode := info.Mode()
		if mode&os.ModeSymlink != 0 {
			return deny("symlink %q is forbidden in bind mount source", cur)
		}
		if mode&(os.ModeSocket|os.ModeDevice|os.ModeCharDevice|os.ModeNamedPipe) != 0 {
			return deny("special file %q is forbidden in bind mount source", cur)
		}
		if i < len(parts)-1 && !info.IsDir() {
			return deny("intermediate path component %q is not a directory", cur)
		}
	}
	return nil
}
