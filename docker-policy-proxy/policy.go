package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// BindMapping maps an allowed Linux path prefix inside the WSL distro to the
// corresponding root-only mirror path under /mnt/wsl that docker-desktop sees.
type BindMapping struct {
	GuestPrefix  string `json:"guestPrefix"`
	DaemonPrefix string `json:"daemonPrefix"`
	ReadOnly     bool   `json:"readOnly"`
}

// ResourceLimits defines optional default/maximum container resource caps.
type ResourceLimits struct {
	MemoryBytes int64 `json:"memoryBytes,omitempty"`
	NanoCpus    int64 `json:"nanoCpus,omitempty"`
	PidsLimit   int64 `json:"pidsLimit,omitempty"`
}

// Policy defines the Docker API containment rules loaded from JSON.
type Policy struct {
	Enabled                   bool                   `json:"enabled"`
	AllowBuildKit             bool                   `json:"allowBuildKit"`
	AllowCapAdd               []string               `json:"allowCapAdd"`
	DenyEndpoints             []string               `json:"denyEndpoints"`
	AllowPortBindings         *bool                  `json:"allowPortBindings,omitempty"`
	ForceLoopbackPortBindings *bool                  `json:"forceLoopbackPortBindings,omitempty"`
	AllowedPublishedPorts     []int                  `json:"allowedPublishedPorts,omitempty"`
	ForceInternalNetwork      bool                   `json:"forceInternalNetwork,omitempty"`
	DefaultLimits             ResourceLimits         `json:"defaultLimits,omitempty"`
	MaxLimits                 ResourceLimits         `json:"maxLimits,omitempty"`
	AllowedRegistries         []string               `json:"allowedRegistries,omitempty"`
	BindMappings              []BindMapping          `json:"bindMappings"`
	EphemeralBindRoot         string                 `json:"ephemeralBindRoot,omitempty"`
	EphemeralDaemonRoot       string                 `json:"ephemeralDaemonRoot,omitempty"`
	bindManager               *EphemeralMountManager `json:"-"`
	networkChecker            func(string) (bool, error)
}

func (p *Policy) portBindingsAllowed() bool {
	if p.AllowPortBindings == nil {
		return true
	}
	return *p.AllowPortBindings
}

func (p *Policy) loopbackPortBindingsForced() bool {
	if p.ForceLoopbackPortBindings == nil {
		return true
	}
	return *p.ForceLoopbackPortBindings
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

	// BuildKit endpoints require allowBuildKit and must not bypass network/registry restrictions.
	for _, bk := range buildKitEndpointPrefixes {
		if norm == bk || strings.HasPrefix(norm, bk+"/") {
			if !p.AllowBuildKit {
				return deny("BuildKit endpoint %q is disabled by policy", norm)
			}
			if p.ForceInternalNetwork || len(p.AllowedRegistries) > 0 {
				return deny("BuildKit endpoint %q is disabled when docker.forceInternalNetwork or docker.allowedRegistries is active", norm)
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
		hasNetworkNone := false
		for k, vals := range query {
			lk := strings.ToLower(k)
			for _, v := range vals {
				lv := strings.ToLower(strings.TrimSpace(v))
				if lk == "networkmode" {
					if lv == "host" || strings.HasPrefix(lv, "host:") || strings.HasPrefix(lv, "ns:") {
						return deny("build networkmode %q is forbidden", v)
					}
					if lv == "none" {
						hasNetworkNone = true
					} else if p.ForceInternalNetwork {
						return deny("build networkmode %q is forbidden when docker.forceInternalNetwork is active (must be \"none\")", v)
					}
				}
				if lk == "securityopt" && isDangerousSecurityOpt(v) {
					return deny("build securityopt %q is forbidden", v)
				}
				if len(p.AllowedRegistries) > 0 && lk == "from" {
					if trimmed := strings.TrimSpace(v); trimmed != "" {
						if err := p.checkImageRegistry(trimmed); err != nil {
							return err
						}
					}
				}
			}
		}
		if p.ForceInternalNetwork && !hasNetworkNone {
			return deny("POST /build requires networkmode=none when docker.forceInternalNetwork is active")
		}
	}

	// Image pull / import registry allowlist on POST /images/create and POST /images/load
	if len(p.AllowedRegistries) > 0 && method == http.MethodPost {
		if norm == "/images/load" {
			return deny("endpoint %q is forbidden when docker.allowedRegistries is configured", norm)
		}
		if norm == "/images/create" {
			for k, vals := range query {
				if strings.EqualFold(k, "fromSrc") {
					for _, v := range vals {
						if strings.TrimSpace(v) != "" {
							return deny("image import fromSrc %q is forbidden when docker.allowedRegistries is configured", v)
						}
					}
				}
				if strings.EqualFold(k, "fromImage") {
					for _, v := range vals {
						if trimmed := strings.TrimSpace(v); trimmed != "" {
							if err := p.checkImageRegistry(trimmed); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// ProcessJSONBody validates and optionally rewrites the JSON request body for
// security-critical endpoints. Returns (newBody, modified, err).
func (p *Policy) ProcessJSONBody(method, rawPath string, body []byte) ([]byte, bool, error) {
	newBody, modified, _, err := p.ProcessJSONBodyWithMounts(method, rawPath, body)
	return newBody, modified, err
}

// ProcessJSONBodyWithMounts validates and rewrites the JSON body, also returning
// any ephemeral host bind-mount paths created for TOCTOU mitigation.
func (p *Policy) ProcessJSONBodyWithMounts(method, rawPath string, body []byte) ([]byte, bool, []string, error) {
	if method != http.MethodPost {
		return body, false, nil, nil
	}
	norm := NormalizeAPIPath(rawPath)

	switch {
	case norm == "/containers/create":
		return p.processContainerCreate(body)
	case strings.HasPrefix(norm, "/containers/") && strings.HasSuffix(norm, "/update"):
		b, m, err := p.processContainerUpdate(body)
		return b, m, nil, err
	case strings.HasPrefix(norm, "/containers/") && strings.HasSuffix(norm, "/exec"):
		b, m, err := p.processContainerExec(body)
		return b, m, nil, err
	case norm == "/volumes/create":
		b, m, err := p.processVolumeCreate(body)
		return b, m, nil, err
	case norm == "/networks/create":
		b, m, err := p.processNetworkCreate(body)
		return b, m, nil, err
	case strings.HasPrefix(norm, "/networks/") && strings.HasSuffix(norm, "/connect"):
		b, m, err := p.processNetworkConnect(norm, body)
		return b, m, nil, err
	default:
		return body, false, nil, nil
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

func (p *Policy) validateNetworkTarget(target string) error {
	lt := strings.ToLower(strings.TrimSpace(target))
	if lt == "none" {
		return nil
	}
	if lt == "" || lt == "default" || lt == "bridge" || lt == "host" ||
		strings.HasPrefix(lt, "host:") || strings.HasPrefix(lt, "ns:") || strings.HasPrefix(lt, "container:") {
		return deny("network %q is forbidden when forceInternalNetwork is enabled", target)
	}
	if p.networkChecker == nil {
		return deny("network %q cannot be verified as internal when forceInternalNetwork is enabled", target)
	}
	internal, err := p.networkChecker(target)
	if err != nil {
		return deny("failed verifying network %q internal status: %v", target, err)
	}
	if !internal {
		return deny("non-internal network %q is forbidden when forceInternalNetwork is enabled", target)
	}
	return nil
}

func (p *Policy) processContainerCreate(body []byte) ([]byte, bool, []string, error) {
	obj, err := decodeStrictObject(body)
	if err != nil {
		return nil, false, nil, err
	}
	if len(p.AllowedRegistries) > 0 {
		if _, imgRaw, ok := getKeyCI(obj, "Image"); ok && imgRaw != nil {
			imgStr, valid := asString(imgRaw)
			if !valid {
				return nil, false, nil, deny("Image must be a string")
			}
			if strings.TrimSpace(imgStr) != "" {
				if err := p.checkImageRegistry(imgStr); err != nil {
					return nil, false, nil, err
				}
			}
		}
	}

	hasEndpoints := false
	ncModified := false
	if ncKey, ncRaw, ok := getKeyCI(obj, "NetworkingConfig"); ok && ncRaw != nil {
		ncObj, ok := ncRaw.(map[string]any)
		if !ok {
			return nil, false, nil, deny("NetworkingConfig must be a JSON object")
		}
		if ecKey, ecRaw, ok := getKeyCI(ncObj, "EndpointsConfig"); ok && ecRaw != nil {
			ecObj, ok := ecRaw.(map[string]any)
			if !ok {
				return nil, false, nil, deny("NetworkingConfig.EndpointsConfig must be a JSON object")
			}
			for netName := range ecObj {
				trimmedNet := strings.ToLower(strings.TrimSpace(netName))
				if p.ForceInternalNetwork && (trimmedNet == "" || trimmedNet == "default") {
					// Docker CLI 29+ emits EndpointsConfig: {"default": {}} when --network is omitted;
					// strip "default" so HostConfig.NetworkMode="none" takes effect cleanly.
					delete(ecObj, netName)
					ncModified = true
					continue
				}
				hasEndpoints = true
				if p.ForceInternalNetwork {
					if err := p.validateNetworkTarget(netName); err != nil {
						return nil, false, nil, err
					}
				}
			}
			if ncModified {
				ncObj[ecKey] = ecObj
				obj[ncKey] = ncObj
			}
		}
	}

	hcKey, hcRaw, hasHC := getKeyCI(obj, "HostConfig")
	if !hasHC || hcRaw == nil {
		hc := map[string]any{}
		modified, _, err := p.applyResourceLimits(hc)
		if err != nil {
			return nil, false, nil, err
		}
		if p.ForceInternalNetwork && !hasEndpoints {
			hc["NetworkMode"] = "none"
			modified = true
		}
		if modified {
			obj["HostConfig"] = hc
			ncModified = true
		}
		if !ncModified {
			return body, false, nil, nil
		}
		out, err := json.Marshal(obj)
		if err != nil {
			return nil, false, nil, fmt.Errorf("re-marshaling container create body: %w", err)
		}
		return out, true, nil, nil
	}
	hc, ok := hcRaw.(map[string]any)
	if !ok {
		return nil, false, nil, deny("HostConfig must be a JSON object")
	}

	modified, ephemeralTargets, err := p.validateAndRewriteHostConfig(hc, hasEndpoints)
	if err != nil {
		if p.bindManager != nil && len(ephemeralTargets) > 0 {
			p.bindManager.CleanupTargets(ephemeralTargets)
		}
		return nil, false, nil, err
	}
	if !modified && !ncModified {
		return body, false, ephemeralTargets, nil
	}
	if modified {
		obj[hcKey] = hc
	}
	out, err := json.Marshal(obj)
	if err != nil {
		if p.bindManager != nil && len(ephemeralTargets) > 0 {
			p.bindManager.CleanupTargets(ephemeralTargets)
		}
		return nil, false, nil, fmt.Errorf("re-marshaling container create body: %w", err)
	}
	return out, true, ephemeralTargets, nil
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
	if err := p.validateMaxLimits(obj, true); err != nil {
		return nil, false, err
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

func (p *Policy) processNetworkConnect(normPath string, body []byte) ([]byte, bool, error) {
	if _, err := decodeStrictObject(body); err != nil {
		return nil, false, err
	}
	if !p.ForceInternalNetwork {
		return body, false, nil
	}
	netRef := strings.TrimPrefix(normPath, "/networks/")
	netRef = strings.TrimSuffix(netRef, "/connect")
	if err := p.validateNetworkTarget(netRef); err != nil {
		return nil, false, err
	}
	return body, false, nil
}

func (p *Policy) processNetworkCreate(body []byte) ([]byte, bool, error) {
	if !p.ForceInternalNetwork {
		return body, false, nil
	}
	obj, err := decodeStrictObject(body)
	if err != nil {
		return nil, false, err
	}
	_, intRaw, hasInt := getKeyCI(obj, "Internal")
	if hasInt && intRaw != nil {
		b, valid := asBool(intRaw)
		if !valid {
			return nil, false, deny("network Internal must be a boolean")
		}
		if !b {
			return nil, false, deny("non-internal Docker networks are forbidden when forceInternalNetwork is enabled")
		}
		return body, false, nil
	}
	obj["Internal"] = true
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, fmt.Errorf("re-marshaling network create body: %w", err)
	}
	return out, true, nil
}

func (p *Policy) validateAndRewritePortBindings(pbMap map[string]any) (bool, error) {
	if len(pbMap) == 0 {
		return false, nil
	}
	if !p.portBindingsAllowed() {
		return false, deny("HostConfig.PortBindings is disabled by policy")
	}
	allowedSet := make(map[int]bool, len(p.AllowedPublishedPorts))
	for _, port := range p.AllowedPublishedPorts {
		allowedSet[port] = true
	}

	modified := false
	for portProto, rawBindings := range pbMap {
		if rawBindings == nil {
			continue
		}
		arr, ok := rawBindings.([]any)
		if !ok {
			return false, deny("PortBindings[%q] must be an array", portProto)
		}
		for _, item := range arr {
			bObj, ok := item.(map[string]any)
			if !ok {
				return false, deny("PortBindings[%q] entry must be an object", portProto)
			}
			if len(allowedSet) > 0 {
				_, hpRaw, hasHP := getKeyCI(bObj, "HostPort")
				if !hasHP || hpRaw == nil {
					return false, deny("PortBindings[%q] must specify an allowlisted HostPort", portProto)
				}
				hpStr, ok := asString(hpRaw)
				if !ok {
					return false, deny("PortBindings[%q].HostPort must be a string", portProto)
				}
				hpNum, err := strconv.Atoi(strings.TrimSpace(hpStr))
				if err != nil || !allowedSet[hpNum] {
					return false, deny("published host port %q is not in docker.allowedPublishedPorts", hpStr)
				}
			}
			if p.loopbackPortBindingsForced() {
				ipKey, ipRaw, hasIP := getKeyCI(bObj, "HostIp")
				if !hasIP || ipRaw == nil {
					bObj["HostIp"] = "127.0.0.1"
					modified = true
				} else {
					ipStr, ok := asString(ipRaw)
					if !ok {
						return false, deny("PortBindings[%q].HostIp must be a string", portProto)
					}
					trimmed := strings.TrimSpace(ipStr)
					if trimmed == "" {
						bObj[ipKey] = "127.0.0.1"
						modified = true
					} else if trimmed != "127.0.0.1" && trimmed != "::1" {
						return false, deny("PortBindings HostIp %q is forbidden (must bind to 127.0.0.1)", ipStr)
					}
				}
			}
		}
	}
	return modified, nil
}

func extractImageRegistry(imageRef string) string {
	ref := strings.TrimSpace(imageRef)
	if strings.HasPrefix(strings.ToLower(ref), "sha256:") {
		return ""
	}
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}
	if ref == "" {
		return ""
	}
	firstSlash := strings.Index(ref, "/")
	if firstSlash == -1 {
		return "docker.io"
	}
	firstPart := ref[:firstSlash]
	if strings.Contains(firstPart, ".") || strings.Contains(firstPart, ":") || strings.EqualFold(firstPart, "localhost") {
		return strings.ToLower(firstPart)
	}
	return "docker.io"
}

func (p *Policy) checkImageRegistry(imageRef string) error {
	if len(p.AllowedRegistries) == 0 {
		return nil
	}
	reg := extractImageRegistry(imageRef)
	if reg == "" {
		return deny("image %q has no registry (raw digests/IDs are forbidden when docker.allowedRegistries is set)", imageRef)
	}
	for _, allowed := range p.AllowedRegistries {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if a == "" {
			continue
		}
		if a == reg {
			return nil
		}
		if a == "docker.io" && (reg == "index.docker.io" || reg == "registry-1.docker.io" || reg == "registry.hub.docker.com") {
			return nil
		}
	}
	return deny("image %q registry %q is not in docker.allowedRegistries", imageRef, reg)
}

func asInt64(v any) (int64, bool) {
	switch tv := v.(type) {
	case float64:
		if math.IsNaN(tv) || math.IsInf(tv, 0) || math.Trunc(tv) != tv {
			return 0, false
		}
		if tv < -9223372036854775808.0 || tv >= 9223372036854775808.0 {
			return 0, false
		}
		return int64(tv), true
	case int64:
		return tv, true
	case int:
		return int64(tv), true
	default:
		return 0, false
	}
}

func (p *Policy) validateCpuQuotaLimits(obj map[string]any, enforce bool) (bool, error) {
	var hasQuota bool
	var quota int64
	if _, qVal, ok := getKeyCI(obj, "CpuQuota"); ok && qVal != nil {
		q, valid := asInt64(qVal)
		if !valid {
			return false, deny("HostConfig.CpuQuota must be an integer")
		}
		if q < 0 {
			return false, deny("HostConfig.CpuQuota (%d) cannot be negative", q)
		}
		if q > 0 {
			hasQuota = true
			quota = q
		}
	}
	var period int64
	if _, pVal, ok := getKeyCI(obj, "CpuPeriod"); ok && pVal != nil {
		pr, valid := asInt64(pVal)
		if !valid {
			return false, deny("HostConfig.CpuPeriod must be an integer")
		}
		if pr < 0 {
			return false, deny("HostConfig.CpuPeriod (%d) cannot be negative", pr)
		}
		period = pr
	}
	if enforce && hasQuota && p.MaxLimits.NanoCpus > 0 {
		effPeriod := int64(100000)
		if period > 0 {
			effPeriod = period
		}
		lhs := new(big.Int).Mul(big.NewInt(quota), big.NewInt(1_000_000_000))
		rhs := new(big.Int).Mul(big.NewInt(p.MaxLimits.NanoCpus), big.NewInt(effPeriod))
		if lhs.Cmp(rhs) > 0 {
			return hasQuota, deny("HostConfig.CpuQuota (%d) / CpuPeriod (%d) exceeds maxLimits.nanoCpus (%d)", quota, effPeriod, p.MaxLimits.NanoCpus)
		}
	}
	return hasQuota, nil
}

func (p *Policy) validateMemorySwapLimits(obj map[string]any) error {
	enforceMem := p.MaxLimits.MemoryBytes > 0 || p.DefaultLimits.MemoryBytes > 0
	if !enforceMem {
		return nil
	}
	_, val, ok := getKeyCI(obj, "MemorySwap")
	if !ok || val == nil {
		return nil
	}
	swap, valid := asInt64(val)
	if !valid {
		return deny("HostConfig.MemorySwap must be an integer")
	}
	if swap < 0 {
		return deny("HostConfig.MemorySwap (%d) unlimited swap is forbidden when memory limits are enforced", swap)
	}
	if p.MaxLimits.MemoryBytes > 0 && swap > 0 {
		maxSwap := new(big.Int).Mul(big.NewInt(p.MaxLimits.MemoryBytes), big.NewInt(2))
		if big.NewInt(swap).Cmp(maxSwap) > 0 {
			return deny("HostConfig.MemorySwap (%d) exceeds 2x maxLimits.memoryBytes (%d)", swap, p.MaxLimits.MemoryBytes)
		}
	}
	return nil
}

func (p *Policy) validateMaxLimits(obj map[string]any, allowZero bool) error {
	checks := []struct {
		field string
		def   int64
		max   int64
	}{
		{"Memory", p.DefaultLimits.MemoryBytes, p.MaxLimits.MemoryBytes},
		{"NanoCpus", p.DefaultLimits.NanoCpus, p.MaxLimits.NanoCpus},
		{"PidsLimit", p.DefaultLimits.PidsLimit, p.MaxLimits.PidsLimit},
	}
	for _, c := range checks {
		if c.max <= 0 && c.def <= 0 {
			continue
		}
		if _, val, ok := getKeyCI(obj, c.field); ok && val != nil {
			n, valid := asInt64(val)
			if !valid {
				return deny("HostConfig.%s must be an integer", c.field)
			}
			if n < 0 {
				return deny("HostConfig.%s (%d) cannot be negative", c.field, n)
			}
			if c.max > 0 {
				if n == 0 && !allowZero {
					if c.field == "NanoCpus" {
						if hasQuota, _ := p.validateCpuQuotaLimits(obj, false); hasQuota {
							continue
						}
					}
					return deny("HostConfig.%s (0) exceeds maxLimits (%d)", c.field, c.max)
				}
				if n > c.max {
					return deny("HostConfig.%s (%d) exceeds maxLimits (%d)", c.field, n, c.max)
				}
			}
		}
	}
	if _, err := p.validateCpuQuotaLimits(obj, true); err != nil {
		return err
	}
	return p.validateMemorySwapLimits(obj)
}

func (p *Policy) applyResourceLimits(hc map[string]any) (bool, []string, error) {
	hasExplicitQuota, err := p.validateCpuQuotaLimits(hc, true)
	if err != nil {
		return false, nil, err
	}
	if err := p.validateMemorySwapLimits(hc); err != nil {
		return false, nil, err
	}

	modified := false
	limits := []struct {
		field string
		def   int64
		max   int64
	}{
		{"Memory", p.DefaultLimits.MemoryBytes, p.MaxLimits.MemoryBytes},
		{"NanoCpus", p.DefaultLimits.NanoCpus, p.MaxLimits.NanoCpus},
		{"PidsLimit", p.DefaultLimits.PidsLimit, p.MaxLimits.PidsLimit},
	}
	for _, l := range limits {
		eff := l.def
		if eff <= 0 {
			eff = l.max
		}
		key, val, ok := getKeyCI(hc, l.field)
		if ok && val != nil {
			n, valid := asInt64(val)
			if !valid {
				return false, nil, deny("HostConfig.%s must be an integer", l.field)
			}
			if n < 0 && (l.def > 0 || l.max > 0) {
				return false, nil, deny("HostConfig.%s (%d) cannot be negative", l.field, n)
			}
			if l.field == "NanoCpus" && hasExplicitQuota {
				if n > 0 {
					return false, nil, deny("HostConfig.NanoCpus cannot be combined with CpuQuota")
				}
				continue
			}
			if eff > 0 && n == 0 {
				hc[key] = eff
				modified = true
			}
		} else if eff > 0 {
			if l.field == "NanoCpus" && hasExplicitQuota {
				continue
			}
			hc[l.field] = eff
			modified = true
		}
	}
	if err := p.validateMaxLimits(hc, false); err != nil {
		return false, nil, err
	}
	return modified, nil, nil
}

func (p *Policy) validateAndRewriteHostConfig(hc map[string]any, hasEndpoints bool) (bool, []string, error) {
	modified := false
	var ephemeralTargets []string

	if limMod, _, err := p.applyResourceLimits(hc); err != nil {
		return false, ephemeralTargets, err
	} else if limMod {
		modified = true
	}

	// 1. Privileged
	if _, val, ok := getKeyCI(hc, "Privileged"); ok {
		b, valid := asBool(val)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.Privileged must be a boolean")
		}
		if b {
			return false, ephemeralTargets, deny("privileged containers are forbidden")
		}
	}

	// 2. Host namespaces (PID, IPC, UTS, Userns, Cgroupns, Network)
	for _, nsField := range []string{"PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode", "NetworkMode"} {
		if _, val, ok := getKeyCI(hc, nsField); ok && val != nil {
			mode, valid := asString(val)
			if !valid {
				return false, ephemeralTargets, deny("HostConfig.%s must be a string", nsField)
			}
			lm := strings.ToLower(strings.TrimSpace(mode))
			if lm == "host" || strings.HasPrefix(lm, "host:") || strings.HasPrefix(lm, "ns:") {
				return false, ephemeralTargets, deny("HostConfig.%s=%q is forbidden", nsField, mode)
			}
		}
	}

	// 2b. Force internal/isolated container networking when configured
	if p.ForceInternalNetwork {
		nmKey, nmRaw, hasNM := getKeyCI(hc, "NetworkMode")
		if !hasNM || nmRaw == nil {
			if !hasEndpoints {
				hc["NetworkMode"] = "none"
				modified = true
			}
		} else {
			mode, _ := asString(nmRaw)
			lm := strings.ToLower(strings.TrimSpace(mode))
			if lm == "" || lm == "default" {
				if !hasEndpoints {
					hc[nmKey] = "none"
					modified = true
				} else {
					return false, ephemeralTargets, deny("HostConfig.NetworkMode=%q is forbidden when forceInternalNetwork is enabled", mode)
				}
			} else if err := p.validateNetworkTarget(mode); err != nil {
				return false, ephemeralTargets, err
			}
		}
	}

	// 2c. PortBindings & PublishAllPorts policy
	if _, val, ok := getKeyCI(hc, "PublishAllPorts"); ok && val != nil {
		b, valid := asBool(val)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.PublishAllPorts must be a boolean")
		}
		if b && (!p.portBindingsAllowed() || p.loopbackPortBindingsForced() || len(p.AllowedPublishedPorts) > 0) {
			return false, ephemeralTargets, deny("HostConfig.PublishAllPorts is forbidden by policy")
		}
	}
	if pbKey, val, ok := getKeyCI(hc, "PortBindings"); ok && val != nil {
		pbMap, valid := val.(map[string]any)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.PortBindings must be an object")
		}
		pbModified, err := p.validateAndRewritePortBindings(pbMap)
		if err != nil {
			return false, ephemeralTargets, err
		}
		if pbModified {
			hc[pbKey] = pbMap
			modified = true
		}
	}

	// 3. Capabilities (CapAdd)
	if _, val, ok := getKeyCI(hc, "CapAdd"); ok && val != nil {
		caps, valid := asStringSlice(val)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.CapAdd must be a string array")
		}
		for _, c := range caps {
			normCap := strings.ToUpper(strings.TrimSpace(c))
			normCap = strings.TrimPrefix(normCap, "CAP_")
			if hardDeniedCaps[normCap] {
				return false, ephemeralTargets, deny("capability %q is hard-denied by policy", c)
			}
			if !p.isCapAllowed(normCap) {
				return false, ephemeralTargets, deny("capability %q is not in allowCapAdd", c)
			}
		}
	}

	// 4. Devices, DeviceCgroupRules, DeviceRequests, Sysctls, OomKillDisable
	for _, field := range []string{"Devices", "DeviceCgroupRules", "DeviceRequests", "Sysctls"} {
		if _, val, ok := getKeyCI(hc, field); ok && !isEmptyValue(val) {
			return false, ephemeralTargets, deny("HostConfig.%s is forbidden", field)
		}
	}

	// 5. MaskedPaths / ReadonlyPaths overrides
	for _, field := range []string{"MaskedPaths", "ReadonlyPaths"} {
		if _, val, ok := getKeyCI(hc, field); ok && val != nil {
			return false, ephemeralTargets, deny("overriding HostConfig.%s is forbidden", field)
		}
	}

	// 6. SecurityOpt
	if _, val, ok := getKeyCI(hc, "SecurityOpt"); ok && val != nil {
		opts, valid := asStringSlice(val)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.SecurityOpt must be a string array")
		}
		for _, opt := range opts {
			if isDangerousSecurityOpt(opt) {
				return false, ephemeralTargets, deny("SecurityOpt %q is forbidden", opt)
			}
		}
	}

	// 7. ExtraHosts (block host-gateway and host.docker.internal)
	if _, val, ok := getKeyCI(hc, "ExtraHosts"); ok && val != nil {
		hosts, valid := asStringSlice(val)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.ExtraHosts must be a string array")
		}
		for _, h := range hosts {
			lh := strings.ToLower(strings.TrimSpace(h))
			if strings.Contains(lh, "host-gateway") || strings.Contains(lh, "host.docker.internal") {
				return false, ephemeralTargets, deny("ExtraHosts entry %q is forbidden", h)
			}
		}
	}

	// 8. Binds ([]string)
	if bKey, val, ok := getKeyCI(hc, "Binds"); ok && val != nil {
		binds, valid := asStringSlice(val)
		if !valid {
			return false, ephemeralTargets, deny("HostConfig.Binds must be a string array")
		}
		newBinds := make([]any, 0, len(binds))
		for _, b := range binds {
			rewritten, changed, ephTarget, err := p.validateAndRewriteBindSpec(b)
			if ephTarget != "" {
				ephemeralTargets = append(ephemeralTargets, ephTarget)
			}
			if err != nil {
				return false, ephemeralTargets, err
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
			return false, ephemeralTargets, deny("HostConfig.Mounts must be an array")
		}
		for i, item := range arr {
			mObj, ok := item.(map[string]any)
			if !ok {
				return false, ephemeralTargets, deny("HostConfig.Mounts[%d] must be an object", i)
			}
			changed, ephTarget, err := p.validateAndRewriteMountObj(mObj)
			if ephTarget != "" {
				ephemeralTargets = append(ephemeralTargets, ephTarget)
			}
			if err != nil {
				return false, ephemeralTargets, err
			}
			if changed {
				modified = true
			}
		}
		if modified {
			hc[mKey] = arr
		}
	}

	return modified, ephemeralTargets, nil
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
func (p *Policy) validateAndRewriteBindSpec(spec string) (string, bool, string, error) {
	if strings.TrimSpace(spec) == "" {
		return "", false, "", deny("empty bind specification")
	}
	// Reject Windows drive paths immediately (e.g. C:\foo:/bar or c:/foo:/bar).
	if windowsDriveRe.MatchString(spec) || strings.HasPrefix(spec, `\\`) {
		return "", false, "", deny("Windows host bind path %q is forbidden", spec)
	}

	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", false, "", deny("invalid bind specification %q", spec)
	}
	src := parts[0]
	dst := parts[1]
	opts := ""
	if len(parts) == 3 {
		opts = parts[2]
	}

	// Named Docker volume (no path separators, no dots-only).
	if !strings.ContainsAny(src, `/\`) && namedVolumeRe.MatchString(src) {
		return spec, false, "", nil
	}

	rewrittenSrc, forceRO, ephTarget, err := p.validateAndPinHostPath(src)
	if err != nil {
		return "", false, ephTarget, err
	}

	// Validate mount propagation options if present.
	newOpts, err := sanitizeBindOptions(opts, forceRO)
	if err != nil {
		return "", false, ephTarget, err
	}

	var rebuilt string
	if newOpts != "" {
		rebuilt = rewrittenSrc + ":" + dst + ":" + newOpts
	} else {
		rebuilt = rewrittenSrc + ":" + dst
	}
	return rebuilt, rebuilt != spec, ephTarget, nil
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

func (p *Policy) validateAndRewriteMountObj(m map[string]any) (bool, string, error) {
	_, typeRaw, _ := getKeyCI(m, "Type")
	mType, valid := asString(typeRaw)
	if !valid {
		return false, "", deny("Mount.Type must be a string")
	}
	lt := strings.ToLower(strings.TrimSpace(mType))
	if lt == "" {
		lt = "volume"
	}

	switch lt {
	case "tmpfs":
		return false, "", nil
	case "volume":
		if _, vOptsRaw, ok := getKeyCI(m, "VolumeOptions"); ok && vOptsRaw != nil {
			vOpts, ok := vOptsRaw.(map[string]any)
			if !ok {
				return false, "", deny("Mount.VolumeOptions must be an object")
			}
			if _, drvCfgRaw, ok := getKeyCI(vOpts, "DriverConfig"); ok && drvCfgRaw != nil {
				drvCfg, ok := drvCfgRaw.(map[string]any)
				if !ok {
					return false, "", deny("Mount.VolumeOptions.DriverConfig must be an object")
				}
				if _, nameRaw, ok := getKeyCI(drvCfg, "Name"); ok && nameRaw != nil {
					name, ok := asString(nameRaw)
					if !ok || (name != "" && !strings.EqualFold(name, "local")) {
						return false, "", deny("volume mount driver %q is forbidden", name)
					}
				}
				if _, optsRaw, ok := getKeyCI(drvCfg, "Options"); ok && optsRaw != nil {
					opts, ok := optsRaw.(map[string]any)
					if !ok {
						return false, "", deny("Mount.VolumeOptions.DriverConfig.Options must be an object")
					}
					if err := checkVolumeDriverOpts(opts); err != nil {
						return false, "", err
					}
				}
			}
		}
		return false, "", nil
	case "bind":
		srcKey, srcRaw, hasSrc := getKeyCI(m, "Source")
		if !hasSrc || srcRaw == nil {
			return false, "", deny("bind mount missing Source")
		}
		src, ok := asString(srcRaw)
		if !ok || strings.TrimSpace(src) == "" {
			return false, "", deny("bind mount Source must be a non-empty string")
		}
		if _, bOptsRaw, ok := getKeyCI(m, "BindOptions"); ok && bOptsRaw != nil {
			bOpts, ok := bOptsRaw.(map[string]any)
			if !ok {
				return false, "", deny("Mount.BindOptions must be an object")
			}
			if _, propRaw, ok := getKeyCI(bOpts, "Propagation"); ok && propRaw != nil {
				prop, ok := asString(propRaw)
				if !ok {
					return false, "", deny("Mount.BindOptions.Propagation must be a string")
				}
				lp := strings.ToLower(strings.TrimSpace(prop))
				if lp != "" && lp != "private" && lp != "rprivate" {
					return false, "", deny("bind mount propagation %q is forbidden", prop)
				}
			}
		}

		rewritten, forceRO, ephTarget, err := p.validateAndPinHostPath(src)
		if err != nil {
			return false, ephTarget, err
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
		return changed, ephTarget, nil
	default:
		return false, "", deny("mount type %q is forbidden", mType)
	}
}

// validateAndTranslateHostPath enforces strict containment on bind mount paths.
func (p *Policy) validateAndTranslateHostPath(rawSrc string) (string, bool, error) {
	rewritten, forceRO, _, err := p.validateAndPinHostPath(rawSrc)
	return rewritten, forceRO, err
}

// validateAndPinHostPath walks every path component with O_NOFOLLOW and, when
// EphemeralBindRoot/EphemeralDaemonRoot are configured, bind-mounts the pinned
// kernel fd into a root-only ephemeral directory to eliminate TOCTOU races.
func (p *Policy) validateAndPinHostPath(rawSrc string) (string, bool, string, error) {
	if windowsDriveRe.MatchString(rawSrc) || strings.Contains(rawSrc, `\`) {
		return "", false, "", deny("Windows host path %q is forbidden", rawSrc)
	}
	if !strings.HasPrefix(rawSrc, "/") {
		return "", false, "", deny("bind mount source %q must be an absolute Linux path", rawSrc)
	}
	for _, seg := range strings.Split(rawSrc, "/") {
		if seg == ".." {
			return "", false, "", deny("path traversal in bind mount source %q is forbidden", rawSrc)
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
		return "", false, "", deny("bind mount source %q is outside allowed prefixes", cleaned)
	}

	gp := path.Clean(matched.GuestPrefix)
	rel := strings.TrimPrefix(cleaned, gp)
	rel = strings.TrimPrefix(rel, "/")

	if p.EphemeralBindRoot != "" && p.EphemeralDaemonRoot != "" && p.bindManager != nil {
		fd, isDir, err := openPinnedNoFollow(gp, rel, !matched.ReadOnly)
		if err != nil {
			return "", false, "", err
		}
		name := p.bindManager.NextMountName()
		ephTarget := filepath.Join(p.EphemeralBindRoot, name)
		bindErr := p.bindManager.mounter.BindFD(fd, ephTarget, isDir, matched.ReadOnly)
		_ = syscall.Close(fd)
		if bindErr != nil {
			return "", false, "", fmt.Errorf("pinning ephemeral bind mount: %w", bindErr)
		}
		return path.Join(path.Clean(p.EphemeralDaemonRoot), name), matched.ReadOnly, ephTarget, nil
	}

	if err := verifyNoSymlinkOrSpecial(gp, rel); err != nil {
		return "", false, "", err
	}

	dp := path.Clean(matched.DaemonPrefix)
	if rel == "" {
		return dp, matched.ReadOnly, "", nil
	}
	return path.Join(dp, rel), matched.ReadOnly, "", nil
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
