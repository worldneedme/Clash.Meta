package outbound

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

var (
	helpersMu  sync.Mutex
	allHelpers = make(map[*helperBackedProxy]struct{})
)

func RegisterHelper(p *helperBackedProxy) {
	helpersMu.Lock()
	defer helpersMu.Unlock()
	allHelpers[p] = struct{}{}
}

func UnregisterHelper(p *helperBackedProxy) {
	helpersMu.Lock()
	defer helpersMu.Unlock()
	delete(allHelpers, p)
}

func CloseAllHelpers() {
	helpersMu.Lock()
	defer helpersMu.Unlock()

	for p := range allHelpers {
		_ = p.Close()
	}
	allHelpers = make(map[*helperBackedProxy]struct{})
}

type helperCommandBuilder func(port int, runtimeDir string) (string, []string, error)

type helperBackedProxy struct {
	*Base
	socks          *Socks5
	dialerProxy    string
	localPort      int
	runtimeDir     string
	commandBuilder helperCommandBuilder

	mu      sync.Mutex
	cmd     *exec.Cmd
	waitErr error
}

type NaiveProxyOption struct {
	BasicOption
	Name                string `proxy:"name"`
	Server              string `proxy:"server"`
	Port                int    `proxy:"port"`
	User                string `proxy:"user,omitempty"`
	UserName            string `proxy:"username,omitempty"`
	Password            string `proxy:"password,omitempty"`
	Scheme              string `proxy:"scheme,omitempty"`
	Proxy               string `proxy:"proxy,omitempty"`
	ExtraHeaders        string `proxy:"extra-headers,omitempty"`
	HostResolverRules   string `proxy:"host-resolver-rules,omitempty"`
	InsecureConcurrency int    `proxy:"insecure-concurrency,omitempty"`
	TunnelTimeout       int    `proxy:"tunnel-timeout,omitempty"`
	IdleTimeout         int    `proxy:"idle-timeout,omitempty"`
	LocalPort           int    `proxy:"local-port,omitempty"`
	HelperPath          string `proxy:"helper-path,omitempty"`
}

func NewNaiveProxy(option NaiveProxyOption) (*helperBackedProxy, error) {
	if option.Name == "" {
		return nil, errors.New("naiveproxy missing name")
	}
	if option.Proxy == "" && (option.Server == "" || option.Port == 0) {
		return nil, errors.New("naiveproxy requires proxy or server/port")
	}
	proxyURL, err := buildNaiveProxyURL(option)
	if err != nil {
		return nil, err
	}
	seed := helperSeed(
		option.Name,
		proxyURL,
		option.ExtraHeaders,
		option.HostResolverRules,
		strconv.Itoa(option.InsecureConcurrency),
		strconv.Itoa(option.TunnelTimeout),
		strconv.Itoa(option.IdleTimeout),
	)
	port, err := chooseLocalPort(seed, option.LocalPort)
	if err != nil {
		return nil, err
	}
	runtimeDir, err := makeHelperRuntimeDir(option.Name, seed)
	if err != nil {
		return nil, err
	}
	builder := func(port int, runtimeDir string) (string, []string, error) {
		exe, err := resolveHelperPath(option.HelperPath, helperBinaryName("naive"))
		if err != nil {
			return "", nil, err
		}
		args := []string{
			"--listen=socks://127.0.0.1:" + strconv.Itoa(port),
			"--proxy=" + proxyURL,
			"--log=" + filepath.Join(runtimeDir, "naive.log"),
		}
		if option.ExtraHeaders != "" {
			args = append(args, "--extra-headers="+option.ExtraHeaders)
		}
		if option.HostResolverRules != "" {
			args = append(args, "--host-resolver-rules="+option.HostResolverRules)
		}
		if option.InsecureConcurrency > 0 {
			args = append(args, "--insecure-concurrency="+strconv.Itoa(option.InsecureConcurrency))
		}
		if option.TunnelTimeout > 0 {
			args = append(args, "--tunnel-timeout="+strconv.Itoa(option.TunnelTimeout))
		}
		if option.IdleTimeout > 0 {
			args = append(args, "--idle-timeout="+strconv.Itoa(option.IdleTimeout))
		}
		return exe, args, nil
	}
	return newHelperBackedProxy(option.Name, option.Server, option.Port, C.NaiveProxy, false, option.BasicOption, port, runtimeDir, builder)
}


func newHelperBackedProxy(name, server string, remotePort int, adapterType C.AdapterType, udp bool, basic BasicOption, localPort int, runtimeDir string, builder helperCommandBuilder) (*helperBackedProxy, error) {
	socks, err := NewSocks5(Socks5Option{
		Name:   name + "-local-helper",
		Server: "127.0.0.1",
		Port:   localPort,
		UDP:    udp,
	})
	if err != nil {
		return nil, err
	}
	p := &helperBackedProxy{
		Base: NewBase(BaseOption{
			Name:         name,
			Addr:         net.JoinHostPort(server, strconv.Itoa(remotePort)),
			Type:         adapterType,
			ProviderName: basic.ProviderName,
			UDP:          udp,
			TFO:          basic.TFO,
			MPTCP:        basic.MPTCP,
			Interface:    basic.Interface,
			RoutingMark:  basic.RoutingMark,
			Prefer:       basic.IPVersion,
		}),
		socks:          socks,
		dialerProxy:    basic.DialerProxy,
		localPort:      localPort,
		runtimeDir:     runtimeDir,
		commandBuilder: builder,
	}
	RegisterHelper(p)
	return p, nil
}

func (p *helperBackedProxy) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	if err := p.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return p.socks.DialContext(ctx, metadata)
}

func (p *helperBackedProxy) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !p.SupportUDP() {
		return nil, C.ErrNotSupport
	}
	if err := p.ensureStarted(ctx); err != nil {
		return nil, err
	}
	return p.socks.ListenPacketContext(ctx, metadata)
}

func (p *helperBackedProxy) ProxyInfo() C.ProxyInfo {
	info := p.Base.ProxyInfo()
	info.DialerProxy = p.dialerProxy
	return info
}

func (p *helperBackedProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
	}
	p.cmd = nil
	p.waitErr = nil
	UnregisterHelper(p)
	return nil
}

func (p *helperBackedProxy) ensureStarted(ctx context.Context) error {
	if p.hasRunningCommand() {
		if err := p.waitUntilReady(ctx, 1*time.Millisecond); err == nil {
			return nil
		}
	}
	p.mu.Lock()
	if p.commandRunningLocked() {
		p.mu.Unlock()
		if err := p.waitUntilReady(ctx, 5*time.Second); err != nil {
			_ = p.Close()
			return fmt.Errorf("%s helper not ready: %w", p.Name(), err)
		}
		return nil
	}
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
		p.cmd = nil
		p.waitErr = nil
	}
	if err := os.MkdirAll(p.runtimeDir, 0700); err != nil {
		p.mu.Unlock()
		return err
	}
	exe, args, err := p.commandBuilder(p.localPort, p.runtimeDir)
	if err != nil {
		p.mu.Unlock()
		return err
	}
	cmd := exec.CommandContext(context.Background(), exe, args...)
	cmd.Dir = filepath.Dir(exe)
	setHideWindow(cmd)
	logFile, err := os.OpenFile(filepath.Join(p.runtimeDir, "helper-process.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err = cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		p.mu.Unlock()
		return err
	}
	p.cmd = cmd
	p.waitErr = nil
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.waitErr = err
		p.mu.Unlock()
		if logFile != nil {
			_ = logFile.Close()
		}
	}()
	p.mu.Unlock()
	if err = p.waitUntilReady(ctx, 5*time.Second); err != nil {
		_ = p.Close()
		return fmt.Errorf("%s helper not ready: %w", p.Name(), err)
	}
	return nil
}

func (p *helperBackedProxy) hasRunningCommand() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.commandRunningLocked()
}

func (p *helperBackedProxy) commandRunningLocked() bool {
	if p.cmd == nil || p.cmd.Process == nil || p.waitErr != nil {
		return false
	}
	if p.cmd.ProcessState != nil {
		return false
	}
	err := probeLocalPort(p.localPort)
	return err == nil
}

func probeLocalPort(port int) error {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 200*time.Millisecond)
	if err != nil {
		return err
	}
	_ = conn.Close()
	return nil
}

func (p *helperBackedProxy) waitUntilReady(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p.localPort)), 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		p.mu.Lock()
		waitErr := p.waitErr
		p.mu.Unlock()
		if waitErr != nil {
			return waitErr
		}
		if time.Now().After(deadline) {
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func chooseLocalPort(seed string, port int) (int, error) {
	if port > 0 {
		return port, nil
	}
	sum := sha1.Sum([]byte(seed))
	hashValue := int(sum[0])<<8 | int(sum[1])
	return 20000 + hashValue%30000, nil
}

func makeHelperRuntimeDir(name, seed string) (string, error) {
	sum := sha1.Sum([]byte(seed))
	if runtime.GOOS == "android" {
		return filepath.Join(C.Path.HomeDir(), "protocol-helpers", "runtime", safeFilePart(name)+"-"+hex.EncodeToString(sum[:])[:8]), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "protocol-helpers", "runtime", safeFilePart(name)+"-"+hex.EncodeToString(sum[:])[:8]), nil
}

func helperSeed(parts ...string) string {
	return strings.Join(parts, "\x00")
}

func resolveHelperPath(configured string, names ...string) (string, error) {
	if configured != "" {
		if _, err := os.Stat(configured); err == nil {
			return configured, nil
		}
		return "", fmt.Errorf("helper not found: %s", configured)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	base := filepath.Dir(exe)
	dirs := []string{}

	// Android 上优先从系统注入的 nativeLibraryDir 环境变量查找
	// 这个值由 Flutter/Android 层在启动时通过环境变量传入
	if nativeLibDir := os.Getenv("NATIVE_LIBRARY_DIR"); nativeLibDir != "" {
		dirs = append(dirs, nativeLibDir)
	}

	// Android 兜底：通过 /proc/self/maps 自发现 native library 目录
	if runtime.GOOS == "android" {
		if dir := androidNativeLibraryDir(); dir != "" {
			dirs = append(dirs, dir)
		}
	}

	// 原有路径保持不变
	dirs = append(dirs,
		filepath.Join(base, "protocol-helpers"),
		filepath.Join(base, "data", "protocol-helpers"),
		base,
	)
	for _, dir := range dirs {
		for _, name := range names {
			candidate := filepath.Join(dir, name)
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("helper executable not found: %s", strings.Join(names, ", "))
}

func buildNaiveProxyURL(option NaiveProxyOption) (string, error) {
	if option.Proxy != "" {
		return option.Proxy, nil
	}
	scheme := defaultString(option.Scheme, "https")
	u := &url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
	}
	username := option.UserName
	if username == "" {
		username = option.User
	}
	if username != "" {
		u.User = url.UserPassword(username, option.Password)
	} else if option.Password != "" {
		u.User = url.UserPassword("", option.Password)
	}
	return u.String(), nil
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func safeFilePart(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "proxy"
	}
	return b.String()
}

// helperBinaryName returns the platform-appropriate binary filename.
// On Windows it appends ".exe"; on all other platforms (Android, Linux, macOS) it returns the name as-is.
func helperBinaryName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}
	if runtime.GOOS == "android" && base == "naive" {
		return "libnaive.so"
	}
	return base
}

func androidNativeLibraryDir() string {
	data, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "libplugin.so") ||
			strings.Contains(line, "libclash.so") ||
			strings.Contains(line, "libgojni.so") {
			fields := strings.Fields(line)
			if len(fields) >= 6 && strings.HasPrefix(fields[len(fields)-1], "/") {
				return filepath.Dir(fields[len(fields)-1])
			}
		}
	}
	return ""
}
