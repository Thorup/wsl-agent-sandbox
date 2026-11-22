package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// BindMounter abstracts kernel bind-mount operations so TOCTOU pinning can be
// unit-tested without CAP_SYS_ADMIN.
type BindMounter interface {
	BindFD(fd int, target string, isDir bool, readOnly bool) error
	UnmountAndRemove(target string) error
}

type linuxBindMounter struct{}

func (linuxBindMounter) BindFD(fd int, target string, isDir bool, readOnly bool) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	if isDir {
		if err := os.Mkdir(target, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
	} else {
		f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		_ = f.Close()
	}

	fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	if err := syscall.Mount(fdPath, target, "", syscall.MS_BIND, ""); err != nil {
		_ = os.Remove(target)
		return fmt.Errorf("syscall.Mount bind %s -> %s: %w", fdPath, target, err)
	}
	if readOnly {
		if err := syscall.Mount("", target, "", syscall.MS_BIND|syscall.MS_REMOUNT|syscall.MS_RDONLY, ""); err != nil {
			_ = linuxBindMounter{}.UnmountAndRemove(target)
			return fmt.Errorf("syscall.Mount remount ro %s: %w", target, err)
		}
	}
	return nil
}

func (linuxBindMounter) UnmountAndRemove(target string) error {
	_ = syscall.Mount("", target, "", syscall.MS_PRIVATE, "")
	if err := syscall.Unmount(target, syscall.MNT_DETACH); err != nil {
		if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOENT) {
			if err2 := syscall.Unmount(target, 0); err2 != nil && !errors.Is(err2, syscall.EINVAL) && !errors.Is(err2, syscall.ENOENT) {
				return fmt.Errorf("unmount %s failed: %w", target, err2)
			}
		}
	}
	if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// EphemeralMountManager tracks root-owned ephemeral bind mounts created to
// eliminate TOCTOU symlink-swap races between validation and container start.
type EphemeralMountManager struct {
	mounter BindMounter
	seq     atomic.Uint64
	mu      sync.Mutex
	byID    map[string][]string
	aliases map[string]string
}

func NewEphemeralMountManager(m BindMounter) *EphemeralMountManager {
	if m == nil {
		m = linuxBindMounter{}
	}
	return &EphemeralMountManager{
		mounter: m,
		byID:    make(map[string][]string),
		aliases: make(map[string]string),
	}
}

func (m *EphemeralMountManager) NextMountName() string {
	id := m.seq.Add(1)
	return fmt.Sprintf("bind-%d", id)
}

func (m *EphemeralMountManager) Track(containerID, containerName string, targets []string) {
	if containerID == "" || len(targets) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[containerID] = append(m.byID[containerID], targets...)
	cleanName := strings.TrimPrefix(strings.TrimSpace(containerName), "/")
	if cleanName != "" {
		m.aliases[cleanName] = containerID
	}
}

func (m *EphemeralMountManager) HasTracked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID) > 0
}

func (m *EphemeralMountManager) CleanupTargets(targets []string) {
	for _, t := range targets {
		_ = m.mounter.UnmountAndRemove(t)
	}
}

func (m *EphemeralMountManager) deleteLocked(id string) []string {
	targets := m.byID[id]
	delete(m.byID, id)
	for name, targetID := range m.aliases {
		if targetID == id {
			delete(m.aliases, name)
		}
	}
	return targets
}

func (m *EphemeralMountManager) CleanupContainer(ref string) {
	ref = strings.TrimPrefix(strings.TrimSpace(ref), "/")
	if ref == "" {
		return
	}
	m.mu.Lock()
	var targets []string
	if t, ok := m.byID[ref]; ok {
		targets = t
		m.deleteLocked(ref)
	} else if fullID, ok := m.aliases[ref]; ok {
		targets = m.deleteLocked(fullID)
	} else if len(ref) >= 6 {
		var matchedID string
		matches := 0
		for id := range m.byID {
			if strings.HasPrefix(id, ref) {
				matchedID = id
				matches++
			}
		}
		if matches == 1 {
			targets = m.deleteLocked(matchedID)
		}
	}
	m.mu.Unlock()
	m.CleanupTargets(targets)
}

func (m *EphemeralMountManager) CleanupAbsent(activeIDs map[string]bool) {
	m.mu.Lock()
	var staleTargets []string
	var gone []string
	for id := range m.byID {
		if !activeIDs[id] {
			gone = append(gone, id)
		}
	}
	for _, id := range gone {
		staleTargets = append(staleTargets, m.deleteLocked(id)...)
	}
	m.mu.Unlock()
	m.CleanupTargets(staleTargets)
}

// CleanupStale removes any leftover ephemeral mounts from prior proxy runs.
func (m *EphemeralMountManager) CleanupStale(root string) {
	if root == "" {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = m.mounter.UnmountAndRemove(filepath.Join(root, e.Name()))
	}
}

// openPinnedNoFollow walks from root through rel using openat(O_NOFOLLOW) so no
// symlink component can ever be traversed, returning the pinned file descriptor
// and whether it is a directory. Caller must close the returned fd.
func openPinnedNoFollow(root, rel string, allowCreate bool) (int, bool, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	curFD, err := syscall.Open(root, flags, 0)
	if err != nil {
		return -1, false, deny("allowed bind root %q is not accessible: %v", root, err)
	}

	var st syscall.Stat_t
	if err := syscall.Fstat(curFD, &st); err != nil {
		_ = syscall.Close(curFD)
		return -1, false, deny("cannot stat allowed bind root %q: %v", root, err)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		_ = syscall.Close(curFD)
		return -1, false, deny("allowed bind root %q is not a real directory", root)
	}

	if rel == "" {
		return curFD, true, nil
	}

	parts := strings.Split(rel, "/")
	for i, part := range parts {
		nextFD, err := syscall.Openat(curFD, part, flags, 0)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) {
				_ = syscall.Close(curFD)
				return -1, false, deny("symlink %q is forbidden in bind mount source", filepath.Join(root, strings.Join(parts[:i+1], "/")))
			}
			if errors.Is(err, syscall.ENOENT) && allowCreate && i == len(parts)-1 {
				var parentSt syscall.Stat_t
				hasParentSt := syscall.Fstat(curFD, &parentSt) == nil
				// Create missing leaf directory inside the already-pinned parent fd while matching
				// the parent directory's owner/group so the agent can still write into it.
				mkErr := syscall.Mkdirat(curFD, part, 0o755)
				if mkErr == nil || errors.Is(mkErr, syscall.EEXIST) {
					nextFD, err = syscall.Openat(curFD, part, flags, 0)
					if err == nil && mkErr == nil && hasParentSt {
						_ = syscall.Fchown(nextFD, int(parentSt.Uid), int(parentSt.Gid))
					}
				}
			}
			if err != nil {
				_ = syscall.Close(curFD)
				return -1, false, deny("cannot inspect bind mount path %q: %v", filepath.Join(root, strings.Join(parts[:i+1], "/")), err)
			}
		}
		_ = syscall.Close(curFD)
		curFD = nextFD

		var nst syscall.Stat_t
		if err := syscall.Fstat(curFD, &nst); err != nil {
			_ = syscall.Close(curFD)
			return -1, false, deny("cannot stat bind mount path %q: %v", filepath.Join(root, strings.Join(parts[:i+1], "/")), err)
		}
		ft := nst.Mode & syscall.S_IFMT
		if ft == syscall.S_IFLNK {
			_ = syscall.Close(curFD)
			return -1, false, deny("symlink %q is forbidden in bind mount source", filepath.Join(root, strings.Join(parts[:i+1], "/")))
		}
		if ft == syscall.S_IFSOCK || ft == syscall.S_IFBLK || ft == syscall.S_IFCHR || ft == syscall.S_IFIFO {
			_ = syscall.Close(curFD)
			return -1, false, deny("special file %q is forbidden in bind mount source", filepath.Join(root, strings.Join(parts[:i+1], "/")))
		}
		if i < len(parts)-1 && ft != syscall.S_IFDIR {
			_ = syscall.Close(curFD)
			return -1, false, deny("intermediate path component %q is not a directory", filepath.Join(root, strings.Join(parts[:i+1], "/")))
		}
		st = nst
	}

	return curFD, (st.Mode & syscall.S_IFMT) == syscall.S_IFDIR, nil
}
