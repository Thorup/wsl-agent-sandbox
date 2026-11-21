package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	if out, err := exec.Command("mount", "--bind", fdPath, target).CombinedOutput(); err != nil {
		return fmt.Errorf("mount --bind %s %s: %w (%s)", fdPath, target, err, strings.TrimSpace(string(out)))
	}
	if readOnly {
		if out, err := exec.Command("mount", "-o", "remount,ro,bind", target).CombinedOutput(); err != nil {
			_ = exec.Command("umount", "-l", target).Run()
			return fmt.Errorf("remount ro %s: %w (%s)", target, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (linuxBindMounter) UnmountAndRemove(target string) error {
	_ = exec.Command("mount", "--make-rprivate", target).Run()
	_ = exec.Command("umount", "-l", target).Run()
	return os.RemoveAll(target)
}

// EphemeralMountManager tracks root-owned ephemeral bind mounts created to
// eliminate TOCTOU symlink-swap races between validation and container start.
type EphemeralMountManager struct {
	mounter BindMounter
	seq     atomic.Uint64
	mu      sync.Mutex
	byID    map[string][]string
}

func NewEphemeralMountManager(m BindMounter) *EphemeralMountManager {
	if m == nil {
		m = linuxBindMounter{}
	}
	return &EphemeralMountManager{
		mounter: m,
		byID:    make(map[string][]string),
	}
}

func (m *EphemeralMountManager) NextMountName() string {
	id := m.seq.Add(1)
	return fmt.Sprintf("bind-%d", id)
}

func (m *EphemeralMountManager) Track(containerID string, targets []string) {
	if containerID == "" || len(targets) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[containerID] = append(m.byID[containerID], targets...)
}

func (m *EphemeralMountManager) CleanupTargets(targets []string) {
	for _, t := range targets {
		_ = m.mounter.UnmountAndRemove(t)
	}
}

func (m *EphemeralMountManager) CleanupContainer(containerID string) {
	if containerID == "" {
		return
	}
	m.mu.Lock()
	targets := m.byID[containerID]
	delete(m.byID, containerID)
	m.mu.Unlock()
	m.CleanupTargets(targets)
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
func openPinnedNoFollow(root, rel string) (int, bool, error) {
	flags := syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC
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
			if errors.Is(err, syscall.ENOENT) {
				// Create missing directory inside the already-pinned parent fd to match Docker's mkdir-on-bind
				// semantics while still pinning the exact inode.
				if i == len(parts)-1 {
					if mkErr := syscall.Mkdirat(curFD, part, 0o755); mkErr == nil || errors.Is(mkErr, syscall.EEXIST) {
						nextFD, err = syscall.Openat(curFD, part, flags, 0)
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
