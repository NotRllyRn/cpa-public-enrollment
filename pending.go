package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const pendingTTL = 10 * time.Minute

func pendingOwner(cookie string) string {
	sum := sha256.Sum256([]byte(cookie))
	return hex.EncodeToString(sum[:])
}
func pendingName(name string) bool {
	if !strings.HasPrefix(name, "codex-device-") || !strings.HasSuffix(name, ".json") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, "codex-device-"), ".json"), "-")
	if len(parts) != 1 && len(parts) != 2 {
		return false
	}
	for _, p := range parts {
		if len(p) != 64 {
			return false
		}
		if _, err := hex.DecodeString(p); err != nil {
			return false
		}
	}
	return true
}

// Caller holds adoption lock. Never follows links or touches CPA's inventory.
func (d *Device) cleanupPending(now time.Time, owner string) error {
	if d == nil || d.Dir == "" {
		return nil
	}
	info, err := os.Lstat(d.Dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return diagnostic("pending directory is not private or is not a directory")
	}
	entries, err := os.ReadDir(d.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !pendingName(e.Name()) {
			continue
		}
		info, err := os.Lstat(filepath.Join(d.Dir, e.Name()))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return diagnostic("pending credential is not a regular file")
		}
		owned := owner != "" && strings.HasPrefix(e.Name(), "codex-device-"+owner+"-")
		if (owner != "" && owned) || (owner == "" && !now.Before(info.ModTime().Add(pendingTTL))) {
			if err := os.Remove(filepath.Join(d.Dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}
func (a *app) cleanupPending(now time.Time) {
	if !a.adopt.TryLock() {
		return
	}
	defer a.adopt.Unlock()
	if err := a.device.cleanupPending(now, ""); err != nil {
		log.Printf("Pending cleanup failed: %s", safeReason(err))
	}
}
