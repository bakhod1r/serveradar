// Package updater replaces the running binary with the latest GitHub release after SHA256 verification.
// It only contacts GitHub when the operator runs `serveradar update`.
package updater

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const DefaultRepo = "bakhod1r/serveradar"

type Release struct {
	Tag    string `json:"tag_name"`
	URL    string `json:"html_url"`
	Assets []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func repo() string {
	if r := os.Getenv("SERVERADAR_REPO"); r != "" {
		return r
	}
	return DefaultRepo
}

var client = &http.Client{Timeout: 60 * time.Second}

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "serveradar-updater")
	if strings.Contains(url, "api.github.com") {
		req.Header.Set("Accept", "application/vnd.github+json")
		if t := os.Getenv("GITHUB_TOKEN"); t != "" {
			req.Header.Set("Authorization", "Bearer "+t)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

// Latest returns the newest published release.
func Latest(ctx context.Context) (*Release, error) {
	resp, err := get(ctx, "https://api.github.com/repos/"+repo()+"/releases/latest")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r Release
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Newer reports whether tag b is a higher semver than a ("dev" is always older).
func Newer(a, b string) bool {
	if a == "dev" || a == "" {
		return true
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pb[i] != pa[i] {
			return pb[i] > pa[i]
		}
	}
	return false
}

func parse(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	v, _, _ = strings.Cut(v, "-")
	for i, p := range strings.SplitN(v, ".", 3) {
		out[i], _ = strconv.Atoi(p)
	}
	return out
}

func asset(r *Release, name string) string {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.URL
		}
	}
	return ""
}

// Apply downloads the release binary for this OS/arch, verifies SHA256SUMS and atomically replaces exe.
func Apply(ctx context.Context, r *Release, exe string) error {
	name := fmt.Sprintf("serveradar-%s-%s", runtime.GOOS, runtime.GOARCH)
	binURL, sumURL := asset(r, name), asset(r, "SHA256SUMS")
	if binURL == "" {
		return fmt.Errorf("release %s has no asset %s", r.Tag, name)
	}
	if sumURL == "" {
		return errors.New("release has no SHA256SUMS; refusing unverified update")
	}
	want, err := checksum(ctx, sumURL, name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".serveradar-update-*") // same dir: atomic rename, avoids noexec /tmp
	if err != nil {
		return fmt.Errorf("cannot write to %s (run with sudo?): %w", dir, err)
	}
	defer os.Remove(tmp.Name())
	resp, err := get(ctx, binURL)
	if err != nil {
		tmp.Close()
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 200<<20))
	resp.Body.Close()
	tmp.Close()
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("checksum mismatch for %s", name)
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), exe)
}

func checksum(ctx context.Context, url, name string) (string, error) {
	resp, err := get(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == name {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("no checksum for %s", name)
}

// Executable returns the real path of the running binary.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exe)
}
