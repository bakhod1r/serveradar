package probe

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "projects", Title: "Projects & Deployments", Profiles: std, Collect: collectProjects})
}

var projectMarkers = []string{"go.mod", "package.json", "pyproject.toml", "requirements.txt", "Cargo.toml", "pom.xml",
	"build.gradle", "composer.json", "Gemfile", "mix.exs", "Dockerfile", "manage.py"}
var deployManifests = []string{"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
	"ecosystem.config.js", "Procfile", "supervisord.conf", "fly.toml", "Makefile"}

func collectProjects(c Ctx) (any, error) {
	pol := c.Policy()
	res := &inventory.Projects{}
	seen := map[string]bool{}
	for _, root := range pol.ProjectRoots {
		if root == "" || seen[root] {
			continue
		}
		if _, err := os.Stat(root); err != nil {
			continue
		}
		seen[root] = true
		res.Roots = append(res.Roots, root)
		base := strings.Count(filepath.Clean(root), string(os.PathSeparator))
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if c.Err() != nil {
				return fs.SkipAll
			}
			if err != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			name := d.Name()
			if p != root && (strings.HasPrefix(name, ".") || slices.Contains(pol.ExcludePaths, name)) {
				return fs.SkipDir
			}
			if strings.Count(p, string(os.PathSeparator))-base > pol.ProjectMaxDepth {
				return fs.SkipDir
			}
			if seen[p] && p != root {
				return fs.SkipDir
			}
			if pr := inspectProject(c, p); pr != nil {
				seen[p] = true
				res.Items = append(res.Items, *pr)
				return fs.SkipDir // don't descend into a project
			}
			return nil
		})
	}
	if c.Err() != nil {
		c.Warn("project walk stopped: timeout")
	}
	return res, nil
}

func inspectProject(c Ctx, dir string) *inventory.Project {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	pr := &inventory.Project{Path: dir}
	isGit := false
	for _, e := range ents {
		n := e.Name()
		switch {
		case n == ".git":
			isGit = true
		case slices.Contains(projectMarkers, n):
			pr.Markers = append(pr.Markers, n)
		case slices.Contains(deployManifests, n):
			pr.Manifests = append(pr.Manifests, n)
		case (n == ".env" || strings.HasPrefix(n, ".env.")) && !isEnvTemplate(n):
			pr.EnvFiles = append(pr.EnvFiles, n) // existence only; contents never read
			if fi, err := e.Info(); err == nil && fi.Mode().Perm()&0o004 != 0 {
				pr.EnvLoose = append(pr.EnvLoose, n)
			}
		}
	}
	if !isGit && len(pr.Markers) == 0 && len(pr.Manifests) == 0 {
		return nil
	}
	if isGit {
		pr.Git = gitInfo(c, dir)
	}
	return pr
}

func gitInfo(c Ctx, dir string) *inventory.Git {
	g := &inventory.Git{}
	if b, err := os.ReadFile(filepath.Join(dir, ".git", "HEAD")); err == nil {
		h := strings.TrimSpace(string(b))
		if ref, ok := strings.CutPrefix(h, "ref: "); ok {
			g.Branch = strings.TrimPrefix(ref, "refs/heads/")
			if cb, err := os.ReadFile(filepath.Join(dir, ".git", ref)); err == nil {
				g.Commit = strings.TrimSpace(string(cb))
			}
		} else {
			g.Branch, g.Commit = "(detached)", h
		}
	}
	if len(g.Commit) > 12 {
		g.Commit = g.Commit[:12]
	}
	if kv, err := os.ReadFile(filepath.Join(dir, ".git", "config")); err == nil {
		inOrigin := false
		for _, ln := range strings.Split(string(kv), "\n") {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "[") {
				inOrigin = ln == `[remote "origin"]`
			}
			if inOrigin && strings.HasPrefix(ln, "url") {
				if _, v, ok := strings.Cut(ln, "="); ok {
					g.Remote = redact.URL(strings.TrimSpace(v))
				}
			}
		}
	}
	// --no-optional-locks: status must not write .git/index
	if out, err := execx.Run(c, 5*time.Second, "git", "--no-optional-locks", "-C", dir, "status", "--porcelain", "-uno"); err == nil {
		g.Dirty = strings.TrimSpace(out) != ""
		if g.Commit == "" {
			if o, err := execx.Run(c, 3*time.Second, "git", "--no-optional-locks", "-C", dir, "rev-parse", "--short=12", "HEAD"); err == nil {
				g.Commit = strings.TrimSpace(o)
			}
		}
	}
	return g
}

func isEnvTemplate(n string) bool {
	for _, s := range []string{"example", "sample", "template", "dist"} {
		if strings.HasSuffix(n, "."+s) {
			return true
		}
	}
	return false
}
