package adminui

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const defaultDirectory = "/usr/share/anyns-admin"

func Handler() http.Handler {
	directory := strings.TrimSpace(os.Getenv("ANYNS_ADMIN_UI_DIR"))
	if directory == "" {
		directory = defaultDirectory
	}
	directory = filepath.Clean(directory)
	fileServer := http.FileServer(http.Dir(directory))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if _, err := os.Stat(filepath.Join(directory, "index.html")); err != nil {
			http.Error(w, "admin UI is not installed", http.StatusServiceUnavailable)
			return
		}

		path := filepath.Clean(filepath.FromSlash(strings.TrimPrefix(r.URL.Path, "/")))
		if path == "." {
			path = "index.html"
		}
		candidate := filepath.Join(directory, path)
		if relative, err := filepath.Rel(directory, candidate); err != nil || strings.HasPrefix(relative, "..") {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if strings.HasPrefix(r.URL.Path, "/assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			fileServer.ServeHTTP(w, r)
			return
		}

		clone := r.Clone(r.Context())
		clone.URL.Path = "/"
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, clone)
	})
}
