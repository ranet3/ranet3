// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"io/fs"
	"net/http"
	"strings"
)

// Handler serves the site from the sources under root, unminified. It loads and renders them again on each request, so an edit to
// a page, site.yaml or the stylesheet shows on the next reload. A templ
// component needs the server rebuilt.
func Handler(root string, tools Tools) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+styleOutput {
			style, err := tools.style(r.Context(), root, false)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			w.Write(style)
			return
		}
		s, err := Load(root)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		file := strings.TrimPrefix(r.URL.Path, "/")
		if file == "" || strings.HasSuffix(file, "/") {
			file += indexFile
		}
		// only the image asked for is drawn, as each takes a resvg run
		if image, ok := s.Images()[file]; ok {
			png, err := tools.png(r.Context(), image)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "image/png")
			w.Write(png)
			return
		}
		files, err := s.Render(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		status := http.StatusOK
		page, ok := files[file]
		fsys := s.file(file)
		switch {
		case ok:
			kind, err := mediaType(file)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", kind+"; charset=utf-8")
			w.Write(page)
			return
		case files[file+"/"+indexFile] != nil:
			// as GitHub Pages answers a directory asked for without its slash
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			return
		case fsys != nil:
			http.ServeFileFS(w, r, fsys, file)
			return
		default:
			status, page = http.StatusNotFound, files[notFoundFile]
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		w.Write(page)
	})
}

func isFile(fsys fs.FS, name string) bool {
	info, err := fs.Stat(fsys, name)
	return err == nil && info.Mode().IsRegular()
}
