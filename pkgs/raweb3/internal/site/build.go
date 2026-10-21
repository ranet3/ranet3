// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"mime"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"

	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"github.com/tdewolff/minify/v2/json"
	"github.com/tdewolff/minify/v2/svg"
)

// Tailwind compiles the site's stylesheet with the tailwind binary at Bin.
type Tailwind struct {
	Bin string
}

func (t Tailwind) compile(ctx context.Context, root string, minified bool) ([]byte, error) {
	args := []string{"--input", styleInput}
	if minified {
		args = append(args, "--minify")
	}
	cmd := exec.CommandContext(ctx, t.Bin, args...)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", t.Bin, err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}

// Build writes the site from the sources under root, with its pages in dir,
// to out, minified as it is served. out must not exist yet, so nothing of an
// earlier build survives in it.
func Build(ctx context.Context, root, dir, out string, tw Tailwind) error {
	s, err := Load(root, dir)
	if err != nil {
		return err
	}
	if err := os.Mkdir(out, dirMode); err != nil {
		return err
	}
	m := newMinifier()
	for file, page := range s.Pages() {
		var b bytes.Buffer
		if err := page.Render(ctx, &b); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		if err := writeMinified(m, filepath.Join(out, file), "text/html", b.Bytes()); err != nil {
			return err
		}
	}
	style, err := tw.compile(ctx, root, true)
	if err != nil {
		return err
	}
	if err := write(filepath.Join(out, styleOutput), style); err != nil {
		return err
	}
	static := filepath.Join(root, staticDir)
	return fs.WalkDir(os.DirFS(static), ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, err := os.ReadFile(filepath.Join(static, p))
		if err != nil {
			return err
		}
		dest := filepath.Join(out, filepath.FromSlash(p))
		if kind := mime.TypeByExtension(path.Ext(p)); kind == "image/svg+xml" {
			return writeMinified(m, dest, kind, b)
		}
		return write(dest, b)
	})
}

// newMinifier minifies as tdewolff's minify command does, keeping the html,
// head and body tags and the quotes around attribute values.
func newMinifier() *minify.M {
	m := minify.New()
	m.AddFunc("text/css", css.Minify)
	m.Add("text/html", &html.Minifier{KeepDocumentTags: true, KeepQuotes: true})
	m.AddFunc("image/svg+xml", svg.Minify)
	m.AddFuncRegexp(regexp.MustCompile(`^(application|text)/(x-)?(java|ecma)script$`), js.Minify)
	m.AddFuncRegexp(regexp.MustCompile(`[/+]json$`), json.Minify)
	return m
}

func writeMinified(m *minify.M, file, kind string, b []byte) error {
	b, err := m.Bytes(kind, b)
	if err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	return write(file, b)
}

func write(file string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), dirMode); err != nil {
		return err
	}
	return os.WriteFile(file, b, fileMode)
}
