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
		if msg := bytes.TrimSpace(stderr.Bytes()); len(msg) > 0 {
			return nil, fmt.Errorf("%s: %w: %s", t.Bin, err, msg)
		}
		return nil, fmt.Errorf("%s: %w", t.Bin, err)
	}
	return out, nil
}

// Build writes the site from the sources under root, with its pages in dir,
// to out, minified as it is served. out must not exist yet, so nothing of an
// earlier build survives in it, and it is made only once every file is
// ready, so a build that fails leaves none behind.
func Build(ctx context.Context, root, dir, out string, tw Tailwind) error {
	s, err := Load(root, dir)
	if err != nil {
		return err
	}
	files, err := s.Render(ctx)
	if err != nil {
		return err
	}
	m := newMinifier()
	for file, b := range files {
		if files[file], err = m.Bytes("text/html", b); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	if files[styleOutput], err = tw.compile(ctx, root, true); err != nil {
		return err
	}
	err = fs.WalkDir(s.static, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if _, ok := files[p]; ok {
			return fmt.Errorf("%s/%s: the site serves another file at %s", staticDir, p, p)
		}
		b, err := fs.ReadFile(s.static, p)
		if err != nil {
			return err
		}
		if kind := mime.TypeByExtension(path.Ext(p)); kind == "image/svg+xml" {
			if b, err = m.Bytes(kind, b); err != nil {
				return fmt.Errorf("%s/%s: %w", staticDir, p, err)
			}
		}
		files[p] = b
		return nil
	})
	if err != nil {
		return err
	}
	if err := os.Mkdir(out, dirMode); err != nil {
		return err
	}
	for file, b := range files {
		if err := write(filepath.Join(out, filepath.FromSlash(file)), b); err != nil {
			return err
		}
	}
	return nil
}

// newMinifier minifies as tdewolff's minify command does, keeping the html,
// head and body tags and the quotes around attribute values.
func newMinifier() *minify.M {
	m := minify.New()
	m.AddFunc("text/css", css.Minify)
	m.Add("text/html", &html.Minifier{KeepDocumentTags: true, KeepQuotes: true})
	m.AddFunc("image/svg+xml", svg.Minify)
	m.AddFuncRegexp(regexp.MustCompile(`^(application|text)/(x-)?(java|ecma)script$`), js.Minify)
	return m
}

func write(file string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), dirMode); err != nil {
		return err
	}
	return os.WriteFile(file, b, fileMode)
}
