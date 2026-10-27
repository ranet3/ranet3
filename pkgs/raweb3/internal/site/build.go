// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/a-h/templ"
	"github.com/tdewolff/minify/v2"
	"github.com/tdewolff/minify/v2/css"
	"github.com/tdewolff/minify/v2/html"
	"github.com/tdewolff/minify/v2/js"
	"github.com/tdewolff/minify/v2/svg"
	"github.com/tdewolff/minify/v2/xml"
)

// Tools are the programs the site is built with and the font they read.
type Tools struct {
	// Tailwind compiles the stylesheet
	Tailwind string
	// Resvg turns each Open Graph image into a PNG, in the font at Font
	Resvg string
	Font  string
}

func (t Tools) style(ctx context.Context, root string, minified bool) ([]byte, error) {
	args := []string{"--input", styleInput}
	if minified {
		args = append(args, "--minify")
	}
	return run(ctx, root, nil, t.Tailwind, args...)
}

func (t Tools) png(ctx context.Context, image templ.Component) ([]byte, error) {
	if t.Font == "" {
		return nil, errors.New("no font to draw the Open Graph images in")
	}
	var svg bytes.Buffer
	if err := image.Render(ctx, &svg); err != nil {
		return nil, err
	}
	return run(ctx, "", &svg, t.Resvg, "--skip-system-fonts", "--use-font-file", t.Font, "-", "-c")
}

// run runs bin in dir with stdin and returns what it writes to stdout.
func run(ctx context.Context, dir string, stdin io.Reader, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Stdin = stdin
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := bytes.TrimSpace(stderr.Bytes()); len(msg) > 0 {
			return nil, fmt.Errorf("%s: %w: %s", bin, err, msg)
		}
		return nil, fmt.Errorf("%s: %w", bin, err)
	}
	return out, nil
}

// Build writes the site from the sources under root, with its pages in dir,
// to out, minified as it is served. out must not exist yet, so nothing of an
// earlier build survives in it, and it is made only once every file is
// ready, so a build that fails leaves none behind.
func Build(ctx context.Context, root, dir, out string, tools Tools) error {
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
		kind, err := mediaType(file)
		if err != nil {
			return err
		}
		if kind == "text/plain" {
			continue
		}
		if files[file], err = m.Bytes(kind, b); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	if files[styleOutput], err = tools.style(ctx, root, true); err != nil {
		return err
	}
	for file, image := range s.Images() {
		if files[file], err = tools.png(ctx, image); err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
	}
	for _, src := range []struct {
		dir   string
		fsys  fs.FS
		pages bool
	}{{staticDir, s.static, false}, {dir, s.files, true}} {
		err = fs.WalkDir(src.fsys, ".", func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || hidden(p) || src.pages && strings.HasSuffix(p, pageSuffix) {
				return err
			}
			if _, ok := files[p]; ok {
				return fmt.Errorf("%s/%s: the site serves another file at %s", src.dir, p, p)
			}
			b, err := fs.ReadFile(src.fsys, p)
			if err != nil {
				return err
			}
			if kind := mime.TypeByExtension(path.Ext(p)); kind == "image/svg+xml" {
				if b, err = m.Bytes(kind, b); err != nil {
					return fmt.Errorf("%s/%s: %w", src.dir, p, err)
				}
			}
			files[p] = b
			return nil
		})
		if err != nil {
			return err
		}
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
	m.AddFunc("application/xml", xml.Minify)
	m.AddFuncRegexp(regexp.MustCompile(`^(application|text)/(x-)?(java|ecma)script$`), js.Minify)
	return m
}

func write(file string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(file), dirMode); err != nil {
		return err
	}
	return os.WriteFile(file, b, fileMode)
}
