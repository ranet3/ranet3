// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

// highlighter renders a code block as goldmark does, with each run of tokens
// of one kind in a span of that kind's class, and focusable, since a block
// wider than the page scrolls and a keyboard has to reach it. A block that
// names no language renders as plain text, and one that names a language
// chroma has no lexer for fails the page.
type highlighter struct{}

func (highlighter) RegisterFuncs(r renderer.NodeRendererFuncRegisterer) {
	r.Register(ast.KindFencedCodeBlock, renderCode)
	r.Register(ast.KindCodeBlock, renderCode)
}

func renderCode(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		_, _ = w.WriteString("</code></pre>\n")
		return ast.WalkContinue, nil
	}
	var code bytes.Buffer
	for i := range node.Lines().Len() {
		line := node.Lines().At(i)
		code.Write(line.Value(source))
	}
	_, _ = w.WriteString(`<pre tabindex="0"><code`)
	var lang []byte
	if n, ok := node.(*ast.FencedCodeBlock); ok {
		lang = n.Language(source)
	}
	if lang == nil {
		_ = w.WriteByte('>')
		html.DefaultWriter.RawWrite(w, code.Bytes())
		return ast.WalkContinue, nil
	}
	lexer := lexers.Get(string(lang))
	if lexer == nil {
		return ast.WalkStop, fmt.Errorf("code block language %q has no lexer", lang)
	}
	_, _ = w.WriteString(` class="language-`)
	html.DefaultWriter.Write(w, lang)
	_, _ = w.WriteString(`">`)
	it, err := lexer.Tokenise(nil, code.String())
	if err != nil {
		return ast.WalkStop, fmt.Errorf("code block language %q: %w", lang, err)
	}
	tokens, classes := classify(lexer.Config().Name, it.Tokens())
	var run bytes.Buffer
	class := ""
	flush := func() {
		if run.Len() == 0 {
			return
		}
		if class != "" {
			_, _ = w.WriteString(`<span class="` + class + `">`)
		}
		html.DefaultWriter.RawWrite(w, run.Bytes())
		if class != "" {
			_, _ = w.WriteString("</span>")
		}
		run.Reset()
	}
	for i, t := range tokens {
		if classes[i] != class {
			flush()
			class = classes[i]
		}
		run.WriteString(t.Value)
	}
	flush()
	return ast.WalkContinue, nil
}

// classify gives each token the class of its color, after tokenClass, and
// colors what a lexer leaves as text or a bare name as nord's VS Code port
// does: the command and flags of a shell line, and the names a nix attribute
// set assigns. A shell lexer's text is split into words first.
func classify(lexer string, tokens []chroma.Token) ([]chroma.Token, []string) {
	shell := lexer == "Bash" || lexer == "Bash Session"
	if shell {
		tokens = words(tokens)
	}
	classes := make([]string, len(tokens))
	for i, t := range tokens {
		classes[i] = tokenClass(t)
	}
	switch {
	case shell:
		shellCommands(tokens, classes)
	case lexer == "Nix":
		nixKeys(tokens, classes)
	}
	return tokens, classes
}

// words splits each text token at its whitespace, so a command or a flag is a
// token of its own.
func words(tokens []chroma.Token) []chroma.Token {
	var out []chroma.Token
	for _, t := range tokens {
		if t.Type != chroma.Text {
			out = append(out, t)
			continue
		}
		for v := t.Value; v != ""; {
			space := unicode.IsSpace(rune(v[0]))
			n := strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) != space })
			if n < 0 {
				n = len(v)
			}
			out = append(out, chroma.Token{Type: chroma.Text, Value: v[:n]})
			v = v[n:]
		}
	}
	return out
}

// shellCommands colors the first word of each shell command as a function
// and a later word that starts with a dash as a keyword. A command starts a
// line, unless a backslash carries the line before on, and follows a prompt,
// an operator that joins commands, or sudo.
func shellCommands(tokens []chroma.Token, classes []string) {
	start, escaped := true, false
	for i, t := range tokens {
		v := t.Value
		if strings.TrimSpace(v) == "" {
			if strings.Contains(v, "\n") && !escaped {
				start = true
			}
			continue
		}
		escaped = t.Type == chroma.LiteralStringEscape
		switch {
		case t.Type == chroma.GenericPrompt, v == "&&", v == "||", v == "|", v == ";":
			start = true
		case start && (t.Type == chroma.Text || t.Type == chroma.NameBuiltin):
			classes[i] = "nf"
			start = v == "sudo"
		case t.Type == chroma.Text && strings.HasPrefix(v, "-"):
			classes[i] = "k"
		default:
			start = false
		}
		if strings.HasSuffix(v, "\n") && !escaped {
			start = true
		}
	}
}

// nixKeys colors the attribute path before each = as keys. A name after
// whitespace starts a new path, so only the last of "f x = " counts.
func nixKeys(tokens []chroma.Token, classes []string) {
	var path []int
	spaced := false
	for i, t := range tokens {
		switch {
		case strings.TrimSpace(t.Value) == "":
			spaced = true
			continue
		case t.Type == chroma.Name:
			if spaced {
				path = path[:0]
			}
			path = append(path, i)
		case t.Type == chroma.Operator && t.Value == ".":
		case t.Type == chroma.Operator && t.Value == "=":
			for _, j := range path {
				classes[j] = "na"
			}
			path = path[:0]
		default:
			path = path[:0]
		}
		spaced = false
	}
}

// tokenClass is the class of the color nord's syntax guide gives a token's
// kind, or where the guide says nothing the one its VS Code port gives,
// named as pygments names that kind, or "" for plain text.
func tokenClass(t chroma.Token) string {
	k := t.Type
	switch {
	// whitespace takes no color, whatever a lexer calls it
	case strings.TrimSpace(t.Value) == "":
		return ""
	case k == chroma.Error, k == chroma.GenericError, k == chroma.GenericDeleted:
		return "err"
	case k.InSubCategory(chroma.CommentPreproc), k == chroma.CommentHashbang, k == chroma.CommentSpecial:
		return "cp"
	// comments, and the prompt of a shell session, which is no part of the
	// command
	case k.InCategory(chroma.Comment), k == chroma.GenericPrompt:
		return "c"
	case k == chroma.NameDecorator:
		return "nd"
	case k == chroma.KeywordType, k == chroma.NameClass, k == chroma.NameException:
		return "kt"
	// keys and attributes, which the port colors as types, among them the
	// keys of JSON, which its lexer calls tags
	case k == chroma.NameTag, k == chroma.NameOther, k == chroma.NameAttribute, k == chroma.NameProperty:
		return "na"
	case k == chroma.NameBuiltinPseudo, k == chroma.NameConstant:
		return "k"
	case k.InSubCategory(chroma.NameFunction), k.InSubCategory(chroma.NameBuiltin):
		return "nf"
	case k.InCategory(chroma.Keyword), k.InCategory(chroma.Operator), k == chroma.NameKeyword, k == chroma.NameOperator:
		return "k"
	// the guide colors separators as keywords, and brackets apart from plain
	// text
	case k == chroma.Punctuation && strings.Trim(t.Value, ".,:;=") == "":
		return "k"
	case k == chroma.Punctuation:
		return "p"
	case k == chroma.LiteralStringEscape, k == chroma.LiteralStringRegex:
		return "se"
	case k.InSubCategory(chroma.LiteralString), k == chroma.GenericInserted:
		return "s"
	case k.InSubCategory(chroma.LiteralNumber), k == chroma.LiteralDate:
		return "m"
	}
	return ""
}
