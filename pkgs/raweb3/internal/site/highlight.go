// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package site

import (
	"fmt"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/util"
)

// highlighter renders a fenced code block as goldmark does, with each run of
// tokens of one kind in a span of that kind's class. A block that names no
// language renders as plain text, and one that names a language chroma has no
// lexer for fails the page.
type highlighter struct{}

func (highlighter) RegisterFuncs(r renderer.NodeRendererFuncRegisterer) {
	r.Register(ast.KindFencedCodeBlock, renderFencedCode)
}

func renderFencedCode(w util.BufWriter, source []byte, node ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		_, _ = w.WriteString("</code></pre>\n")
		return ast.WalkContinue, nil
	}
	n := node.(*ast.FencedCodeBlock)
	var code strings.Builder
	for i := range n.Lines().Len() {
		line := n.Lines().At(i)
		code.Write(line.Value(source))
	}
	_, _ = w.WriteString("<pre><code")
	lang := n.Language(source)
	if lang == nil {
		_ = w.WriteByte('>')
		html.DefaultWriter.RawWrite(w, []byte(code.String()))
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
	var run strings.Builder
	class := ""
	flush := func() {
		if run.Len() == 0 {
			return
		}
		if class != "" {
			_, _ = w.WriteString(`<span class="` + class + `">`)
		}
		html.DefaultWriter.RawWrite(w, []byte(run.String()))
		if class != "" {
			_, _ = w.WriteString("</span>")
		}
		run.Reset()
	}
	for t := it(); t != chroma.EOF; t = it() {
		if c := tokenClass(t); c != class {
			flush()
			class = c
		}
		run.WriteString(t.Value)
	}
	flush()
	return ast.WalkContinue, nil
}

// tokenClass is the class of the color nord's syntax guide gives a token's
// kind, named as pygments names that kind, or "" for plain text and the
// brackets that structure it.
func tokenClass(t chroma.Token) string {
	switch k := t.Type; {
	case k == chroma.Error, k == chroma.GenericError, k == chroma.GenericDeleted:
		return "err"
	case k.InSubCategory(chroma.CommentPreproc), k == chroma.CommentHashbang, k == chroma.CommentSpecial:
		return "cp"
	case k.InCategory(chroma.Comment):
		return "c"
	case k == chroma.NameDecorator:
		return "nd"
	case k == chroma.KeywordType, k == chroma.NameClass, k == chroma.NameException:
		return "kt"
	case k == chroma.NameBuiltinPseudo:
		return "k"
	case k.InSubCategory(chroma.NameFunction), k.InSubCategory(chroma.NameBuiltin):
		return "nf"
	case k.InCategory(chroma.Keyword), k.InCategory(chroma.Operator), k == chroma.NameTag, k == chroma.NameKeyword, k == chroma.NameOperator:
		return "k"
	// the guide colors separators as keywords, and brackets as plain text
	case k == chroma.Punctuation && strings.Trim(t.Value, ".,:;=") == "":
		return "k"
	case k == chroma.LiteralStringEscape, k == chroma.LiteralStringRegex:
		return "se"
	case k.InSubCategory(chroma.LiteralString), k == chroma.GenericInserted:
		return "s"
	case k.InSubCategory(chroma.LiteralNumber), k == chroma.LiteralDate:
		return "m"
	// variables, constants, attributes and fields
	case k.InCategory(chroma.Name):
		return "nv"
	}
	return ""
}
