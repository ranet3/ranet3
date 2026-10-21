// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

// Command raweb3 builds the ranet3 websites from their sources, or serves
// them from the sources while they are written.
package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/raweb3/internal/site"
)

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// sources are the flags every command reads the sources through.
type sources struct {
	root     string
	pages    string
	tailwind string
}

func newRoot() *cobra.Command {
	var src sources
	root := &cobra.Command{
		Use:   "raweb3",
		Short: "Build and serve the ranet3 websites",
		Long: `The build command writes a site to a directory, as it is deployed. The
serve command renders it from the sources on each request.`,
		// main prints the one error and the usage is on --help
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	flags := root.PersistentFlags()
	flags.StringVar(&src.root, "root", defaultRoot, "Directory that holds site.yaml, static and ui")
	flags.StringVar(&src.pages, "pages", defaultPages, "Directory of the markdown pages, relative to the root")
	flags.StringVar(&src.tailwind, "tailwind", defaultTailwind, "Tailwind binary that compiles the stylesheet")
	root.MarkPersistentFlagDirname("root")
	root.MarkPersistentFlagDirname("pages")
	root.MarkPersistentFlagFilename("tailwind")
	root.AddCommand(buildCommand(&src), serveCommand(&src))
	return root
}

func buildCommand(src *sources) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Write the site to a directory",
		Long: `The directory must not exist yet, so nothing of an earlier build survives
in it. Every page, the stylesheet and the static files are minified.`,
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return site.Build(cmd.Context(), src.root, src.pages, out, site.Tailwind{Bin: src.tailwind})
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "Directory to write the site to")
	cmd.MarkFlagRequired("out")
	cmd.MarkFlagDirname("out")
	return cmd
}

func serveCommand(src *sources) *cobra.Command {
	var listen string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the site from its sources",
		Long: `The markdown pages, site.yaml and the stylesheet are read again on each
request, so an edit shows on the next reload. A change to a templ component
needs the command restarted, which templ generate --watch --cmd does.`,
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			server := &http.Server{
				Addr:              listen,
				Handler:           site.Handler(src.root, src.pages, site.Tailwind{Bin: src.tailwind}),
				ReadHeaderTimeout: readHeaderTimeout,
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Serving on http://%s\n", listen)
			return server.ListenAndServe()
		},
	}
	cmd.Flags().StringVar(&listen, "listen", defaultListen, "Address to serve on")
	cmd.RegisterFlagCompletionFunc("listen", cobra.NoFileCompletions)
	return cmd
}
