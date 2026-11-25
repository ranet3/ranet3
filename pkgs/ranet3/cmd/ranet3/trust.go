// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/internal/config"
	"ranet3.com/pkgs/ranet3/trust"
)

func trustCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "trust",
		Short: "Manage signed trust documents",
		Long:  "Sign, inspect and verify trust documents under selected authority keys.",
	}
	command.AddCommand(trustShowCommand())
	return command
}

type trustSource struct {
	authorities []string
	configPath  string
}

func (source *trustSource) flags(command *cobra.Command) {
	command.Flags().StringArrayVar(&source.authorities, "authority", nil, "Authority public key as base64 DER SPKI")
	command.Flags().StringVar(&source.configPath, "config", "", "Configuration holding eligible authority keys")
	command.MarkFlagFilename("config")
	command.RegisterFlagCompletionFunc("authority", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return nil, cobra.ShellCompDirectiveNoFileComp
	})
}

func (source *trustSource) keys(command *cobra.Command) ([]trust.AuthorityKey, error) {
	flags := command.Flags()
	explicit, configured := flags.Changed("authority"), flags.Changed("config")
	if !explicit && !configured {
		return nil, errors.New("no authority key: supply --authority or --config")
	}
	var fromConfig *config.Config
	if configured {
		var err error
		fromConfig, err = config.Load(source.configPath)
		if err != nil {
			return nil, err
		}
	}
	texts := source.authorities
	if !explicit {
		texts = fromConfig.Auth.Authority
	}
	if len(texts) == 0 {
		return nil, errors.New("no authority key: supply --authority or --config")
	}
	keys := make([]trust.AuthorityKey, 0, len(texts))
	seen := make(map[string]bool, len(texts))
	for _, text := range texts {
		key, err := trust.ParseAuthorityKey(text)
		if err != nil {
			return nil, fmt.Errorf("invalid --authority key: %w", err)
		}
		if seen[string(key.DER)] {
			return nil, errors.New("duplicate authority key")
		}
		seen[string(key.DER)] = true
		keys = append(keys, key)
	}
	return keys, nil
}

func trustVerified(path string, keys []trust.AuthorityKey, verb string) (trust.Verified, error) {
	verified, err := trust.ReadSignedFile(path, keys)
	if err == nil {
		return verified, nil
	}
	if errors.Is(err, trust.ErrSignature) {
		switch verb {
		case "show":
			return trust.Verified{}, fmt.Errorf("%s: bad signature, payload not decoded", path)
		case "verify":
			return trust.Verified{}, fmt.Errorf("%s: signature does not verify under the key given", path)
		}
	}
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return trust.Verified{}, fmt.Errorf("%s: %w", path, err)
	}
	if errors.Is(err, trust.ErrNotSign1) {
		return trust.Verified{}, fmt.Errorf("%s: malformed input: not a COSE_Sign1 under tag 18", path)
	}
	return trust.Verified{}, fmt.Errorf("%s: malformed envelope", path)
}

func trustFacts(w io.Writer, verified trust.Verified, mesh, first bool) error {
	fingerprint := sha256.Sum256(verified.Key.DER)
	if _, err := fmt.Fprintf(w, "height %d\n", verified.Payload.Height); err != nil {
		return err
	}
	if !first {
		if verified.Payload.Previous == nil {
			if _, err := io.WriteString(w, "previous none\n"); err != nil {
				return err
			}
		} else if _, err := fmt.Fprintf(w, "previous %x\n", *verified.Payload.Previous); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "digest %x\nalgorithm %s\nkey SHA256:%s\n", verified.Digest, trustAlgorithm(verified.Key.Algorithm), base64.RawStdEncoding.EncodeToString(fingerprint[:])); err != nil {
		return err
	}
	if mesh {
		_, err := fmt.Fprintf(w, "mesh %s\n", verified.Payload.Mesh)
		return err
	}
	return nil
}

func trustAlgorithm(algorithm int) string {
	switch algorithm {
	case -19:
		return "Ed25519 (-19)"
	case -9:
		return "ESP256 (-9)"
	case -51:
		return "ESP384 (-51)"
	default:
		panic("unrecognized verified authority algorithm")
	}
}

func trustShowCommand() *cobra.Command {
	var source trustSource
	var mesh bool
	command := &cobra.Command{
		Use:   "show <signed file>",
		Short: "Show a verified trust document",
		Long:  "Verify a signed file under the selected authority keys and print its canonical JSON.",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveDefault
		},
		RunE: func(command *cobra.Command, args []string) error {
			keys, err := source.keys(command)
			if err != nil {
				return err
			}
			verified, err := trustVerified(args[0], keys, "show")
			if err != nil {
				return err
			}
			body, err := trust.RenderJSON(verified.Payload.Document)
			if err != nil {
				return err
			}
			if _, err := command.OutOrStdout().Write(body); err != nil {
				return err
			}
			return trustFacts(command.ErrOrStderr(), verified, mesh, false)
		},
	}
	source.flags(command)
	command.Flags().BoolVar(&mesh, "mesh", false, "Print the mesh identifier")
	return command
}
