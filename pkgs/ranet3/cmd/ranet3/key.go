// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/internal/statefile"
)

func keyCommand() *cobra.Command {
	return keyCommandWithPublish(statefile.PublishNew)
}

func keyCommandWithPublish(publish func(string, []byte, fs.FileMode) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage authority keys",
		Long:  "Generate a private authority key and print its public key for the authority list.",
	}
	var keyType, output string
	generate := &cobra.Command{
		Use:               "generate",
		Short:             "Generate an authority key",
		Long:              "Write a new PKCS8 private key without replacing any existing file, then print its public key as base64 DER SubjectPublicKeyInfo.",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(command *cobra.Command, _ []string) error {
			if keyType == "" {
				return errors.New("--type is required: ed25519, p256 or p384")
			}
			if output == "" {
				return errors.New("--out is required")
			}
			return generateKey(command.OutOrStdout(), keyType, output, publish)
		},
	}
	generate.Flags().StringVar(&keyType, "type", "", "Authority key type")
	generate.Flags().StringVar(&output, "out", "", "New private key file")
	generate.RegisterFlagCompletionFunc("type", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return []string{"ed25519", "p256", "p384"}, cobra.ShellCompDirectiveNoFileComp
	})
	generate.MarkFlagFilename("out")
	cmd.AddCommand(generate)
	return cmd
}

func generateKey(w io.Writer, keyType, output string, publish func(string, []byte, fs.FileMode) error) error {
	var signer crypto.Signer
	switch keyType {
	case "ed25519":
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return fmt.Errorf("generate Ed25519 key: %w", err)
		}
		signer = private
	case "p256", "p384":
		curve := elliptic.P256()
		if keyType == "p384" {
			curve = elliptic.P384()
		}
		private, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return fmt.Errorf("generate %s key: %w", keyType, err)
		}
		signer = private
	default:
		return fmt.Errorf("unknown authority key type %q", keyType)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return fmt.Errorf("encode authority private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("encode authority public key: %w", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	if err := publish(output, body, 0600); err != nil {
		return fmt.Errorf("write authority private key %s: %w", output, err)
	}
	_, err = fmt.Fprintln(w, base64.StdEncoding.EncodeToString(publicDER))
	return err
}
