// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"github.com/spf13/cobra"

	"ranet3.com/pkgs/ranet3/internal/statefile"
	"ranet3.com/pkgs/ranet3/trust"
)

func trustInitCommand() *cobra.Command {
	return trustInitWithPublish(statefile.PublishNew)
}

func trustInitWithPublish(publish func(string, []byte, fs.FileMode) error) *cobra.Command {
	var keyPath, output string
	command := &cobra.Command{
		Use:   "init <document.json>",
		Short: "Sign a new mesh trust document",
		Long:  "Create a new mesh identifier and sign the first trust snapshot to an absent file.",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveDefault
		},
		RunE: func(command *cobra.Command, args []string) error {
			if keyPath == "" {
				return errors.New("--key is required")
			}
			if output == "" {
				return errors.New("--out is required")
			}
			signer, key, err := trust.LoadAuthorityPrivateKey(keyPath)
			if err != nil {
				return err
			}
			mesh, err := trust.NewMeshID()
			if err != nil {
				return err
			}
			return signTrustDocument(command.ErrOrStderr(), args[0], output, trust.Payload{Height: 1, Mesh: mesh}, signer, key, publish, "a mesh")
		},
	}
	command.Flags().StringVar(&keyPath, "key", "", "Authority private key file")
	command.Flags().StringVar(&output, "out", "", "New signed output file")
	command.MarkFlagFilename("key")
	command.MarkFlagFilename("out")
	return command
}

func trustSignCommand() *cobra.Command {
	return trustSignWithPublish(statefile.PublishNew)
}

func trustSignWithPublish(publish func(string, []byte, fs.FileMode) error) *cobra.Command {
	var keyPath, output, previousPath string
	var source trustSource
	command := &cobra.Command{
		Use:   "sign <document.json>",
		Short: "Sign a successor trust document",
		Long:  "Verify the named parent under eligible authority keys and sign its next height to an absent file.",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return nil, cobra.ShellCompDirectiveDefault
		},
		RunE: func(command *cobra.Command, args []string) error {
			if keyPath == "" {
				return errors.New("--key is required")
			}
			if previousPath == "" {
				return errors.New("--previous is required")
			}
			if output == "" {
				return errors.New("--out is required")
			}
			if !command.Flags().Changed("authority") && !command.Flags().Changed("config") {
				return errors.New("--previous requires --authority or --config")
			}
			keys, err := source.keys(command)
			if err != nil {
				return err
			}
			parent, err := trust.ReadSignedFile(previousPath, keys)
			if err != nil {
				if errors.Is(err, trust.ErrSignature) {
					if command.Flags().Changed("authority") {
						return fmt.Errorf("%s: parent does not verify under the key given", previousPath)
					}
					return fmt.Errorf("%s: parent does not verify under the eligible keys of %s", previousPath, source.configPath)
				}
				return fmt.Errorf("%s: %w", previousPath, err)
			}
			if parent.Payload.Height == trust.MaxHeight {
				return fmt.Errorf("%s: parent is at the maximum height", previousPath)
			}
			signer, key, err := trust.LoadAuthorityPrivateKey(keyPath)
			if err != nil {
				return err
			}
			previous := parent.Digest
			payload := trust.Payload{Height: parent.Payload.Height + 1, Previous: &previous, Mesh: parent.Payload.Mesh}
			return signTrustDocument(command.ErrOrStderr(), args[0], output, payload, signer, key, publish, "signed output")
		},
	}
	source.flags(command)
	command.Flags().StringVar(&keyPath, "key", "", "Authority private key file")
	command.Flags().StringVar(&previousPath, "previous", "", "Verified parent signed file")
	command.Flags().StringVar(&output, "out", "", "New signed output file")
	command.MarkFlagFilename("key")
	command.MarkFlagFilename("previous")
	command.MarkFlagFilename("out")
	return command
}

func readAuthoredJSON(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: open authored JSON: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s: stat authored JSON: %w", path, err)
	}
	size := 4096
	if info.Size() > 0 && info.Size() <= trust.MaxJSONBytes {
		size = int(info.Size()) + 1
	}
	body := make([]byte, size)
	n := 0
	for {
		if n == len(body) {
			if n > trust.MaxJSONBytes {
				return nil, fmt.Errorf("%s: authored JSON exceeds 256 MiB", path)
			}
			larger := make([]byte, min(2*len(body), trust.MaxJSONBytes+1))
			copy(larger, body)
			body = larger
		}
		count, readErr := file.Read(body[n:])
		n += count
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("%s: read authored JSON: %w", path, readErr)
		}
	}
	if n > trust.MaxJSONBytes {
		return nil, fmt.Errorf("%s: authored JSON exceeds 256 MiB", path)
	}
	return body[:n], nil
}

func signTrustDocument(w io.Writer, input, output string, payload trust.Payload, signer crypto.Signer, key trust.AuthorityKey, publish func(string, []byte, fs.FileMode) error, outputKind string) error {
	body, err := readAuthoredJSON(input)
	if err != nil {
		return err
	}
	document, err := trust.ReadJSON(body)
	if err != nil {
		return fmt.Errorf("%s: %w", input, err)
	}
	payload.Document = document
	signed, err := trust.SignPayload(payload, signer)
	if err != nil {
		return fmt.Errorf("%s: %w", input, err)
	}
	verified, err := trust.VerifySignedFile(signed, []trust.AuthorityKey{key})
	if err != nil {
		return fmt.Errorf("%s: self-verification failed: %w", input, err)
	}
	rendered, err := trust.RenderJSON(verified.Payload.Document)
	if err != nil {
		return fmt.Errorf("%s: self-verification failed: %w", input, err)
	}
	if !bytes.Equal(rendered, body) {
		return fmt.Errorf("%s: reviewed bytes differ from the canonical render", input)
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("%s exists, refusing to replace %s", output, outputKind)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s: inspect signed output: %w", output, err)
	}
	if err := publish(output, signed, signedOutputMode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s exists, refusing to replace %s", output, outputKind)
		}
		return fmt.Errorf("%s: publish signed output: %w", output, err)
	}
	if err := trustFacts(w, verified, false, payload.Height == 1); err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "written %s (%d bytes)\n", output, len(signed))
	return err
}
