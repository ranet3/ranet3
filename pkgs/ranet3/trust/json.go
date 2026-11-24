// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"bytes"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
)

func ReadJSON(body []byte) (Document, error) {
	// Null is not a value of any member. Optional members are omitted, not null.
	if bytes.Contains(body, []byte("null")) {
		decoder := jsontext.NewDecoder(bytes.NewReader(body))
		for {
			token, err := decoder.ReadToken()
			if err == io.EOF {
				break
			}
			if err != nil {
				return Document{}, fmt.Errorf("trust: parse JSON: %w", err)
			}
			if token.Kind() == 'n' {
				return Document{}, errors.New("trust: JSON null is not permitted")
			}
		}
	}
	var document Document
	if err := jsonv2.Unmarshal(body, &document, jsonv2.RejectUnknownMembers(true)); err != nil {
		return Document{}, fmt.Errorf("trust: parse JSON: %w", err)
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}

func RenderJSON(document Document) ([]byte, error) {
	if err := document.Validate(); err != nil {
		return nil, err
	}
	body, err := jsonv2.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("trust: render JSON: %w", err)
	}
	return body, nil
}
