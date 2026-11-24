// SPDX-FileCopyrightText: 2026 Yifei Sun
// SPDX-License-Identifier: FSL-1.1-ALv2

package trust

import (
	"encoding/base64"
	"fmt"
)

// cborNode differs from Node only where JSON stores the key as base64 text.
// Endpoints retain their backing array when the two representations are converted.
type cborDocument struct {
	Nodes []cborNode `cbor:"1,keyasint"`
}

type cborNode struct {
	Name      string     `cbor:"1,keyasint"`
	Key       []byte     `cbor:"2,keyasint,omitempty"`
	Endpoints []Endpoint `cbor:"3,keyasint"`
}

func encodeDocumentCBOR(document Document) ([]byte, error) {
	wire, err := documentToWire(document)
	if err != nil {
		return nil, err
	}
	return marshalCBOR(wire)
}

func documentToWire(document Document) (cborDocument, error) {
	if err := document.Validate(); err != nil {
		return cborDocument{}, err
	}
	wire := cborDocument{Nodes: make([]cborNode, len(document.Nodes))}
	for i, node := range document.Nodes {
		wire.Nodes[i] = cborNode{Name: node.Name, Endpoints: node.Endpoints}
		if node.Key != nil {
			der, err := base64.StdEncoding.DecodeString(*node.Key)
			if err != nil {
				return cborDocument{}, fmt.Errorf("trust: decode validated node key: %w", err)
			}
			wire.Nodes[i].Key = der
		}
	}
	return wire, nil
}

func decodeDocumentCBOR(body []byte) (Document, error) {
	var wire cborDocument
	if err := unmarshalCBOR(body, &wire); err != nil {
		return Document{}, err
	}
	return documentFromWire(wire)
}

func documentFromWire(wire cborDocument) (Document, error) {
	document := Document{Nodes: make([]Node, len(wire.Nodes))}
	for i, node := range wire.Nodes {
		document.Nodes[i] = Node{Name: node.Name, Endpoints: node.Endpoints}
		if node.Key != nil {
			document.Nodes[i].Key = new(base64.StdEncoding.EncodeToString(node.Key))
		}
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	return document, nil
}
