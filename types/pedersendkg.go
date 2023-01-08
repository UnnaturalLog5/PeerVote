package types

import "fmt"

// ---

// NewEmpty implements types.Message.
func (m DKGShareMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m DKGShareMessage) Name() string {
	return "dkg-share"
}

// String implements types.Message.
func (m DKGShareMessage) String() string {
	return fmt.Sprintf("<%s> - DKG-share: %s", m.share, m.X)
}

// HTML implements types.Message.
func (m DKGShareMessage) HTML() string {
	return m.String()
}
