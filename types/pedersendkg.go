package types

import "fmt"

// ---

// NewEmpty implements types.Message.
func (m DKGShareMessage) NewEmpty() Message {
	return &AnnounceElectionMessage{}
}

// Name implements types.Message.
func (m DKGShareMessage) Name() string {
	return "dkg-share"
}

// String implements types.Message.
func (m DKGShareMessage) String() string {
	return fmt.Sprintf("<%s> - DKG-share: %s", m.Share, m.X)
}

// HTML implements types.Message.
func (m DKGShareMessage) HTML() string {
	return m.String()
}

// ---

// NewEmpty implements types.Message.
func (m DKGShareValiditionMessage) NewEmpty() Message {
	return &AnnounceElectionMessage{}
}

// Name implements types.Message.
func (m DKGShareValiditionMessage) Name() string {
	return "dkg-share"
}

// String implements types.Message.
func (m DKGShareValiditionMessage) String() string {
	return fmt.Sprintf("DKG-share-validation: electionID: %s; mixnetServerID: %s; isValid: %t",
		m.ElectionID, m.MixnetServerID, m.IsShareValid)
}

// HTML implements types.Message.
func (m DKGShareValiditionMessage) HTML() string {
	return m.String()
}
