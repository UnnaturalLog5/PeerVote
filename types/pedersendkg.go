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
func (m DKGShareValidationMessage) NewEmpty() Message {
	return &AnnounceElectionMessage{}
}

// Name implements types.Message.
func (m DKGShareValidationMessage) Name() string {
	return "dkg-share"
}

// String implements types.Message.
func (m DKGShareValidationMessage) String() string {
	return fmt.Sprintf("DKG-share-validation: electionID: %s; mixnetServerID: %s; isValid: %t",
		m.ElectionID, m.MixnetServerID, m.IsShareValid)
}

// HTML implements types.Message.
func (m DKGShareValidationMessage) HTML() string {
	return m.String()
}

// ---

// NewEmpty implements types.Message.
func (m ElectionReadyMessage) NewEmpty() Message {
	return &AnnounceElectionMessage{}
}

// Name implements types.Message.
func (m ElectionReadyMessage) Name() string {
	return "election-ready"
}

// String implements types.Message.
func (m ElectionReadyMessage) String() string {
	return fmt.Sprintf("ElectionReadyMessage: electionID: %s; qualified mixnet servers: %v",
		m.ElectionID, m.QualifiedServers)
}

// HTML implements types.Message.
func (m ElectionReadyMessage) HTML() string {
	return m.String()
}
