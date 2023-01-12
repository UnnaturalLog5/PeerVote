package types

import (
	"fmt"
	"time"
)

// ---

// NewEmpty implements types.Message.
func (m DKGShareMessage) NewEmpty() Message {
	return &DKGShareMessage{}
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
	return &DKGShareValidationMessage{}
}

// Name implements types.Message.
func (m DKGShareValidationMessage) Name() string {
	return "dkg-share-validation"
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
	return &ElectionReadyMessage{}
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

// ---

// NewEmpty implements types.Message.
func (m DKGRevealShareMessage) NewEmpty() Message {
	return &DKGRevealShareMessage{}
}

// Name implements types.Message.
func (m DKGRevealShareMessage) Name() string {
	return "dkg-reveal-share"
}

// String implements types.Message.
func (m DKGRevealShareMessage) String() string {
	return fmt.Sprintf("DKGRevealShareMessage: electionID: %s;  mixnet server ID: %d; complaining server ID: %d",
		m.ElectionID, m.MixnetServerID, m.ComplainingServerID)
}

// HTML implements types.Message.
func (m DKGRevealShareMessage) HTML() string {
	return m.String()
}

// ---

// NewEmpty implements types.Message.
func (m StartElectionMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m StartElectionMessage) Name() string {
	return "start-election"
}

// String implements types.Message.
func (m StartElectionMessage) String() string {
	return fmt.Sprintf("StartElectionMessage: electionID: %s;  expiration: %s",
		m.ElectionID, m.Expiration.Format(time.RFC822))
}

// HTML implements types.Message.
func (m StartElectionMessage) HTML() string {
	return m.String()
}
