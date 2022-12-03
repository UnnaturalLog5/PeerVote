package types

import "fmt"

// NewEmpty implements types.Message.
func (m StartElectionMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m StartElectionMessage) Name() string {
	return "chat"
}

// String implements types.Message.
func (m StartElectionMessage) String() string {
	return fmt.Sprintf("<%s> - Election: %s", m.ElectionID, m.Description)
}

// HTML implements types.Message.
func (m StartElectionMessage) HTML() string {
	return m.String()
}

// ---

// NewEmpty implements types.Message.
func (m VoteMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m VoteMessage) Name() string {
	return "chat"
}

// String implements types.Message.
func (m VoteMessage) String() string {
	return fmt.Sprintf("<%s> - Vote: %s", m.ElectionID, m.Vote)
}

// HTML implements types.Message.
func (m VoteMessage) HTML() string {
	return m.String()
}

// ---

// NewEmpty implements types.Message.
func (m ResultMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m ResultMessage) Name() string {
	return "chat"
}

// String implements types.Message.
func (m ResultMessage) String() string {
	return fmt.Sprintf("<%s> - Winner: %s", m.ElectionID, m.Winner)
}

// HTML implements types.Message.
func (m ResultMessage) HTML() string {
	return m.String()
}
