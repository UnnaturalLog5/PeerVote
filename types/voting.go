package types

import "fmt"

// NewEmpty implements types.Message.
func (m StartElectionMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m StartElectionMessage) Name() string {
	return "startelection"
}

// String implements types.Message.
func (m StartElectionMessage) String() string {
	return fmt.Sprintf("<%s> - Election: %s", m.Base.ElectionID, m.Base.Description)
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
	return "vote"
}

// String implements types.Message.
func (m VoteMessage) String() string {
	return fmt.Sprintf("<%s> - Vote: %s", m.ElectionID, m.ChoiceID)
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
	return "result"
}

// String implements types.Message.
func (m ResultMessage) String() string {
	highestCount := uint(0)
	winner := ""

	for choice, count := range m.Results {
		if count > highestCount {
			winner = choice
			highestCount = count
		}
	}

	return fmt.Sprintf("<%s> - Winner: %s", m.ElectionID, winner)
}

// HTML implements types.Message.
func (m ResultMessage) HTML() string {
	return m.String()
}

// ---

// NewEmpty implements types.Message.
func (m MixMessage) NewEmpty() Message {
	return &StartElectionMessage{}
}

// Name implements types.Message.
func (m MixMessage) Name() string {
	return "mix"
}

// String implements types.Message.
func (m MixMessage) String() string {
	return fmt.Sprintf("<%s> - MixMessage Hop %d", m.ElectionID, m.NextHop)
}

// HTML implements types.Message.
func (m MixMessage) HTML() string {
	return m.String()
}
