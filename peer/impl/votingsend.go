package impl

import "go.dedis.ch/cs438/types"

func (n *node) sendAnnounceElectionMessage(electionMessage types.AnnounceElectionMessage) error {
	msg, err := marshalMessage(electionMessage)
	if err != nil {
		return err
	}

	err = n.Broadcast(msg)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) sendVoteMessage(mixnetPeer string, voteMessage types.VoteMessage) error {
	recipients := make(map[string]struct{})
	recipients[mixnetPeer] = struct{}{}

	n.sendPrivateMessage(recipients, voteMessage)

	return nil
}

func (n *node) sendResultsMessage(resultMessage types.ResultMessage) error {
	msg, err := marshalMessage(resultMessage)
	if err != nil {
		return err
	}

	err = n.Broadcast(msg)
	if err != nil {
		return err
	}

	return nil
}
