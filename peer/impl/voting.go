package impl

import (
	"crypto/elliptic"
	"errors"
	"math/big"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/types"
)

const (
	INITIAL_MIX_HOP = -1
)

func (n *node) AnnounceElection(title, description string, choices, mixnetServers []string, electionDuration time.Duration) (string, error) {
	// generate election id
	electionChoices := []types.Choice{}
	for i, choice := range choices {
		electionChoices = append(electionChoices, types.Choice{
			ChoiceID: i,
			Name:     choice,
		})
	}

	electionID := xid.New().String()
	mixnetServersPoints := make([]int, len(mixnetServers))
	threshold := len(mixnetServers)/2 + len(mixnetServers)%2
	initiators := make(map[string]types.Point)

	announceElectionMessage := types.AnnounceElectionMessage{
		Base: types.ElectionBase{
			ElectionID:  electionID,
			Announcer:   n.myAddr,
			Title:       title,
			Description: description,
			Choices:     electionChoices,

			Duration: electionDuration,

			// initiated later (see HandleInitiateElectionMessage)
			// Expiration:    expirationTime,
			MixnetServers: mixnetServers,

			// initiated only if needed (see HandleAnnounceElectionMessage)
			// MixnetServerInfos:   make(make([]types.MixnetServerInfo, len(mixnetServers)),

			// Incremented when mixnet server is among qualified nodes in types.ElectionReadyMessage
			MixnetServersPoints: mixnetServersPoints,

			Threshold:        threshold,
			ElectionReadyCnt: 0,
			Initiators:       initiators,
		},
	}

	err := n.sendAnnounceElectionMessage(announceElectionMessage)
	if err != nil {
		return "", err
	}

	return electionID, nil
}

func (n *node) GetElections() []*types.Election {
	elections := n.electionStore.GetAll()

	return elections
}

// todo vasilije vote async notify
func (n *node) Vote(electionID string, choiceID int) error {
	election := n.electionStore.Get(electionID)

	// encrypt choiceID
	plaintext := big.NewInt(int64(choiceID))
	publicKey := election.GetPublicKey()
	rScalar := GenerateRandomBigInt(elliptic.P256().Params().N)
	encryptedVote := ElGamalEncryption(elliptic.P256(), &publicKey, &rScalar, plaintext)

	// DLog proof
	secretBit := choiceID == 1
	secretOther := make([]byte, 32)
	pointOtherX, pointOtherY := elliptic.P256().ScalarBaseMult(secretOther)
	pointOther := NewPoint(pointOtherX, pointOtherY)
	proof, err := ProveDlogOr(rScalar.Bytes(), encryptedVote.Ct1, secretOther, pointOther, secretBit, elliptic.P256())

	if err != nil {
		return err
	}

	// broadcast as private message
	voteMessage := types.VoteMessage{
		ElectionID:       electionID,
		EncryptedVote:    *encryptedVote,
		CorrectVoteProof: *proof,
	}

	if election.MyVote != -1 {
		return errors.New("this peer has already voted")
	}

	n.dkgMutex.Lock()
	if !election.IsElectionStarted() {
		n.dkgMutex.Unlock()
		return errors.New("election hasn't started yet")
	}

	election.MyVote = choiceID
	n.electionStore.Set(voteMessage.ElectionID, election)

	mixnetServer := election.GetFirstQualifiedInitiator()
	n.dkgMutex.Unlock()

	err = n.sendVoteMessage(mixnetServer, voteMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) Mix(electionID string, hop int, shuffleProofs []types.ShuffleProof) error {
	election := n.electionStore.Get(electionID)
	votes := election.Votes

	// do the actual mixing
	voteCnt := len(votes)
	election.Base.VotesPermutation = MakeRandomPermutation(voteCnt)

	permutedVotes := make([]types.ElGamalCipherText, voteCnt)
	for i := 0; i < voteCnt; i++ {
		permutedVotes[i] = votes[election.Base.VotesPermutation[i]]
	}

	publicKey := election.GetPublicKey()
	reencryptedVotes := make([]types.ElGamalCipherText, voteCnt)

	rScalars := GenerateRandomPolynomial(len(votes)-1, elliptic.P256().Params().N)

	//todo dejan decryptShares := make([]types.ElGamalCipherText, voteCnt)
	for i, permutedVote := range permutedVotes {
		reencryptedVote := ElGamalReEncryption(elliptic.P256(), &publicKey, &rScalars[i], &permutedVote)

		// todo decryptShare := MakeDecryptShare(reencryptedVote, publicKey,)
		// decryptShares = append(decryptShares, )

		reencryptedVotes = append(reencryptedVotes, *reencryptedVote)
	}

	// shuffle proof

	shuffleInstance := NewShuffleInstance(elliptic.P256(), publicKey, votes, reencryptedVotes)
	shuffleWitness := NewShuffleWitness(election.Base.VotesPermutation, rScalars)
	shuffleProof, err := ProveShuffle(shuffleInstance, shuffleWitness)

	shuffleProofs = append(shuffleProofs, *shuffleProof)

	if err != nil {
		return err
	}

	nextHop := election.GetNextMixHop(hop)

	if nextHop != -1 {
		// done with mixing -> tally
		log.Info().Str("peerAddr", n.myAddr).Msgf("Last mixnet node reached: Start Tallying")
		n.Tally(electionID, reencryptedVotes)
		return nil
	}

	// otherwise continue forwarding to the next mixnet server

	mixMessage := types.MixMessage{
		ElectionID:    electionID,
		Votes:         reencryptedVotes,
		NextHop:       nextHop,
		ShuffleProofs: shuffleProofs,
		//		ReencryptionProof: reencryptionProof,
	}

	// get address for next hop
	mixnetPeer := election.Base.MixnetServers[mixMessage.NextHop]

	recipients := make(map[string]struct{})
	recipients[mixnetPeer] = struct{}{}

	err = n.sendPrivateMessage(recipients, mixMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) Tally(electionID string, votes []types.ElGamalCipherText) {
	election := n.electionStore.Get(electionID)

	// we want 0 to show up as a count as well
	// inefficient, but doesn't matter
	results := map[int]uint{}
	for _, choice := range election.Base.Choices {
		count := uint(0)
		//for _, vote := range votes {
		// todo vasilije uncomment dis
		//if vote == choice.ChoiceID {
		count++
		//}
		//}

		results[choice.ChoiceID] = count
	}

	resultMessage := types.ResultMessage{
		ElectionID: electionID,
		Results:    results,
	}

	err := n.sendResultsMessage(resultMessage)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msgf("error broadcasting election results")
	}
}
