package impl

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/rs/xid"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
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

	secretValue, err := rand.Int(rand.Reader, new(big.Int).SetUint64(2))
	if err != nil {
		return err
	}

	secretValueInt := int(secretValue.Int64())

	secretBit := secretValueInt == 0

	// rPkPoint will act as a decryption share on the part of the voters
	// In Decryption, the final mixnet server will have to access it in the ballot proof in order to do correct
	rPkX, rPkY := elliptic.P256().ScalarMult(publicKey.X, publicKey.Y, rScalar.Bytes())
	rPkPoint := NewPoint(rPkX, rPkY)
	correctEncProof, err := ProveDlogEq(rScalar.Bytes(), encryptedVote.Ct1, publicKey, rPkPoint, elliptic.P256())

	if err != nil {
		return err
	}

	// Prove that ballot is either the encryption of 0 or of 1
	proofBallot, err := ProveDlogEqOr(rScalar.Bytes(), encryptedVote.Ct1, publicKey, rPkPoint, elliptic.P256(), secretBit)
	if err != nil {
		return err
	}

	// broadcast as private message
	voteMessage := types.VoteMessage{
		ElectionID:       electionID,
		EncryptedVote:    *encryptedVote,
		CorrectVoteProof: *proofBallot,
		CorectEncProof:   *correctEncProof,
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

func (n *node) Mix(electionID string, hop int, shuffleProofs []types.ShuffleProof, reEncProofs []types.Proof) error {
	election := n.electionStore.Get(electionID)
	votes := election.Votes
	curve := elliptic.P256()

	// do the actual mixing
	voteCnt := len(votes)
	election.Base.VotesPermutation = MakeRandomPermutation(voteCnt)

	permutedVotes := make([]types.VoteMessage, voteCnt)
	for i := 0; i < voteCnt; i++ {
		permutedVotes[i] = votes[election.Base.VotesPermutation[i]]
	}

	publicKey := election.GetPublicKey()
	reencryptedVotes := make([]types.VoteMessage, voteCnt)

	// Generates a list of scalars for reencryption
	rScalars := GenerateRandomPolynomial(len(votes)-1, curve.Params().N)

	for i, permutedVote := range permutedVotes {
		// Vote instead of Ciphetext
		reencryptedVote := ElGamalVoteReEncryption(curve, &publicKey, &rScalars[i], permutedVote)

		// This is the original vote on which reEncryption is done
		encVoteBefore := votes[election.Base.VotesPermutation[i]].EncryptedVote

		minusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))

		// Negate the before ciphertexts
		negEncVoteBeforeCt1X, negEncVoteBeforeCt1Y := curve.ScalarMult(encVoteBefore.Ct1.X, encVoteBefore.Ct1.Y, minusOne.Bytes())
		negEncVoteBeforeCt2X, negEncVoteBeforeCt2Y := curve.ScalarMult(encVoteBefore.Ct2.X, encVoteBefore.Ct2.Y, minusOne.Bytes())

		DiffCt1X, DiffCt1Y := curve.Add(reencryptedVote.EncryptedVote.Ct1.X, reencryptedVote.EncryptedVote.Ct1.Y, negEncVoteBeforeCt1X, negEncVoteBeforeCt1Y)
		DiffCt1Point := NewPoint(DiffCt1X, DiffCt1Y)

		DiffCt2X, DiffCt2Y := curve.Add(reencryptedVote.EncryptedVote.Ct2.X, reencryptedVote.EncryptedVote.Ct2.Y, negEncVoteBeforeCt2X, negEncVoteBeforeCt2Y)
		DiffCt2Point := NewPoint(DiffCt2X, DiffCt2Y)

		// Mixnet needs to prove that reenecryption is done properly. This is also a proof of the correct decryption share.
		reEncProof, err := ProveDlogEq(rScalars[i].Bytes(), DiffCt1Point, election.GetPublicKey(), DiffCt2Point, curve)
		if err != nil {
			return xerrors.Errorf("Error in Mix function, when generating reEncryption Proof, %v", err)
		}

		reEncProofs = append(reEncProofs, *reEncProof)
		reencryptedVotes = append(reencryptedVotes, reencryptedVote)
	}

	// Do Shuffle proof on the code

	// Extract ciphertexts from the received vote list
	ctBeforeList := make([]types.ElGamalCipherText, 0)
	for _, vote := range votes {
		ctBeforeList = append(ctBeforeList, vote.EncryptedVote)
	}

	// Extract ciphertexts from reencrypted vote list
	ctAfterList := make([]types.ElGamalCipherText, 0)
	for _, vote := range reencryptedVotes {
		ctBeforeList = append(ctAfterList, vote.EncryptedVote)
	}

	shuffleInstance := NewShuffleInstance(curve, publicKey, ctBeforeList, ctAfterList)
	shuffleWitness := NewShuffleWitness(election.Base.VotesPermutation, rScalars)
	shuffleProof, err := ProveShuffle(shuffleInstance, shuffleWitness)

	shuffleProofs = append(shuffleProofs, *shuffleProof)

	if err != nil {
		return err
	}

	// TODO: Changed order here
	// get address for next hop
	nextHop := election.GetNextMixHop(hop)

	// otherwise continue forwarding to the next mixnet server
	mixMessage := types.MixMessage{
		ElectionID:         electionID,
		Votes:              reencryptedVotes,
		NextHop:            nextHop,
		ShuffleProofs:      shuffleProofs,
		ReEncryptionProofs: reEncProofs,
	}

	if nextHop != -1 {
		// done with mixing -> tally
		log.Info().Str("peerAddr", n.myAddr).Msgf("Last mixnet node reached: Start Tallying")
		n.Tally(electionID, mixMessage)
		return nil
	}

	mixnetPeer := election.Base.MixnetServers[mixMessage.NextHop]

	recipients := make(map[string]struct{})
	recipients[mixnetPeer] = struct{}{}

	err = n.sendPrivateMessage(recipients, mixMessage)
	if err != nil {
		return err
	}

	return nil
}

func (n *node) Tally(electionID string, mixMessage types.MixMessage) {
	election := n.electionStore.Get(electionID)
	curve := elliptic.P256()
	votes := mixMessage.Votes
	// Step 1: add all ct2's together; this aggregates all encrypted vote into "encrypted result"
	electionResultX, electionResultY := votes[0].EncryptedVote.Ct2.X, votes[0].EncryptedVote.Ct2.Y
	encResult := NewPoint(electionResultX, electionResultY)
	if len(votes) > 1 {
		for i := 1; i < len(votes); i++ {
			encResult.X, encResult.Y = curve.Add(encResult.X, encResult.Y, votes[i].EncryptedVote.Ct2.X, votes[i].EncryptedVote.Ct2.X)
		}
	}

	// Step 2: Access all decryption shares of the mixnets
	minusOne := new(big.Int).Sub(curve.Params().N, big.NewInt(1))
	for _, proof := range mixMessage.ReEncryptionProofs {
		decryptShareCompressed := proof.PPointOther
		decryptShareX, decryptShareY := elliptic.UnmarshalCompressed(curve, decryptShareCompressed)
		negDecryptShareX, negDecryptShareY := curve.ScalarMult(decryptShareX, decryptShareY, minusOne.Bytes())

		encResult.X, encResult.Y = curve.Add(encResult.X, encResult.Y, negDecryptShareX, negDecryptShareY)
	}

	// Step 3: Access all decryption shares of the voters
	for _, vote := range votes {
		proof := vote.CorectEncProof
		decryptShareCompressed := proof.PPointOther
		decryptShareX, decryptShareY := elliptic.UnmarshalCompressed(curve, decryptShareCompressed)
		negDecryptShareX, negDecryptShareY := curve.ScalarMult(decryptShareX, decryptShareY, minusOne.Bytes())

		encResult.X, encResult.Y = curve.Add(encResult.X, encResult.Y, negDecryptShareX, negDecryptShareY)
	}
	// The actual vote count (the number of 1 votes) is the discrete log of the encResult
	participantNum := len(votes)
	resultOnes, _ := BsgsFunction(&encResult, curve, participantNum)

	resultOnesUint := uint(resultOnes.Uint64())

	// Do partial decryption, then append proofs to the result message

	// we want 0 to show up as a count as well
	// inefficient, but doesn't matter
	results := map[int]uint{}
	results[1] = resultOnesUint
	results[0] = uint(participantNum) - resultOnesUint
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

	// Put proof into Result Messages at the end
	resultMessage := types.ResultMessage{
		ElectionID: electionID,
		Results:    results,
	}

	err := n.sendResultsMessage(resultMessage)
	if err != nil {
		log.Err(err).Str("peerAddr", n.myAddr).Msgf("error broadcasting election results")
	}
}

// TODO: Make a Verify(election?) message which will putput string ->bool map, string is name of the proof, and bool is whether it passed or not
// When I handle result message, save proofs into election, when you want to do display, then verify
