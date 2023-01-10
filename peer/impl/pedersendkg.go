package impl

import (
	"crypto/rand"
	"fmt"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"math/big"
)

// PedersenDkg implements Pedersen’s Distributed Key Generation Protocol
// Reference: Topics in Cryptology – CT-RSA 2003
// The Cryptographers’ Track at the RSA Conference 2003
// San Francisco, CA, USA, April 13-17, 2003 Proceedings
// Threshold Cryptography, Secure Applications of Pedersen’s Distributed
// Key Generation Protocol (Rosario Gennaro, Stanislaw Jarecki,
// Hugo Krawczyk, and Tal Rabin)
func (n *node) PedersenDkg(electionID string, mixnetServers []string) {
	// Choose a random polynomial f(z) over Zq of degree t:
	// f(z) = a0 + a1*z + ... + at*z^t
	a := n.GenerateRandomPolynomial()
	X := make([]big.Int, n.conf.PedersenSuite.T+1)
	for i := 0; i < len(a); i++ {
		// X[i] = g^a[i]
		X[i].Exp(&n.conf.PedersenSuite.G, &a[i], &n.conf.PedersenSuite.P)
	}
	f := func(id int) big.Int {
		sum := big.Int{}
		for i := 0; i < n.conf.PedersenSuite.T; i++ {
			tmp := new(big.Int).Mul(&a[i], new(big.Int).Exp(big.NewInt(int64(id)), big.NewInt(int64(id)), nil))
			sum.Add(&sum, tmp)
		}
		return sum
	}

	// Compute the share xij and send it to each mixnetServer
	for i := 0; i < len(mixnetServers); i++ {
		share := f(i + 1)
		n.sendDKGShareMessage(electionID, mixnetServers[i], i, share, X)
	}

}

// sendDKGShareMessage creates a new types.DKGShareMessage, wraps it inside a
// types.PrivateMessage and sends it secretly to mixnetServer
func (n *node) sendDKGShareMessage(electionID string, mixnetServer string, mixnetServerID int, share big.Int, X []big.Int) {

	log.Info().Str("peerAddr", n.myAddr).Msgf("sending DKG Share Message")

	recipients := map[string]struct{}{
		mixnetServer: {},
	}

	dkgShareMessage := types.DKGShareMessage{
		ElectionID:     electionID,
		MixnetServerID: mixnetServerID,
		Share:          share,
		X:              X,
	}
	dkgShareTransportMessage, err := marshalMessage(dkgShareMessage)

	privateMessage := types.PrivateMessage{
		Recipients: recipients,
		Msg:        &dkgShareTransportMessage,
	}

	msg, err := marshalMessage(privateMessage)
	if err != nil {
		return
	}

	err = n.Broadcast(msg)
	if err != nil {
		return
	}
}

// GenerateRandomPolynomial generates random polynomial of degree t
// over group Zq. Returns a slice which contains the coefficients of
// the corresponding polynomial.
func (n *node) GenerateRandomPolynomial() []big.Int {
	arr := make([]big.Int, n.conf.PedersenSuite.T+1)
	for i := 0; i < n.conf.PedersenSuite.T+1; i++ {
		arr[i] = *n.GenerateRandomBigInt()
	}
	return arr
}

// GenerateRandomBigInt generates a random value in Zq
func (n *node) GenerateRandomBigInt() *big.Int {
	//Generate cryptographically strong pseudo-random between 0 - max
	a, _ := rand.Int(rand.Reader, &n.conf.PedersenSuite.Q)
	return a
}

// HandleDKGShareMessage handles types.DKGShareMessage
func (n *node) HandleDKGShareMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	dkgMessage, ok := msg.(*types.DKGShareMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing DKGShareMessage

	election := n.electionStore.Get(dkgMessage.ElectionID)
	// todo what if node hasn't received ElectionAnnounceMessage yet?
	// add some kind of synchronization

	mixnetServers := election.Base.MixnetServers

	if !contains(mixnetServers, n.myAddr) {
		return fmt.Errorf("node received DKGShareMessage for electionID %s,"+
			" but the node is not one of the mixnetServers", dkgMessage.ElectionID)
	}

	// store info about mixnetserver
	// todo what if I already received a Complaint message for example?
	election.Base.MixnetServerInfos[dkgMessage.MixnetServerID] = types.MixnetServerInfo{
		ReceivedShare: dkgMessage.Share,
		X:             dkgMessage.X,
		VerifiedCnt:   0,
		ComplainedCnt: 0,
	}

	myMixnetID := big.NewInt(int64(n.GetMyMixnetServerID(election.Base.MixnetServers)))
	isValid := n.VerifyEquation(myMixnetID, &dkgMessage.Share, dkgMessage.X)

	n.sendDKGShareValidationMessage(dkgMessage.ElectionID, election.Base.MixnetServers, dkgMessage.MixnetServerID, isValid)

	// todo update election in the store -> alter election store so it stores *references* to elections instead
	return nil
}

// sendDKGShareValidationMessage creates a new types.DKGShareValidationMessage, wraps it inside a
// types.PrivateMessage and sends it secretly to other mixnet servers
func (n *node) sendDKGShareValidationMessage(electionID string, mixnetServers []string, mixnetServerID int, isShareValid bool) {

	log.Info().Str("peerAddr", n.myAddr).Msgf("sending DKG Share Validition Message")

	recipients := make(map[string]struct{})
	for _, mixnetServer := range mixnetServers {
		recipients[mixnetServer] = struct{}{}
	}

	dkgShareValidationMessage := types.DKGShareValidationMessage{
		ElectionID:     electionID,
		MixnetServerID: mixnetServerID,
		IsShareValid:   isShareValid,
	}
	dkgShareValidationTransportMessage, err := marshalMessage(&dkgShareValidationMessage)

	privateMessage := types.PrivateMessage{
		Recipients: recipients,
		Msg:        &dkgShareValidationTransportMessage,
	}

	msg, err := marshalMessage(privateMessage)
	if err != nil {
		return
	}

	err = n.Broadcast(msg)
	if err != nil {
		return
	}
}

// HandleDKGShareValidationMessage handles types.DKGShareValidationMessage
func (n *node) HandleDKGShareValidationMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	dkgShareValidationMessage, ok := msg.(*types.DKGShareValidationMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing DKGShareMessage

	election := n.electionStore.Get(dkgShareValidationMessage.ElectionID)
	// todo what if node hasn't received ElectionAnnounceMessage yet?
	// add some kind of synchronization

	mixnetServers := election.Base.MixnetServers

	if !contains(mixnetServers, n.myAddr) {
		return fmt.Errorf("node received DKGShareValidationMessage for electionID %s,"+
			" but the node is not one of the mixnetServers", dkgShareValidationMessage.ElectionID)
	}

	if dkgShareValidationMessage.IsShareValid {
		election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].VerifiedCnt++
	} else {
		election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].ComplainedCnt++
	}

	if n.ShouldSendElectionReadyMessage(election) {
		n.sendElectionReadyMessage(election)
	}

	return nil
}

// sendElectionReadyMessage broadcasts types.ElectionReadyMessage
func (n *node) sendElectionReadyMessage(election types.Election) {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending ElectionReadyMessage")

	qualifiedServers := n.GetQualifiedMixnetServers(election)

	electionReadyMessage := types.ElectionReadyMessage{
		ElectionID:       election.Base.ElectionID,
		QualifiedServers: qualifiedServers,
	}
	electionReadyTransportMessage, err := marshalMessage(&electionReadyMessage)

	err = n.Broadcast(electionReadyTransportMessage)
	if err != nil {
		return
	}
}

// GetQualifiedMixnetServers returns a list of qualified mixnet servers for the corresponding
// election.
func (n *node) GetQualifiedMixnetServers(election types.Election) []string {
	qualifiedServers := make([]string, 0)
	for i := 0; i < len(election.Base.MixnetServers); i++ {
		if election.Base.MixnetServerInfos[i].VerifiedCnt == len(election.Base.MixnetServers) {
			qualifiedServers = append(qualifiedServers, election.Base.MixnetServers[i])
		}
	}
	return qualifiedServers
}

// ShouldSendElectionReadyMessage checks whether types.ElectionReadyMessage should be sent.
// types.ElectionReadyMessage should be sent only when all n*n types.DKGShareValidationMessage
// have arrived and if all of the mixnet servers have clear status (Qualified/Disqualified)
func (n *node) ShouldSendElectionReadyMessage(election types.Election) bool {
	serverCnt := len(election.Base.MixnetServers)
	for _, mixnetServerInfo := range election.Base.MixnetServerInfos {
		if mixnetServerInfo.VerifiedCnt+mixnetServerInfo.ComplainedCnt != serverCnt ||
			(mixnetServerInfo.ComplainedCnt != 0 && mixnetServerInfo.ComplainedCnt < serverCnt/2) {
			return false
		}
	}
	return true
}

// VerifyEquation verifies if the received share is valid as a part of the second step
// of the Pedersen DKG protocol.
func (n *node) VerifyEquation(myMixnetID *big.Int, share *big.Int, X []big.Int) bool {
	shareVal := new(big.Int).Exp(&n.conf.PedersenSuite.G, share, &n.conf.PedersenSuite.P)
	productVal := new(big.Int).SetInt64(1)
	for k := 0; k <= n.conf.PedersenSuite.T; k++ {
		exp := new(big.Int).Exp(myMixnetID, big.NewInt(int64(k)), nil)
		factor := new(big.Int).Exp(&X[k], exp, &n.conf.PedersenSuite.P)
		productVal.Mul(productVal, factor)
		productVal.Mod(productVal, &n.conf.PedersenSuite.P)
	}

	return shareVal.Cmp(productVal) == 0
}

// GetMyMixnetServerID returns the ID of the node within mixnet servers
func (n *node) GetMyMixnetServerID(mixnetServers []string) int {
	for i, addr := range mixnetServers {
		if addr == n.myAddr {
			return i + 1
		}
	}
	return -1
}
