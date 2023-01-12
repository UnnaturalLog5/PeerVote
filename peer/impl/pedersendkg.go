package impl

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
	"math/big"
	"time"
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
	a := GenerateRandomPolynomial(n.conf.PedersenSuite.T, &n.conf.PedersenSuite.Q)
	X := make([]big.Int, n.conf.PedersenSuite.T+1)
	for i := 0; i < len(a); i++ {
		// X[i] = g^a[i]
		X[i].Exp(&n.conf.PedersenSuite.G, &a[i], &n.conf.PedersenSuite.P)
	}
	f := func(id int) big.Int {
		base := big.NewInt(int64(id))
		sum := a[0]
		for i := 1; i <= n.conf.PedersenSuite.T; i++ {
			exp := big.NewInt(int64(i))
			factor := new(big.Int).Exp(base, exp, nil)
			tmp := new(big.Int).Mul(&a[i], factor)
			sum.Add(&sum, tmp)
		}
		return *new(big.Int).Mod(&sum, &n.conf.PedersenSuite.Q)
	}

	// Compute the share xij and send it to each mixnetServer
	for i := 0; i < len(mixnetServers); i++ {
		share := f(i + 1) // IDs of the mixnet server starts from 1
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
	dkgShareTransportMessage, err := marshalMessage(&dkgShareMessage)

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

// HandleDKGShareMessage handles types.DKGShareMessage
func (n *node) HandleDKGShareMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	dkgMessage, ok := msg.(*types.DKGShareMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing DKGShareMessage
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling DKGShareMessage from %v", pkt.Header.Source)

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
		ReceivedShare:   dkgMessage.Share,
		X:               dkgMessage.X,
		VerifiedCnt:     0,
		ComplainedCnt:   0,
		QualifiedStatus: types.NOT_DECIDED_YET,
	}

	myMixnetID := big.NewInt(int64(n.GetMyMixnetServerID(election)))
	isValid := n.VerifyEquation(myMixnetID, &dkgMessage.Share, dkgMessage.X)

	n.sendDKGShareValidationMessage(dkgMessage.ElectionID, election.Base.MixnetServers, dkgMessage.MixnetServerID, isValid)

	// todo update election in the store -> alter election store so it stores *references* to elections instead
	return nil
}

// sendDKGShareValidationMessage creates a new types.DKGShareValidationMessage, wraps it inside a
// types.PrivateMessage and sends it secretly to other mixnet servers
func (n *node) sendDKGShareValidationMessage(electionID string, mixnetServers []string, mixnetServerID int, isShareValid bool) {

	log.Info().Str("peerAddr", n.myAddr).Msgf("sending DKG Share Validation Message")

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

	// Processing DKGShareValidationMessage
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling DKGShareValidationMessage from %v", pkt.Header.Source)

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
		if election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].VerifiedCnt == len(election.Base.MixnetServers) {
			election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].QualifiedStatus = types.QUALIFIED
			if n.ShouldSendElectionReadyMessage(election) {
				n.sendElectionReadyMessage(election)
			}
		}
	} else {
		election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].ComplainedCnt++
		if election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].ComplainedCnt > n.conf.PedersenSuite.T {
			election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].QualifiedStatus = types.DISQUALIFIED
			election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID].X[0] = *big.NewInt(1)
			if n.ShouldSendElectionReadyMessage(election) {
				n.sendElectionReadyMessage(election)
			}
		} else {
			myMixnetServerID := n.GetMyMixnetServerID(election)
			if myMixnetServerID == dkgShareValidationMessage.MixnetServerID {
				n.sendDKGRevealShareMessage(election, myMixnetServerID, dkgShareValidationMessage.MixnetServerID)
			}
		}
	}

	return nil
}

// sendDKGRevealShareMessage broadcasts types.DKGRevealShareMessage to other mixnet servers
func (n *node) sendDKGRevealShareMessage(election types.Election, myMixnetServerID int, complainingServerID int) {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending KGRevealShareMessage")

	recipients := make(map[string]struct{})
	for _, mixnetServer := range election.Base.MixnetServers {
		recipients[mixnetServer] = struct{}{}
	}

	dkgRevealShareMessage := types.DKGRevealShareMessage{
		ElectionID:          election.Base.ElectionID,
		MixnetServerID:      myMixnetServerID,
		ComplainingServerID: complainingServerID,
	}

	dkgRevealShareTransportMessage, err := marshalMessage(&dkgRevealShareMessage)
	if err != nil {
		return
	}

	privateMessage := types.PrivateMessage{
		Recipients: recipients,
		Msg:        &dkgRevealShareTransportMessage,
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

// HandleDKGRevealShareMessage handles types.DKGRevealShareMessage
func (n *node) HandleDKGRevealShareMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	dkgRevealShareMessage, ok := msg.(*types.DKGRevealShareMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing DKGRevealShareMessage
	election := n.electionStore.Get(dkgRevealShareMessage.ElectionID)
	// todo what if node hasn't received ElectionAnnounceMessage yet?
	// add some kind of synchronization

	mixnetServers := election.Base.MixnetServers

	if !contains(mixnetServers, n.myAddr) {
		return fmt.Errorf("node received DKGShareValidationMessage for electionID %s,"+
			" but the node is not one of the mixnetServers", dkgRevealShareMessage.ElectionID)
	}

	if election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].QualifiedStatus == types.NOT_DECIDED_YET {

		j := big.NewInt(int64(dkgRevealShareMessage.MixnetServerID))
		share := dkgRevealShareMessage.Share
		X := election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].X
		isValid := n.VerifyEquation(j, &share, X)

		if !isValid {
			election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].QualifiedStatus = types.DISQUALIFIED
			election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].X[0] = *big.NewInt(1)
			if n.ShouldSendElectionReadyMessage(election) {
				n.sendElectionReadyMessage(election)
			}
		} else {
			election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].VerifiedCnt++
			election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].ComplainedCnt--
			if election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].VerifiedCnt == len(election.Base.MixnetServers) {
				election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].QualifiedStatus = types.QUALIFIED
				if n.ShouldSendElectionReadyMessage(election) {
					n.sendElectionReadyMessage(election)
				}
			}
		}
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
	if err != nil {
		return
	}
	err = n.Broadcast(electionReadyTransportMessage)
	if err != nil {
		return
	}

	// send election start message if I am among the qualified nodes with the lowest ID
	if n.ShouldInitiateElection(election) {
		n.InitiateElection(election)
	}
}

// HandleElectionReadyMessage processes types.ElectionReadyMessage. This message
// can be received by any peer. The peer collects the information about qualified
// (trusted) mixnet nodes.
func (n *node) HandleElectionReadyMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	electionReadyMessage, ok := msg.(*types.ElectionReadyMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing ElectionReadyMessage
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling ElectionReadyMessage from %v", pkt.Header.Source)

	// update QualifiedCnt for each mixnet server
	election := n.electionStore.Get(electionReadyMessage.ElectionID)
	for _, qualifiedServerID := range electionReadyMessage.QualifiedServers {
		election.Base.MixnetServersPoints[qualifiedServerID]++
	}
	election.Base.ElectionReadyCnt++

	n.electionStore.Set(election.Base.ElectionID, election) // todo delete dis (store references!!)

	if n.IsElectionStarted(election) {
		// todo election started, I am allowed to cast a vote
		log.Info().Str("peerAddr", n.myAddr).Msgf("election started, I am allowed to cast a vote", pkt.Header.Source)
	}

	return nil
}

// InitiateElection sends types.StartElectionMessage indicating that the election
// has officially started and that the peers are allowed to cast their votes.
func (n *node) InitiateElection(election types.Election) {

	election.Base.Expiration = time.Now().Add(election.Base.Duration)
	n.sendStartElectionMessage(election)

	// TODO
	// set timer for expiration to start with mixing
	go func() {
		// wait until the set expiration date until tallying votes
		expireIn := election.Base.Expiration.Sub(time.Now())
		<-time.After(expireIn)

		// TODO
		// mix and forward
		// n.MixAndForward()

		// for now just start tallying

		log.Info().Str("peerAddr", n.myAddr).Msgf("Election expired, starting tallying")
		n.Tally(election.Base.ElectionID)
	}()
}

// HandleStartElectionMessage processes types.StartElectionMessage. This message
// can be received by any peer. The peer learns that the election can officially start.
func (n *node) HandleStartElectionMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	startElectionMessage, ok := msg.(*types.StartElectionMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing types.StartElectionMessage
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling StartElectionMessage from %v", pkt.Header.Source)

	election := n.electionStore.Get(startElectionMessage.ElectionID)
	election.Base.Initiators[pkt.Header.Source] = struct{}{}
	election.Base.Expiration = startElectionMessage.Expiration

	n.electionStore.Set(election.Base.ElectionID, election) // todo delete dis (store references!!)

	if n.IsElectionStarted(election) {
		// todo election started, I am allowed to cast a vote
		log.Info().Str("peerAddr", n.myAddr).Msgf("election started, I am allowed to cast a vote!")
	}

	return nil
}

// sendStartElectionMessage creates a new types.StartElectionMessage, and broadcasts it to all the peers in the network,
func (n *node) sendStartElectionMessage(election types.Election) {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending StartElectionMessage")

	startElectionMessage := types.StartElectionMessage{
		ElectionID: election.Base.ElectionID,
		Expiration: election.Base.Expiration,
	}

	msg, err := marshalMessage(&startElectionMessage)

	if err != nil {
		return
	}

	err = n.Broadcast(msg)
	if err != nil {
		return
	}
}

// ShouldInitiateElection checks whether mixnet node should start the election
func (n *node) ShouldInitiateElection(election types.Election) bool {
	myID := n.GetMyMixnetServerID(election)
	initiatorID := n.GetMixnetServerInitiatorID(election)
	return myID == initiatorID
}

// GetMixnetServerInitiatorID returns the ID of the mixnet node which is responsible for
// starting the election, that is, the ID of a qualified mixnet node with the lowest ID
func (n *node) GetMixnetServerInitiatorID(election types.Election) int {
	for i := 0; i < len(election.Base.MixnetServerInfos); i++ {
		if election.Base.MixnetServerInfos[i].QualifiedStatus == types.QUALIFIED {
			return i + 1
		}
	}
	return -1
}

// GetQualifiedMixnetServers returns a list of qualified mixnet servers for the corresponding
// election.
func (n *node) GetQualifiedMixnetServers(election types.Election) []int {
	qualifiedServers := make([]int, 0)
	for i := 0; i < len(election.Base.MixnetServers); i++ {
		if election.Base.MixnetServerInfos[i].QualifiedStatus == types.QUALIFIED {
			qualifiedServers = append(qualifiedServers, i)
		}
	}
	return qualifiedServers
}

// ShouldSendElectionReadyMessage checks whether types.ElectionReadyMessage should be sent.
// types.ElectionReadyMessage should be sent only if all the mixnet servers have a decided status
// (types.QUALIFIED or types.DISQUALIFIED)
func (n *node) ShouldSendElectionReadyMessage(election types.Election) bool {
	for _, mixnetServerInfo := range election.Base.MixnetServerInfos {
		if mixnetServerInfo.QualifiedStatus == types.NOT_DECIDED_YET {
			return false
		}
	}
	return true
}

// VerifyEquation verifies if the received share is valid as a part of the second step
// of the Pedersen DKG protocol.
func (n *node) VerifyEquation(j *big.Int, share *big.Int, X []big.Int) bool {
	shareVal := new(big.Int).Exp(&n.conf.PedersenSuite.G, share, &n.conf.PedersenSuite.P)
	productVal := new(big.Int).SetInt64(1)
	for k := 0; k <= n.conf.PedersenSuite.T; k++ {
		exp := new(big.Int).Exp(j, big.NewInt(int64(k)), nil)
		factor := new(big.Int).Exp(&X[k], exp, &n.conf.PedersenSuite.P)
		productVal.Mul(productVal, factor)
		productVal.Mod(productVal, &n.conf.PedersenSuite.P)
	}

	return shareVal.Cmp(productVal) == 0
}

// ReconstructPublicKey reconstructs the public value of the distributed shared key
func (n *node) ReconstructPublicKey(election types.Election) *big.Int {
	productVal := new(big.Int).SetInt64(1)
	for _, server := range election.Base.MixnetServerInfos {
		productVal.Mul(productVal, &server.X[0])
		productVal.Mod(productVal, &n.conf.PedersenSuite.P)
	}
	return productVal
}

// GetMyMixnetServerID returns the ID of the node within mixnet servers
func (n *node) GetMyMixnetServerID(election types.Election) int {
	for i, addr := range election.Base.MixnetServers {
		if addr == n.myAddr {
			return i + 1
		}
	}
	return -1
}
