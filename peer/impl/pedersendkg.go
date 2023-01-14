package impl

import (
	"crypto/elliptic"
	"errors"
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
func (n *node) PedersenDkg(election *types.Election) {
	// Choose a random polynomial f(z) over Zq of degree t:
	// f(z) = a0 + a1*z + ... + at*z^t
	a := GenerateRandomPolynomial(election.Base.Threshold, elliptic.P256().Params().N)
	X := make([]types.Point, election.Base.Threshold+1)
	for i := 0; i < len(a); i++ {
		// X[i] = g^a[i]
		X[i].X, X[i].Y = elliptic.P256().ScalarBaseMult(a[i].Bytes())
	}
	f := func(id int) big.Int {
		base := big.NewInt(int64(id))
		sum := new(big.Int)
		sum = sum.Set(&a[0])
		for i := 1; i <= election.Base.Threshold; i++ {
			exp := big.NewInt(int64(i))
			factor := new(big.Int).Exp(base, exp, nil)
			tmp := new(big.Int).Mul(&a[i], factor)
			sum.Add(sum, tmp)
		}
		return *new(big.Int).Mod(sum, elliptic.P256().Params().N)
	}
	myMixnetServerID := election.GetMyMixnetServerID(n.myAddr)
	// Compute the share xij and send it to each mixnetServer
	for i := 0; i < len(election.Base.MixnetServers); i++ {
		share := f(i + 1) // IDs of the mixnet server starts from 1
		n.sendDKGShareMessage(election.Base.ElectionID, election.Base.MixnetServers[i], myMixnetServerID, share, X)
	}
}

// sendDKGShareMessage creates a new types.DKGShareMessage, wraps it inside a
// types.PrivateMessage and sends it secretly to mixnetServer
func (n *node) sendDKGShareMessage(electionID string, mixnetServer string, mixnetServerID int, share big.Int, X []types.Point) {

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

	n.dkgMutex.Lock()

	// Processing DKGShareMessage
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling DKGShareMessage from %v", pkt.Header.Source)

	election := n.electionStore.Get(dkgMessage.ElectionID)
	if election == nil {
		timeout := time.Second * 10
		n.notfify.RegisterTimer(dkgMessage.ElectionID, timeout)
		n.dkgMutex.Unlock()
		_, ok := n.notfify.Wait(dkgMessage.ElectionID, timeout)
		if !ok {
			return errors.New("received DKGShareMessage before AnnounceElectionMessage")
		}
		n.dkgMutex.Lock()
		election = n.electionStore.Get(dkgMessage.ElectionID)
	}

	mixnetServers := election.Base.MixnetServers

	if !contains(mixnetServers, n.myAddr) {
		return fmt.Errorf("node received DKGShareMessage for electionID %s,"+
			" but the node is not one of the mixnetServers", dkgMessage.ElectionID)
	}

	// store info about mixnetserver
	if election.Base.MixnetServerInfos[dkgMessage.MixnetServerID] == nil {
		election.Base.MixnetServerInfos[dkgMessage.MixnetServerID] = &types.MixnetServerInfo{
			ReceivedShare:   dkgMessage.Share,
			X:               dkgMessage.X,
			VerifiedCnt:     0,
			ComplainedCnt:   0,
			QualifiedStatus: types.NOT_DECIDED_YET,
		}
	} else {
		if election.Base.MixnetServerInfos[dkgMessage.MixnetServerID].QualifiedStatus != types.NOT_DECIDED_YET {
			n.dkgMutex.Unlock()
			return nil
		} else {
			election.Base.MixnetServerInfos[dkgMessage.MixnetServerID].ReceivedShare = dkgMessage.Share
			election.Base.MixnetServerInfos[dkgMessage.MixnetServerID].X = dkgMessage.X
		}
	}

	n.dkgMutex.Unlock()

	myMixnetID := big.NewInt(int64(election.GetMyMixnetServerID(n.myAddr) + 1))
	isValid := n.VerifyEquation(myMixnetID, &dkgMessage.Share, dkgMessage.X, election.Base.Threshold)
	//if isValid {
	//	fmt.Printf("share received from %s is valid | says %s\n", pkt.Header.Source, n.myAddr)
	//} else {
	//	fmt.Printf("share received from %s is invalid | says %s\n", pkt.Header.Source, n.myAddr)
	//}
	n.sendDKGShareValidationMessage(dkgMessage.ElectionID, election.Base.MixnetServers, dkgMessage.MixnetServerID, isValid)

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

	n.dkgMutex.Lock()
	// Processing DKGShareValidationMessage
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling DKGShareValidationMessage from %v", pkt.Header.Source)

	election := n.electionStore.Get(dkgShareValidationMessage.ElectionID)
	if election == nil {
		timeout := time.Second * 10
		n.notfify.RegisterTimer(dkgShareValidationMessage.ElectionID, timeout)
		n.dkgMutex.Unlock()
		_, ok := n.notfify.Wait(dkgShareValidationMessage.ElectionID, timeout)
		if !ok {
			return errors.New("received DKGShareValidationMessage before AnnounceElectionMessage")
		}
		n.dkgMutex.Lock()
		election = n.electionStore.Get(dkgShareValidationMessage.ElectionID)
	}

	mixnetServers := election.Base.MixnetServers

	if !contains(mixnetServers, n.myAddr) {
		return fmt.Errorf("node received DKGShareValidationMessage for electionID %s,"+
			" but the node is not one of the mixnetServers", dkgShareValidationMessage.ElectionID)
	}

	mixnetServerInfo := election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID]
	if mixnetServerInfo == nil {
		mixnetServerInfo = &types.MixnetServerInfo{
			ReceivedShare:   big.Int{},
			X:               make([]types.Point, len(election.Base.MixnetServers)),
			VerifiedCnt:     0,
			ComplainedCnt:   0,
			QualifiedStatus: types.NOT_DECIDED_YET,
		}
		election.Base.MixnetServerInfos[dkgShareValidationMessage.MixnetServerID] = mixnetServerInfo
	}

	if dkgShareValidationMessage.IsShareValid {
		mixnetServerInfo.VerifiedCnt++
		if mixnetServerInfo.VerifiedCnt == len(election.Base.MixnetServers) {
			mixnetServerInfo.QualifiedStatus = types.QUALIFIED
			if n.ShouldSendElectionReadyMessage(election) {
				n.dkgMutex.Unlock()
				n.sendElectionReadyMessage(election)
				return nil
			}
		}
	} else {
		mixnetServerInfo.ComplainedCnt++
		if mixnetServerInfo.ComplainedCnt > election.Base.Threshold {
			mixnetServerInfo.QualifiedStatus = types.DISQUALIFIED
			mixnetServerInfo.X[0].X, mixnetServerInfo.X[0].Y = elliptic.P256().ScalarBaseMult(make([]byte, 32))
			if n.ShouldSendElectionReadyMessage(election) {
				n.dkgMutex.Unlock()
				n.sendElectionReadyMessage(election)
				return nil
			}
		} else {
			myMixnetServerID := election.GetMyMixnetServerID(n.myAddr)
			if myMixnetServerID == dkgShareValidationMessage.MixnetServerID {
				n.dkgMutex.Unlock()
				n.sendDKGRevealShareMessage(election, myMixnetServerID, dkgShareValidationMessage.MixnetServerID)
				return nil
			}
		}
	}

	n.dkgMutex.Unlock()
	return nil
}

// sendDKGRevealShareMessage broadcasts types.DKGRevealShareMessage to other mixnet servers
func (n *node) sendDKGRevealShareMessage(election *types.Election, myMixnetServerID int, complainingServerID int) {
	return
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending DKGRevealShareMessage")

	recipients := make(map[string]struct{})
	for _, mixnetServer := range election.Base.MixnetServers {
		if mixnetServer != n.myAddr {
			recipients[mixnetServer] = struct{}{}
		}
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
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling DKGRevealShareMessage from %v", pkt.Header.Source)

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
		isValid := n.VerifyEquation(j, &share, X, election.Base.Threshold)

		if !isValid {
			election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].QualifiedStatus = types.DISQUALIFIED
			election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].X[0].X,
				election.Base.MixnetServerInfos[dkgRevealShareMessage.MixnetServerID].X[0].Y =
				elliptic.P256().ScalarBaseMult(make([]byte, 32))
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
func (n *node) sendElectionReadyMessage(election *types.Election) {
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
	n.dkgMutex.Lock()
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling ElectionReadyMessage from %v", pkt.Header.Source)

	// update QualifiedCnt for each mixnet server
	election := n.electionStore.Get(electionReadyMessage.ElectionID)
	if election == nil {
		timeout := time.Second * 10
		n.notfify.RegisterTimer(electionReadyMessage.ElectionID, timeout)
		n.dkgMutex.Unlock()
		_, ok := n.notfify.Wait(electionReadyMessage.ElectionID, timeout)
		if !ok {
			return errors.New("received ElectionReadyMessage before AnnounceElectionMessage")
		}
		n.dkgMutex.Lock()
		election = n.electionStore.Get(electionReadyMessage.ElectionID)
	}

	for _, qualifiedServerID := range electionReadyMessage.QualifiedServers {
		election.Base.MixnetServersPoints[qualifiedServerID]++
	}
	election.Base.ElectionReadyCnt++

	if election.IsElectionStarted() {
		// todo election started, I am allowed to cast a vote
		// todo display some kind of a message on frontend
		log.Info().Str("peerAddr", n.myAddr).Msgf("election started, I am allowed to cast a vote", pkt.Header.Source)
	}
	n.dkgMutex.Unlock()
	return nil
}

// sendStartElectionMessage creates a new types.StartElectionMessage, and broadcasts it to all the peers in the network,
func (n *node) sendStartElectionMessage(election *types.Election) {
	log.Info().Str("peerAddr", n.myAddr).Msgf("sending StartElectionMessage")

	publicKey := n.ReconstructPublicKey(election)
	startElectionMessage := types.StartElectionMessage{
		ElectionID: election.Base.ElectionID,
		Expiration: election.Base.Expiration,
		PublicKey:  publicKey,
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

// HandleStartElectionMessage processes types.StartElectionMessage. This message
// can be received by any peer. The peer learns that the election can officially start.
func (n *node) HandleStartElectionMessage(msg types.Message, pkt transport.Packet) error {
	// cast the message to its actual type. You assume it is the right type.
	startElectionMessage, ok := msg.(*types.StartElectionMessage)
	if !ok {
		return fmt.Errorf("wrong type: %T", msg)
	}

	// Processing types.StartElectionMessage
	n.dkgMutex.Lock()
	log.Info().Str("peerAddr", n.myAddr).Msgf("handling StartElectionMessage from %v", pkt.Header.Source)

	election := n.electionStore.Get(startElectionMessage.ElectionID)
	if election == nil {
		timeout := time.Second * 10
		n.notfify.RegisterTimer(startElectionMessage.ElectionID, timeout)
		n.dkgMutex.Unlock()
		_, ok := n.notfify.Wait(startElectionMessage.ElectionID, timeout)
		if !ok {
			return errors.New("received StartElectionMessage before AnnounceElectionMessage")
		}
		n.dkgMutex.Lock()
		election = n.electionStore.Get(startElectionMessage.ElectionID)
	}

	election.Base.Initiators[pkt.Header.Source] = startElectionMessage.PublicKey
	election.Base.Expiration = startElectionMessage.Expiration

	if election.IsElectionStarted() {
		// todo election started, I am allowed to cast a vote
		// todo display some kind of a message on frontend
		log.Info().Str("peerAddr", n.myAddr).Msgf("election started, I am allowed to cast a vote!")
	}

	n.dkgMutex.Unlock()

	log.Info().Str("peerAddr", n.myAddr).Msgf("processing StartElectionMessage from %v done", pkt.Header.Source)

	return nil
}

// ShouldInitiateElection checks whether mixnet node should start the election
func (n *node) ShouldInitiateElection(election *types.Election) bool {
	myID := election.GetMyMixnetServerID(n.myAddr)
	initiatorID := n.GetMixnetServerInitiatorID(election)
	return myID == initiatorID
}

// InitiateElection sends types.StartElectionMessage indicating that the election
// has officially started and that the peers are allowed to cast their votes.
func (n *node) InitiateElection(election *types.Election) {

	election.Base.Expiration = time.Now().Add(election.Base.Duration)
	n.sendStartElectionMessage(election)

	go func() {
		// wait until the set expiration date until tallying votes
		expireIn := election.Base.Expiration.Sub(time.Now())
		<-time.After(expireIn)

		// mix and forward
		log.Info().Str("peerAddr", n.myAddr).Msgf("Election expired, starting mixing")
		// send to ourselves a MixMessage (hop 0) so we can bootstrap the mixing process
		n.Mix(election.Base.ElectionID, 0)
	}()
}

// GetMixnetServerInitiatorID returns the ID of the mixnet node which is responsible for
// starting the election, that is, the ID of a qualified mixnet node with the lowest ID
func (n *node) GetMixnetServerInitiatorID(election *types.Election) int {
	for i := 0; i < len(election.Base.MixnetServerInfos); i++ {
		if election.Base.MixnetServerInfos[i].QualifiedStatus == types.QUALIFIED {
			return i
		}
	}
	return -1
}

// GetQualifiedMixnetServers returns a list of qualified mixnet servers for the corresponding
// election.
func (n *node) GetQualifiedMixnetServers(election *types.Election) []int {
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
func (n *node) ShouldSendElectionReadyMessage(election *types.Election) bool {
	for _, mixnetServerInfo := range election.Base.MixnetServerInfos {
		if mixnetServerInfo.QualifiedStatus == types.NOT_DECIDED_YET {
			return false
		}
	}
	return true
}

// VerifyEquation verifies if the received share is valid as a part of the second step
// of the Pedersen DKG protocol.
func (n *node) VerifyEquation(j *big.Int, share *big.Int, X []types.Point, t int) bool {
	leftSideX, leftSideY := elliptic.P256().ScalarBaseMult(share.Bytes())
	productValX, productValY := elliptic.P256().ScalarBaseMult(make([]byte, 32))
	for k := 0; k <= t; k++ {
		exp := new(big.Int).Exp(j, big.NewInt(int64(k)), nil)
		factorX, factorY := elliptic.P256().ScalarMult(X[k].X, X[k].Y, exp.Bytes())
		productValX, productValY = elliptic.P256().Add(factorX, factorY, productValX, productValY)
	}
	return leftSideX.Cmp(productValX) == 0 && leftSideY.Cmp(productValY) == 0
}

// ReconstructPublicKey reconstructs the public value of the distributed shared key
func (n *node) ReconstructPublicKey(election *types.Election) types.Point {
	productValX, productValY := elliptic.P256().ScalarBaseMult(make([]byte, 32))
	for _, server := range election.Base.MixnetServerInfos {
		productValX, productValY = elliptic.P256().Add(server.X[0].X, server.X[0].Y, productValX, productValY)
	}

	//
	return NewPoint(productValX, productValY)
}
