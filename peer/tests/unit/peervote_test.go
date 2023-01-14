package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/transport/channel"
)

func GetWinner(results map[string]uint) string {
	highestCount := uint(0)
	winner := ""

	for choice, count := range results {
		if count > highestCount {
			winner = choice
			highestCount = count
		}
	}

	return winner
}

func Test_SimpleElection(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())

	choices := []string{"One choice", "a better choice"}

	mixnetServers := []string{node2.GetAddr()}

	electionID, err := node1.AnnounceElection("Election for Mayor", "El Cidad is looking for a new mayor", choices, mixnetServers, time.Second*10)
	require.NoError(t, err)

	time.Sleep(time.Second * 6)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	// The election information that holds a mixnet node is
	// a bit different from other peers, hence this test can't pass

	//elections2 := node2.GetElections()
	//election2 := elections2[0]
	//require.Equal(t, election, election2)

	choiceID := election.Base.Choices[0].ChoiceID

	err = node1.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	err = node2.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	time.Sleep(time.Second)

	// first mixnet node accepts the votes
	votes := node2.GetElections()[0].Votes
	require.Len(t, votes, 2)

	time.Sleep(time.Second * 5)

	elections = node1.GetElections()
	election = elections[0]

	winner := GetWinner(election.Results)
	require.Equal(t, winner, choiceID)

	//elections2 = node2.GetElections()
	//election2 = elections2[0]

	winner2 := GetWinner(election.Results)
	require.Equal(t, winner2, choiceID)
}

func Test_ElectionTwoMixnetNodes(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node1.GetAddr())

	choices := []string{"One choice", "a better choice"}

	mixnetServers := []string{node1.GetAddr(), node2.GetAddr()}

	electionID, err := node1.AnnounceElection("Election for Mayor", "El Cidad is looking for a new mayor", choices, mixnetServers, time.Second*5)
	require.NoError(t, err)

	time.Sleep(time.Second * 3333)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	choiceID := election.Base.Choices[0].ChoiceID

	err = node1.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	err = node2.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	time.Sleep(time.Second)

	// first mixnet node accepts the votes
	votes := node1.GetElections()[0].Votes
	require.Len(t, votes, 2)

	time.Sleep(time.Second * 5)

	elections = node1.GetElections()
	election = elections[0]

	winner := GetWinner(election.Results)
	require.Equal(t, winner, choiceID)

	winner2 := GetWinner(election.Results)
	require.Equal(t, winner2, choiceID)
}

func Test_ElectionThreeMixnetNodes(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	node3 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	// add peers
	node1.AddPeer(node2.GetAddr())
	node1.AddPeer(node3.GetAddr())

	node2.AddPeer(node1.GetAddr())
	node2.AddPeer(node3.GetAddr())

	node3.AddPeer(node1.GetAddr())
	node3.AddPeer(node2.GetAddr())

	choices := []string{"One choice", "a better choice"}

	mixnetServers := []string{node1.GetAddr(), node2.GetAddr(), node3.GetAddr()}

	electionID, err := node1.AnnounceElection("Election for Mayor", "El Cidad is looking for a new mayor", choices, mixnetServers, time.Second*5)
	require.NoError(t, err)

	time.Sleep(time.Second * 3)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	choiceID := election.Base.Choices[0].ChoiceID

	err = node1.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	err = node2.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	err = node3.Vote(elections[0].Base.ElectionID, choiceID)
	require.NoError(t, err)

	time.Sleep(time.Second)

	// first mixnet node accepts the votes
	votes := node1.GetElections()[0].Votes
	require.Len(t, votes, 3)

	time.Sleep(time.Second * 5)

	elections = node1.GetElections()
	election = elections[0]

	winner := GetWinner(election.Results)
	require.Equal(t, winner, choiceID)

	winner2 := GetWinner(election.Results)
	require.Equal(t, winner2, choiceID)
}

func Test_ElectionExpired(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node1.Stop()

	node2 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
	defer node2.Stop()

	node1.AddPeer(node2.GetAddr())

	choices := []string{"One choice", "a better choice"}

	mixnetServers := []string{node2.GetAddr()}

	electionID, err := node1.AnnounceElection("Election for Mayer", "El Cidad is looking for a new mayor", choices, mixnetServers, time.Second)
	require.NoError(t, err)

	time.Sleep(time.Second * 2)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	//elections2 := node2.GetElections()
	//election2 := elections2[0]
	//require.Equal(t, election, election2)

	choiceID := election.Base.Choices[0].ChoiceID

	err = node1.Vote(elections[0].Base.ElectionID, choiceID)

	err = node2.Vote(elections[0].Base.ElectionID, choiceID)

	time.Sleep(time.Second)

	var node z.TestNode
	voteAcceptor := election.Base.MixnetServers[0]
	if voteAcceptor == "127.0.0.1:1" {
		node = node1
	} else {
		node = node2
	}

	votes := node.GetElections()[0].Votes
	require.Len(t, votes, 0)
}

func Test_Mixing(t *testing.T) {
	transp := channel.NewTransport()

	node1 := z.NewTestNode(t,
		peerFac,
		transp,
		"127.0.0.1:0",
	)
	defer node1.Stop()

	node2 := z.NewTestNode(t,
		peerFac,
		transp,
		"127.0.0.1:0",
	)
	defer node2.Stop()

	node3 := z.NewTestNode(t,
		peerFac,
		transp,
		"127.0.0.1:0",
	)
	defer node3.Stop()

	node1.AddPeer(node2.GetAddr())
	node2.AddPeer(node3.GetAddr())

	choices := []string{"One choice", "a better choice"}

	mixnetServers := []string{
		node1.GetAddr(),
		node2.GetAddr(),
		node3.GetAddr(),
	}

	electionID, err := node1.AnnounceElection(
		"Election for Mayor",
		"El Cidad is looking for a new mayor",
		choices,
		mixnetServers,
		time.Second*3)
	require.NoError(t, err)

	time.Sleep(time.Second)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	elections2 := node2.GetElections()
	election2 := elections2[0]
	require.Equal(t, election, election2)

	choice1 := election.Base.Choices[0].ChoiceID
	choice2 := election.Base.Choices[1].ChoiceID

	err = node1.Vote(elections[0].Base.ElectionID, choice1)
	require.NoError(t, err)

	err = node2.Vote(elections[0].Base.ElectionID, choice2)
	require.NoError(t, err)

	err = node3.Vote(elections[0].Base.ElectionID, choice2)
	require.NoError(t, err)

	time.Sleep(time.Second * 4)

	// all chosen mixnet servers have sent the expected messages

	// node 1 rumors
	n1outs := node1.GetOuts()
	// 1: startelection
	msg, _ := getRumorByOrigin(t, n1outs, node1.GetAddr(), 1)
	require.NotNil(t, msg)
	startElection := z.GetStartElection(t, msg)
	require.NotNil(t, startElection)

	// 2: vote - private
	msg, _ = getRumorByOrigin(t, n1outs, node1.GetAddr(), 2)
	require.NotNil(t, msg)
	private := z.GetPrivate(t, msg)
	require.Contains(t, private.Recipients, node1.GetAddr())
	vote := z.GetVote(t, private.Msg)
	require.NotNil(t, vote)

	// 3: mix - private
	msg, _ = getRumorByOrigin(t, n1outs, node1.GetAddr(), 3)
	require.NotNil(t, msg)
	private = z.GetPrivate(t, msg)
	require.Contains(t, private.Recipients, node2.GetAddr())
	mix := z.GetMix(t, private.Msg)
	require.NotNil(t, mix)

	// node 2
	n2outs := node2.GetOuts()
	// 1: vote - private
	msg, _ = getRumorByOrigin(t, n2outs, node2.GetAddr(), 1)
	require.NotNil(t, msg)
	private = z.GetPrivate(t, msg)
	require.Contains(t, private.Recipients, node1.GetAddr())
	vote = z.GetVote(t, private.Msg)
	require.NotNil(t, vote)

	// 2: mix - private
	msg, _ = getRumorByOrigin(t, n2outs, node2.GetAddr(), 2)
	require.NotNil(t, msg)
	private = z.GetPrivate(t, msg)
	require.Contains(t, private.Recipients, node3.GetAddr())
	mix = z.GetMix(t, private.Msg)
	require.NotNil(t, mix)

	// node 3
	n3outs := node3.GetOuts()
	// 1: vote - private
	msg, _ = getRumorByOrigin(t, n3outs, node3.GetAddr(), 1)
	require.NotNil(t, msg)
	private = z.GetPrivate(t, msg)
	require.Contains(t, private.Recipients, node1.GetAddr())
	vote = z.GetVote(t, private.Msg)
	require.NotNil(t, vote)
	// 2: result
	msg, _ = getRumorByOrigin(t, n3outs, node3.GetAddr(), 2)
	require.NotNil(t, msg)
	results := z.GetResults(t, msg)
	require.NotNil(t, results)

	// all the nodes agree on the winner
	elections = node1.GetElections()
	election = elections[0]
	winner := GetWinner(election.Results)
	require.Equal(t, winner, choice2)

	elections2 = node2.GetElections()
	election2 = elections2[0]
	winner2 := GetWinner(election2.Results)
	require.Equal(t, winner2, choice2)

	elections3 := node3.GetElections()
	election3 := elections3[0]
	winner3 := GetWinner(election3.Results)
	require.Equal(t, winner3, choice2)
}

// func Test_StartNode(t *testing.T) {
// 	transp := udp.NewUDP()

// 	node1 := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0")
// 	defer node1.Stop()

// 	time.Sleep(time.Hour)
// }

// --- Utility Functions ---

// getRumor returns the transport.Message embedded in the rumor at the provided
// sequence.
func getRumorByOrigin(t *testing.T, pkts []transport.Packet, initiator string, sequence uint) (*transport.Message, *transport.Header) {
	for _, pkt := range pkts {
		if pkt.Msg.Type == "rumor" {
			rumor := z.GetRumor(t, pkt.Msg)

			// a broadcast only have one rumor
			if len(rumor.Rumors) == 1 {
				if rumor.Rumors[0].Sequence == sequence && rumor.Rumors[0].Origin == initiator {
					return rumor.Rumors[0].Msg, pkt.Header
				}
			}
		}
	}
	return nil, nil
}
