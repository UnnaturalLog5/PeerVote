package unit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
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
	expirationTime := time.Now().Add(time.Second * 3)

	mixnetServers := []string{node2.GetAddr()}

	electionID, err := node1.StartElection("Election for Mayer", "El Cidad is looking for a new mayor", choices, mixnetServers, expirationTime)
	require.NoError(t, err)

	time.Sleep(time.Second)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	elections2 := node2.GetElections()
	election2 := elections2[0]
	require.Equal(t, election, election2)

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

	elections2 = node2.GetElections()
	election2 = elections2[0]

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
	expirationTime := time.Now().Add(time.Second * 1)

	mixnetServers := []string{node2.GetAddr()}
	electionID, err := node1.StartElection("Election for Mayer", "El Cidad is looking for a new mayor", choices, mixnetServers, expirationTime)
	require.NoError(t, err)

	time.Sleep(time.Second * 2)

	elections := node1.GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	elections2 := node2.GetElections()
	election2 := elections2[0]
	require.Equal(t, election, election2)

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
