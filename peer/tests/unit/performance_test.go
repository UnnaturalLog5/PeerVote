package unit

import (
	"encoding/csv"
	"github.com/stretchr/testify/require"
	z "go.dedis.ch/cs438/internal/testing"
	"go.dedis.ch/cs438/transport/channel"
	"log"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

type Performance struct {
	Duration1 time.Duration
	Duration2 time.Duration
}

func (p Performance) String() string {
	return strconv.FormatInt(p.Duration1.Microseconds(), 10) + "," + strconv.FormatInt(p.Duration2.Microseconds(), 10)
}

func GetPerformances(t *testing.T, numNodes, numMixnetNodes int, electionDuration time.Duration) []Performance {

	transp := channel.NewTransport()

	nodes := make([]z.TestNode, numNodes)
	performances := make([]Performance, numNodes)

	for i := range nodes {
		node := z.NewTestNode(t, peerFac, transp, "127.0.0.1:0", z.WithTotalPeers(uint(numNodes)), z.WithPaxosID(uint(i+1)))
		defer node.Stop()

		nodes[i] = node
	}

	for _, n1 := range nodes {
		for _, n2 := range nodes {
			n1.AddPeer(n2.GetAddr())
		}
	}

	choices := []string{"One choice", "a better choice"}

	mixnetServers := make([]string, 0)
	for i := 0; i < numMixnetNodes; i++ {
		mixnetServers = append(mixnetServers, nodes[i].GetAddr())
	}

	wait := sync.WaitGroup{}
	wait.Add(numNodes)

	announceTime := time.Now()
	electionID, err := nodes[0].AnnounceElection("Election for Mayor", "El Cidad is looking for a new mayor", choices, mixnetServers, electionDuration)
	require.NoError(t, err)

	time.Sleep(time.Second)

	elections := nodes[0].GetElections()
	election := elections[0]

	require.Len(t, elections, 1)
	require.Equal(t, electionID, election.Base.ElectionID)

	choiceID := election.Base.Choices[0].ChoiceID

	for _, node := range nodes {
		go func(n z.TestNode) {
			defer wait.Done()
			err = n.Vote(elections[0].Base.ElectionID, choiceID)
			require.NoError(t, err)
		}(node)
	}

	wait.Wait()

	time.Sleep(electionDuration + time.Second*5)

	mixingStartedTime := nodes[0].GetElections()[0].MixingStartedTimestamp
	for i := 0; i < numNodes; i++ {
		performances[i] = Performance{
			Duration1: nodes[i].GetElections()[0].ElectionStartedTimestamp.Sub(announceTime),
			Duration2: nodes[i].GetElections()[0].ReceivedResultsTimestamp.Sub(mixingStartedTime),
		}
	}
	return performances
}

func Test_Performance(t *testing.T) {
	file, err := os.Create("perf.csv")
	defer file.Close()
	if err != nil {
		log.Fatalln("failed to open file", err)
		return
	}
	w := csv.NewWriter(file)
	defer w.Flush()

	nodeNum := 7
	minNumMixnetNodes := 1
	maxNumMixnetNodes := 6

	electionDurationBase := time.Second * 10

	if err = w.Write([]string{"n", "t1", "t2"}); err != nil {
		log.Fatalln("error writing record to file", err)
	}

	for i := minNumMixnetNodes; i <= maxNumMixnetNodes; i++ {
		performances := GetPerformances(t, nodeNum, i, electionDurationBase+time.Second*time.Duration(i))
		// Using Write
		for _, p := range performances {
			row := []string{
				strconv.FormatInt(int64(i), 10),
				strconv.FormatInt(p.Duration1.Microseconds(), 10),
				strconv.FormatInt(p.Duration2.Microseconds(), 10)}
			if err = w.Write(row); err != nil {
				log.Fatalln("error writing record to file", err)
			}
		}
	}

}

func Test_Demo(t *testing.T) {
	file, err := os.Create("perf.csv")
	defer file.Close()
	if err != nil {
		log.Fatalln("failed to open file", err)
		return
	}
	w := csv.NewWriter(file)
	defer w.Flush()

	nodeNum := 7
	numMixnetNodes := 3

	electionDurationBase := time.Second * 10

	if err = w.Write([]string{"n", "t1", "t2"}); err != nil {
		log.Fatalln("error writing record to file", err)
	}

	performances := GetPerformances(t, nodeNum, numMixnetNodes, electionDurationBase+time.Second*time.Duration(numMixnetNodes))
	// Using Write
	for _, p := range performances {
		row := []string{
			strconv.FormatInt(int64(numMixnetNodes), 10),
			strconv.FormatInt(p.Duration1.Microseconds(), 10),
			strconv.FormatInt(p.Duration2.Microseconds(), 10)}
		if err = w.Write(row); err != nil {
			log.Fatalln("error writing record to file", err)
		}
	}

}
