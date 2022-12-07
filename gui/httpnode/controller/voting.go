package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/template"
	"time"

	"github.com/rs/zerolog"
	"go.dedis.ch/cs438/peer"
	"go.dedis.ch/cs438/types"
)

type voting struct {
	node peer.Peer
	conf peer.Configuration
	log  *zerolog.Logger
}

// NewBlockchain returns a new initialized blockchain.
func NewVoting(node peer.Peer, conf peer.Configuration, log *zerolog.Logger) voting {
	return voting{
		node: node,
		conf: conf,
		log:  log,
	}
}

func (v voting) VotingPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			v.votingGet(w, r)
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

type electionView struct {
	ElectionID    string
	Initiator     string
	Title         string
	Description   string
	Choices       []types.Choice
	Expiration    string
	MixnetServers []string
	Winner        string
}

func (v voting) votingGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// choices := []types.Choice{
	// 	{
	// 		ChoiceID: xid.New().String(),
	// 		Name:     "choice 1",
	// 	},
	// 	{
	// 		ChoiceID: xid.New().String(),
	// 		Name:     "choice 2",
	// 	},
	// }

	electionViews := []electionView{}

	elections := v.node.GetElections()
	for _, election := range elections {
		electionV := electionView{
			ElectionID:    election.Base.ElectionID,
			Initiator:     election.Base.Initiator,
			Title:         election.Base.Title,
			Description:   election.Base.Description,
			Choices:       election.Base.Choices,
			Expiration:    election.Base.Expiration.Format(time.ANSIC),
			MixnetServers: election.Base.MixnetServers,
		}

		electionViews = append(electionViews, electionV)
	}

	// election := electionView{
	// 	ElectionID:    "1",
	// 	Initiator:     "127.0.0.1:1",
	// 	Title:         "Election for Best Project",
	// 	Description:   "We can vote on anything we like.",
	// 	Choices:       choices,
	// 	Expiration:    time.Now().Add(time.Second * 60).Format(time.ANSIC),
	// 	MixnetServers: []string{"127.0.0.1:1"},
	// }

	// electionViews := []electionView{
	// 	election,
	// 	election,
	// }

	routingTable := v.node.GetRoutingTable()
	peers := []string{}
	for peer := range routingTable {
		peers = append(peers, peer)
	}

	viewData := struct {
		NodeAddr  string
		Servers   []string
		Elections []electionView
	}{
		NodeAddr:  v.conf.Socket.GetAddress(),
		Servers:   peers,
		Elections: electionViews,
	}

	tmpl, err := template.New("html").ParseFiles(("httpnode/controller/voting.gohtml"))
	if err != nil {
		http.Error(w, "failed to parse template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.ExecuteTemplate(w, "voting.gohtml", viewData)
}

// ---

func (v voting) ElectionsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			v.electionsGet(w, r)
		case http.MethodPost:
			v.electionsPost(w, r)
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

type startElectionArgument struct {
	Title          string
	Description    string
	Choices        []string
	MixnetServers  []string
	ExpirationTime uint
}

func (v voting) electionsGet(w http.ResponseWriter, r *http.Request) {
	elections := v.node.GetElections()

	res, err := json.Marshal(elections)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed marshal elections response: %v", err),
			http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	w.Write(res)
}

func (v voting) electionsPost(w http.ResponseWriter, r *http.Request) {
	// unmarshal argument
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	res := startElectionArgument{}
	err = json.Unmarshal(buf, &res)
	if err != nil {
		http.Error(w, "failed to unmarshal addPeerArgument: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	expirationTime := time.Now().Add(time.Duration(res.ExpirationTime))

	_, err = v.node.StartElection(res.Title, res.Description, res.Choices, res.MixnetServers, expirationTime)
	if err != nil {
		http.Error(w, fmt.Sprintf("%v, %v", string(buf), res)+err.Error(),
			http.StatusInternalServerError)
		// http.Error(w, "failed to start election: "+err.Error(),
		// 	http.StatusInternalServerError)
		return
	}
}

// ---

func (v voting) VoteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			v.votePost(w, r)
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

type voteArgument struct {
	ElectionID string
	ChoiceID   string
}

func (v voting) votePost(w http.ResponseWriter, r *http.Request) {
	// unmarshal argument
	buf, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body: "+err.Error(), http.StatusInternalServerError)
		return
	}

	res := voteArgument{}
	err = json.Unmarshal(buf, &res)
	if err != nil {
		http.Error(w, "failed to unmarshal addPeerArgument: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	err = v.node.Vote(res.ElectionID, res.ChoiceID)
	if err != nil {
		http.Error(w, "failed to cast vote: "+err.Error(),
			http.StatusInternalServerError)
		return
	}
}
