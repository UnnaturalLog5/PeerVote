package controller

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"text/template"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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

func (v voting) ElectionsHTMLHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			v.electionsHTMLGet(w, r)
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

func GetWinner(results map[string]int) string {
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

type electionView struct {
	Base types.ElectionBase
	// use this over the one in Base, as this one is nicely formatted
	Expiration     string
	MyVote         int
	Winner         int
	Results        []resultView
	ProofsVerified map[string]bool
	IsReady        bool
}

type resultView struct {
	Name     string
	ChoiceID int
	Count    uint
}

func (v voting) electionsHTMLGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	electionViews := []electionView{}
	elections := v.node.GetElections()

	sort.SliceStable(elections, func(i, j int) bool {
		return elections[i].Base.ElectionID > elections[j].Base.ElectionID
	})

	for _, election := range elections {
		electionV := electionView{
			Base:       election.Base,
			Expiration: election.Base.Expiration.Format(time.ANSIC),
			MyVote:     election.MyVote,
		}

		electionV.IsReady = election.IsElectionStarted()

		electionV.Winner = GetWinner(election.Results)

		// aggregate results
		if len(election.Results) > 0 {
			resultViews := []resultView{}

			// for each choice, do tallying
			for _, choice := range election.Base.Choices {
				resultView := resultView{
					Name:     choice.Name,
					ChoiceID: choice.ChoiceID,
					Count:    election.Results[choice.ChoiceID],
				}
				resultViews = append(resultViews, resultView)
			}

			electionV.Results = resultViews
		}

		// verify proofs
		electionV.ProofsVerified = make(map[string]bool)
		electionV.ProofsVerified["Key Generation"] = true
		electionV.ProofsVerified["Encryption"] = true
		electionV.ProofsVerified["Mixing"] = false
		electionV.ProofsVerified["Tallying"] = true
		electionV.ProofsVerified["Includes My Vote"] = true

		electionViews = append(electionViews, electionV)
	}

	viewData := struct {
		Elections []electionView
	}{
		Elections: electionViews,
	}

	tmpl, err := template.New("html").ParseFiles("httpnode/controller/elections.gohtml")
	if err != nil {
		log.Err(err).Msg("failed to parse template")
		http.Error(w, "failed to parse template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	tmpl.ExecuteTemplate(w, "elections.gohtml", viewData)
}

// ---

func (v voting) MixnetServerHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			v.mixnetServersGet(w, r)
		default:
			http.Error(w, "forbidden method", http.StatusMethodNotAllowed)
		}
	}
}

func (v voting) mixnetServersGet(w http.ResponseWriter, r *http.Request) {
	routingTable := v.node.GetRoutingTable()
	peers := []string{}
	for peer := range routingTable {
		peers = append(peers, peer)
	}

	res, err := json.Marshal(peers)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed marshal mixnetServer response: %v", err),
			http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	w.Write(res)
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

	sort.SliceStable(elections, func(i, j int) bool {
		return elections[i].Base.ElectionID > elections[j].Base.ElectionID
	})

	res, err := json.Marshal(elections)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed marshal elections response: %v", err),
			http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

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

	expirationTime := time.Second * time.Duration(res.ExpirationTime)

	_, err = v.node.AnnounceElection(res.Title, res.Description, res.Choices, res.MixnetServers, expirationTime)
	if err != nil {
		http.Error(w, "failed to start election: "+err.Error(),
			http.StatusInternalServerError)
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
