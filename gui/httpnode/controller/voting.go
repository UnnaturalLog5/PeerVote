package controller

import (
	"net/http"
	"text/template"
	"time"

	"github.com/rs/xid"
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

func (v voting) VotingHandler() http.HandlerFunc {
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

	choices := []types.Choice{
		{
			ChoiceID: xid.New().String(),
			Name:     "choice 1",
		},
		{
			ChoiceID: xid.New().String(),
			Name:     "choice 2",
		},
	}

	election := electionView{
		ElectionID:    "1",
		Initiator:     "127.0.0.1:1",
		Title:         "Election for Best Project",
		Description:   "We can vote on anything we like.",
		Choices:       choices,
		Expiration:    time.Now().Add(time.Second * 60).Format(time.ANSIC),
		MixnetServers: []string{"127.0.0.1:1"},
	}

	elections := []electionView{
		election,
		election,
	}

	viewData := struct {
		NodeAddr  string
		Servers   []string
		Elections []electionView
	}{
		NodeAddr:  v.conf.Socket.GetAddress(),
		Servers:   []string{"127.0.0.1:1", "127.0.0.1:2"},
		Elections: elections,
	}

	tmpl, err := template.New("html").ParseFiles(("httpnode/controller/voting.gohtml"))
	if err != nil {
		http.Error(w, "failed to parse template: "+err.Error(), http.StatusInternalServerError)
		return
	}

	tmpl.ExecuteTemplate(w, "voting.gohtml", viewData)
}
