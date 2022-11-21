package impl

func (n *node) findPaxosConsensus(filename, metahash string) bool {
	if n.conf.TotalPeers == 1 {
		return true
	}

	// Phase 1
	for {
		// initialize round
		prepare, ok := n.multiPaxos.PreparePaxos(n.myAddr)
		if !ok {
			return false
		}

		// send prepare
		err := n.sendPaxosPrepareMessage(prepare)
		if err != nil {
			// todo error
			return false
		}

		// wait for promises
		// HandlePromise will notify this waiter
		nextPhase := n.multiPaxos.WaitForNextPhase(n.conf.PaxosProposerRetry)
		if nextPhase {
			break
		}
		// retry after timeout if not successful
	}

	// Phase 2
	for {
		propose := n.multiPaxos.ProposePaxos(filename, metahash)

		err := n.sendPaxosProposeMessage(propose)
		if err != nil {
			// todo log error
			return false
		}

		// wait for accepts
		// HandleAccept will notify this waiter
		nextPhase := n.multiPaxos.WaitForNextPhase(n.conf.PaxosProposerRetry)
		if nextPhase {
			break
		}
		// retry after timeout if not successful
	}

	return true
}
