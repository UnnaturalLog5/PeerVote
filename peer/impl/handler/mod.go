package handler

import (
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// is type of registry.Exec
func ChatMessage(t types.Message, pkt transport.Packet) error {
	log.Info().Msgf("received message: '%v'", string(pkt.Msg.Payload))

	return nil
}
