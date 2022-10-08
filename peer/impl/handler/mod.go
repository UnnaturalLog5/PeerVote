package handler

import (
	"github.com/rs/zerolog/log"
	"go.dedis.ch/cs438/transport"
	"go.dedis.ch/cs438/types"
)

// implements registry.Exec
func ChatMessage(t types.Message, pkt transport.Packet) error {
	data := make([]byte, 1)
	err := pkt.Msg.Payload.UnmarshalJSON(data)
	if err != nil {
		return err
	}

	log.Info().Msgf("%v", data)

	return nil
}
