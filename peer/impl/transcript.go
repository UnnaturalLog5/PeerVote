package impl

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/mimoo/StrobeGo/strobe"
)

const (
	SEC_LVL      = 128
	MERLIN_LABEL = "Merlin v1.0"
	RNG_LABEL    = "rng"
	DOMAIN_SEP   = "dom-sep"
	LABEL_TRUE   = true
	LABEL_FALSE  = false
)

type Transcript struct {
	strobe strobe.Strobe
	label  string
}

func NewTranscript(label string) Transcript {
	st := strobe.InitStrobe(MERLIN_LABEL, SEC_LVL)

	tr := Transcript{
		strobe: st,
		label:  label,
	}
	tr.AppendMessage([]byte(DOMAIN_SEP), []byte(label))
	return tr
}

// Label is metadata about the message, and is appended to the transcript
// Append prover's message to the trancript
func (tr *Transcript) AppendMessage(label, message []byte) {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(message)))
	dataLen := append(label, sizeBuffer...)

	tr.strobe.AD(true, dataLen)
	tr.strobe.AD(false, message)
}

func (tr *Transcript) BatchAppendMessages(label []byte, messageList [][]byte) {
	for _, msg := range messageList {
		tr.AppendMessage(label, msg)
	}
}

func (tr *Transcript) GetChallengeBytes(label []byte, outputLen int) []byte {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(outputLen))
	dataLen := append(label, sizeBuffer...)

	//Applies PRF to the transcript to get challenge
	tr.strobe.AD(true, dataLen)
	return tr.strobe.PRF(outputLen)
}

// Serves to obtain randomness (ex. the prover's side for blinding factors)
func (tr *Transcript) BuildRng() TranscriptRngBuilder {
	return TranscriptRngBuilder{
		strobe: *tr.strobe.Clone(),
	}
}

type TranscriptRngBuilder struct {
	strobe strobe.Strobe
}

func (trBuilder *TranscriptRngBuilder) RekeyWitnessBytes(label, witness []byte) {
	sizeBuffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBuffer[0:], uint32(len(witness)))
	dataLen := append(label, sizeBuffer...)

	trBuilder.strobe.AD(true, dataLen)
	trBuilder.strobe.KEY(witness)
}

func (trBuilder *TranscriptRngBuilder) BatchRekeyWitnessBytes(label []byte, witnessList [][]byte) {
	for _, msg := range witnessList {
		trBuilder.RekeyWitnessBytes(label, msg)
	}
}

func (trBuilder *TranscriptRngBuilder) Finalize(label []byte) (*TranscriptRng, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, err
	}

	trBuilder.strobe.AD(LABEL_TRUE, []byte(RNG_LABEL))
	trBuilder.strobe.KEY(bytes)

	return &TranscriptRng{
		strobe: *trBuilder.strobe.Clone(),
	}, nil
}

type TranscriptRng struct {
	strobe strobe.Strobe
}

func (trRng *TranscriptRng) GetRandomness(outputLen int) []byte {
	return trRng.strobe.PRF(outputLen)
}
