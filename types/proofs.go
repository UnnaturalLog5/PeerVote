package types

import (
	"crypto/elliptic"
	"math/big"
)

type Proof struct {
	ProofType   string
	Curve       elliptic.Curve
	BPointOther []byte //basePointOther (for equality proof)
	PPoint      []byte //publicPoint
	PPointOther []byte //publicPointOther (for equality proof)
	CPoint      []byte //commitPoint
	CPointOther []byte //commitPointOhter (for equality proof)

	OtherBPointOther []byte //basePointOther (for equality proof)
	OtherPPoint      []byte //publicPoint
	OtherPPointOther []byte //publicPointOther (for equality proof)
	OtherCPoint      []byte //commitPoint
	OtherCPointOther []byte //commitPointOhter (for equality proof)
	VerifierChall    []byte //verifier's issued public coins
	ProverChall      []byte //prover's derived public coins for the first statement
	ProverChallOther []byte //prover's derived public coins for the second statement
	Result           big.Int
	ResultOther      big.Int
}

type ShuffleInstance struct {
	Curve    elliptic.Curve
	PPoint   Point
	CtBefore []ElGamalCipherText
	CtAfter  []ElGamalCipherText
}

type ShuffleWitness struct {
	PermList    []uint32
	RscalarList []big.Int
}

type ShuffleProof struct {
	ProofType          string
	Instance           ShuffleInstance
	VerifierChallList  [][]byte
	TPoint             []byte
	VPoint             []byte
	WPoint             []byte
	UPoint             []byte
	UPointListBytes    [][]byte
	GPrimePoint        []byte
	MPrimePoint        []byte
	TCapPointListBytes [][]byte
	VCapPointListBytes [][]byte
	VCapPoint          []byte
	WCapPointListBytes [][]byte
	WCapPoint          []byte
	SZeroScalar        big.Int
	SList              []big.Int
	DScalar            big.Int
}
