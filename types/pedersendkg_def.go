package types

import (
	"math/big"
	"time"
)

// PedersenSuite is a structure which contains all the
// parameters needed for establishing Pedersen DKG protocol.
// We assume for simplicity that the initial input of all peers
// is given in the peer's configuration.
// p and q are primes and g is a generator of subgroup Gq of
// order q in Zp, while t is the order of the polynomial f()
// Reference: Topics in Cryptology – CT-RSA 2003
// The Cryptographers’ Track at the RSA Conference 2003
// San Francisco, CA, USA, April 13-17, 2003 Proceedings
// Threshold Cryptography, Secure Applications of Pedersen’s Distributed
// Key Generation Protocol (Rosario Gennaro, Stanis9law Jarecki,
// Hugo Krawczyk, and Tal Rabin)
//type PedersenSuite struct {
//	P big.Int
//	G big.Int
//	Q big.Int
//}
//
//var DefaultPedersenSuite = PedersenSuite{
//	P: *big.NewInt(7), // Z*7
//	G: *big.NewInt(2),                   // <2>
//	Q: *big.NewInt(3),                   // <2> = {2, 4, 1}
//}

type Point struct {
	X big.Int
	Y big.Int
}

type DKGShareMessage struct {
	ElectionID     string
	MixnetServerID int
	Share          big.Int
	X              []Point
}

type DKGShareValidationMessage struct {
	ElectionID     string
	MixnetServerID int
	IsShareValid   bool
}

type ElectionReadyMessage struct {
	ElectionID       string
	QualifiedServers []int
}

type DKGRevealShareMessage struct {
	ElectionID          string
	Share               big.Int
	MixnetServerID      int
	ComplainingServerID int
}

type StartElectionMessage struct {
	ElectionID string
	Expiration time.Time
	PublicKey  Point
	Initiator  string
}
