package pedersendkg

import "math/big"

// PedersenSuite is a structure which contains all the
// parameters needed for establishing Pedersen DKG protocol.
// We assume for simplicity that the initial input of all peers
// is given in the peer's configuration.
// p and q are primes and g is a generator of subgroup Gq of
// order q in Zp, while t is the order of the polynomial f()
type PedersenSuite struct {
	p big.Int
	g big.Int
	q big.Int
	t big.Int
}
