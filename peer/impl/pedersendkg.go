package impl

import (
	"crypto/rand"
	"math/big"
	"regexp"
	"strconv"
)

// PedersenDkg implements Pedersen’s Distributed Key Generation Protocol
// Reference: Topics in Cryptology – CT-RSA 2003
// The Cryptographers’ Track at the RSA Conference 2003
// San Francisco, CA, USA, April 13-17, 2003 Proceedings
// Threshold Cryptography, Secure Applications of Pedersen’s Distributed
// Key Generation Protocol (Rosario Gennaro, Stanislaw Jarecki,
// Hugo Krawczyk, and Tal Rabin)
func (n *node) PedersenDkg(mixnetServers []string) {
	// Choose a random polynomial f(z) over Zq of degree t:
	// f(z) = a0 + a1*z + ... + at*z^t
	a := n.GenerateRandomPolynomial()
	X := make([]big.Int, n.conf.PedersenSuite.T+1)
	for i := 0; i < len(a); i++ {
		X[i].Exp(&n.conf.PedersenSuite.G, &a[i], &n.conf.PedersenSuite.P)
	}
	f := func(id int) big.Int {
		sum := big.Int{}
		for i := 0; i < n.conf.PedersenSuite.T; i++ {
			tmp := new(big.Int).Mul(&a[i], new(big.Int).Exp(big.NewInt(int64(id)), big.NewInt(int64(id)), nil))
			sum.Add(&sum, tmp)
		}
		return sum
	}

	// Compute the share for each mixnetServer
	for _, mixnetServer := range mixnetServers {
		id := GetId(mixnetServer)
		share := f(id)
		n.sendDKGShareMessage(mixnetServer, share, X)
	}
}

func (n *node) sendDKGShareMessage(mixnetServer string, share big.Int, X []big.Int) {
	// todo
	/*
		log.Info().Str("peerAddr", n.myAddr).Msgf("sending DKG Share Message")

		dkgShareMessage := types.DKGShareMessage{}

		msg, err := marshalMessage(dkgShareMessage)
		if err != nil {
			return
		}

		err = n.Broadcast(msg)
		if err != nil {
			return
		}*/
}

// GenerateRandomPolynomial generates random polynomial of degree t
// over group Zq. Returns a slice which contains the coefficients of
// the corresponding polynomial.
func (n *node) GenerateRandomPolynomial() []big.Int {
	arr := make([]big.Int, n.conf.PedersenSuite.T+1)
	for i := 0; i < n.conf.PedersenSuite.T+1; i++ {
		arr[i] = *n.GenerateRandomBigInt()
	}
	return arr
}

// GenerateRandomBigInt generates a random value in Zq
func (n *node) GenerateRandomBigInt() *big.Int {
	//Generate cryptographically strong pseudo-random between 0 - max
	a, _ := rand.Int(rand.Reader, &n.conf.PedersenSuite.Q)
	return a
}

// GetId returns the ID of the mixnet server. In this case,
// the port number of the server's address is used.
func GetId(serverAddr string) int {
	r := regexp.MustCompile(`.*:(\d+)`)
	m := r.FindStringSubmatch(serverAddr)
	i, _ := strconv.Atoi(m[1])
	return i
}
