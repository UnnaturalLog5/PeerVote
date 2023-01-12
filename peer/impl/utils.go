package impl

import (
	"crypto/rand"
	"math/big"
)

// contains checks whether elem of type T is contained in slice arr
func contains[T comparable](arr []T, elem T) bool {
	for _, s := range arr {
		if elem == s {
			return true
		}
	}
	return false
}

// GenerateRandomPolynomial generates random polynomial of degree t
// over group Zq. Returns a slice which contains the coefficients of
// the corresponding polynomial.
func GenerateRandomPolynomial(degree int, max *big.Int) []big.Int {
	arr := make([]big.Int, degree+1)
	for i := 0; i < degree+1; i++ {
		arr[i] = GenerateRandomBigInt(max)
	}
	return arr
}

// GenerateRandomBigInt generates a random value in Zq
func GenerateRandomBigInt(max *big.Int) big.Int {
	//Generate cryptographically strong pseudo-random between 0 - max
	a, _ := rand.Int(rand.Reader, max)
	return *a
}
