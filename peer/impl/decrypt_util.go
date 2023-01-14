package impl

//NOTES:
// Check JP. Aumasson's crypto gotchas for const time arithmetic
// Switch to: https://pkg.go.dev/crypto/elliptic#P256 /or #P521
// The choice of the group is based on the RFC and standardization proposal
//https://datatracker.ietf.org/doc/html/draft-hao-schnorr-03#section-3.1
//https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf

import (
	"crypto/elliptic"
	"crypto/rand"
	"go.dedis.ch/cs438/types"
	"math/big"

	"golang.org/x/xerrors"
)

type BSGSPoint struct {
	X uint64
	Y uint64
}

// Each party generates its' decryption share based on the ciphertext pair, and broadcasts it
// together with the proof of the correct share generation (Chaum-Pedersen protocol)
func MakeDecryptShare(ciphertext *ElGamalCipherText, publicShare *types.Point, secretShare []byte) (*types.Point, *Proof, error) {
	curve := elliptic.P256()

	shareCtPointX, shareCtPointY := curve.ScalarMult(ciphertext.ct1.X, ciphertext.ct1.Y, secretShare)
	shareCtPoint := types.Point{}
	shareCtPoint.X = shareCtPointX
	shareCtPoint.Y = shareCtPointY

	bPointOther := types.Point{}
	bPointOther.X = ciphertext.ct1.X
	bPointOther.Y = ciphertext.ct1.Y
	proof, err := ProveDlogEq(secretShare, *publicShare, bPointOther, shareCtPoint, curve)
	if err != nil {
		return nil, nil, xerrors.Errorf("Error in Decrypt  partial, error in generating proof")
	}

	return &shareCtPoint, proof, nil

}

func RecoverVoteCount(cipherText *ElGamalCipherText, shareCtPointList []types.Point, participantNum int) (*big.Int, bool) {
	curve := elliptic.P256()
	curveParams := curve.Params()
	minusOne := new(big.Int).Sub(curveParams.N, big.NewInt(1))

	result := types.Point{}
	result.X.Set(cipherText.ct2.X)
	result.Y.Set(cipherText.ct2.Y)

	for _, p := range shareCtPointList {
		minusP := types.Point{}
		minusP.X, minusP.Y = curve.ScalarMult(p.X, p.Y, minusOne.Bytes())

		result.X, result.Y = curve.Add(result.X, result.Y, minusP.X, minusP.Y)
	}

	return BsgsFunction(&result, curve, participantNum)

}

// Shank's baby step-giant step algorithm, used for obtaining final vote tallying
func BsgsFunction(target *types.Point, curve elliptic.Curve, participantNum int) (*big.Int, bool) {

	table := make(map[BSGSPoint]int, 0)
	current := BSGSPoint{}

	// fmt.Printf("Target Point is (%d,%d):\n", target.X.Uint64(), target.Y.Uint64())

	zero := make([]byte, 32)
	//currX, currY := curve.ScalarBaseMult(zero)
	currX, currY := curve.ScalarBaseMult(zero)
	current.X = currX.Uint64()
	current.Y = currY.Uint64()

	// fmt.Printf("Initial Point is (%d,%d):\n", current.X, current.Y)

	table[current] = 0

	sq := new(big.Int).SetUint64(uint64(participantNum))
	sq = sq.Sqrt(sq)

	for i := 0; i <= participantNum; i++ {
		curr := new(big.Int).SetUint64(uint64(i))
		cX, cY := curve.ScalarBaseMult(curr.Bytes())

		current.X = cX.Uint64()
		current.Y = cY.Uint64()
		store := BSGSPoint{}
		// fmt.Printf("For dlog %d, Stored Point is (%d,%d):\n", i, current.X, current.Y)

		store.X = cX.Uint64()
		store.Y = cY.Uint64()
		table[store] = i
	}

	for i := 0; i <= participantNum; i++ {
		iInt := new(big.Int).SetUint64(uint64(i))
		prod := new(big.Int).Mul(sq, iInt)

		negProd := new(big.Int).Neg(prod)
		negProd = prod.Mod(negProd, curve.Params().N)

		prodBaseX, prodBaseY := curve.ScalarBaseMult(negProd.Bytes())

		challPointX, challPointY := curve.Add(target.X, target.Y, prodBaseX, prodBaseY)
		// fmt.Printf("For dlog %d, Stored Point is (%d,%d):\n", i, challPointX, challPointY)

		challP := BSGSPoint{
			X: challPointX.Uint64(),
			Y: challPointY.Uint64(),
		}

		val, ok := table[challP]

		valBigInt := new(big.Int).SetUint64(uint64(val))
		if ok {
			result := new(big.Int).Add(prod, valBigInt)
			result = result.Mod(result, curve.Params().N)

			// fmt.Printf("Result is: %d", result.Uint64())
			return result, true
		}
	}

	return nil, false
}

// Generate random permutation based on the
func GenerateRandPermutation(k int) ([]int, error) {
	permList := make([]int, k)
	for i := 0; i < k; i++ {
		permList[i] = i
	}

	// Fisher–Yates shuffle
	for i := k - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, xerrors.Errorf("Error in GenerateRandPermutation, %v", err)
		}
		j := int(jBig.Int64())
		if j != i {
			permList[i], permList[j] = permList[j], permList[i]
		}
	}

	return permList, nil
}
