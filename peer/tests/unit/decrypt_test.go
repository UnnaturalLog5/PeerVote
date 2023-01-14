package unit

import (
	"crypto/elliptic"
	"fmt"
	"go.dedis.ch/cs438/types"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cs438/peer/impl"
)

func Test_BSGS(t *testing.T) {
	curve := elliptic.P256()

	secret := new(big.Int).SetUint64(8)
	targetPoint := types.Point{}

	targetPoint.X, targetPoint.Y = curve.ScalarBaseMult(secret.Bytes())

	result, isFound := impl.BsgsFunction(&targetPoint, curve, 8)

	fmt.Printf("Result is %d\n", result.Uint64())

	require.Equal(t, true, isFound)
	require.Equal(t, 0, secret.Cmp(result))

}
