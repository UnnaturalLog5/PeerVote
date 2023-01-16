package unit

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cs438/peer/impl"
)

func Test_BSGS(t *testing.T) {
	curve := elliptic.P256()

	secret := new(big.Int).SetUint64(8)

	tpX, tpY := curve.ScalarBaseMult(secret.Bytes())

	targetPoint := impl.NewPoint(tpX, tpY)

	// targetPoint.X, targetPoint.Y =

	result, isFound := impl.BsgsFunction(&targetPoint, curve, 8)

	fmt.Printf("Result is %d\n", result.Uint64())

	require.Equal(t, true, isFound)
	require.Equal(t, 0, secret.Cmp(result))

}
