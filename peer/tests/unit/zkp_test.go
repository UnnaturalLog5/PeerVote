package unit

import (
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"go.dedis.ch/cs438/peer/impl"
)

func Test_ZKP_Dlog_True(t *testing.T) {
	curve := elliptic.P256()
	secret, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	fmt.Printf("In Test_ZKP_Dlog_True, secret length: %v\n", len(secret))

	if err != nil {

	}

	pPoint := impl.NewPoint(px, py)

	proof, err := impl.ProveDlog(secret, pPoint, curve)
	if err != nil {
	}

	isTrue, err := impl.VerifyDlog(proof)
	if err != nil {

	}

	require.Equal(t, isTrue, true)
}

/*
func Test_ZKP_Dlog_False(t *testing.T) {
	curve := elliptic.P256()
	secret, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	fmt.Printf("In Test_ZKP_Dlog_False, secret length: %v\n", len(secret))

	if err != nil {

	}

	//Point (1,1) is not on the curve
	px.SetUint64(1)
	py.SetUint64(1)

	pPoint := impl.NewPoint(px, py)

	proof, err := impl.ProveDlog(secret, pPoint, curve)
	if err != nil {

	}

	isTrue, err := impl.VerifyDlog(proof)
	if err != nil {

	}

	require.Equal(t, isTrue, true)
}

*/

func Test_ZKP_DlogEq_True(t *testing.T) {
	curve := elliptic.P256()
	secret, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	if err != nil {

	}

	pPoint := impl.NewPoint(px, py)

	_, bx, by, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	if err != nil {

	}

	bPointOther := impl.NewPoint(bx, by)

	pox, poy := elliptic.P256().ScalarMult(bPointOther.X, bPointOther.Y, secret)

	pPointOther := impl.NewPoint(pox, poy)

	proof, err := impl.ProveDlogEq(secret, pPoint, bPointOther, pPointOther, curve)
	if err != nil {

	}

	isTrue, err := impl.VerifyDlogEq(proof)
	if err != nil {

	}

	require.Equal(t, isTrue, true)
}

/*

func Test_ZKP_DlogEq_False(t *testing.T) {
	curve := elliptic.P256()
	secret, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	if err != nil {

	}

	pPoint := impl.NewPoint(px, py)

	_, bx, by, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	if err != nil {

	}

	bPointOther := impl.NewPoint(bx, by)

	pPointOther := impl.NewPoint(bx, by)

	proof, err := impl.ProveDlogEq(secret, pPoint, bPointOther, pPointOther, curve)
	if err != nil {

	}

	isTrue, err := impl.VerifyDlogEq(proof)
	if err != nil {

	}

	require.Equal(t, isTrue, false)
}
*/

func Test_ZKP_DlogSimulator(t *testing.T) {
	curve := elliptic.P256()
	curveParams := curve.Params()
	_, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	if err != nil {
		fmt.Printf("Error in key generation")
		return
	}

	transcript := impl.NewTranscript(impl.DLOG_OR_LABEL)

	pPoint := impl.NewPoint(px, py)

	fmt.Printf("Check if pPoint is on curve: %v\n", curve.IsOnCurve(px, py))
	pPointCompressed := elliptic.MarshalCompressed(curve, px, py)
	pPointNewX, pPointNewY := elliptic.UnmarshalCompressed(curve, pPointCompressed)
	fmt.Printf("Check if pPoint is on curve: %v\n", curve.IsOnCurve(pPointNewX, pPointNewY))

	label := []byte(impl.DLOG_OR_LABEL)

	transcript.AppendMessage(label, pPointCompressed)

	randSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		fmt.Printf("Error in randomness generation")
		return
	}

	//Build randomness generator for the commitment value
	trPRGbuilder := transcript.BuildRng()
	//trPRGbuilder.RekeyWitnessBytes(label, secret)
	trPRGbuilder.RekeyWitnessBytes(label, randSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(label)
	if err != nil {

	}
	//TODO: added for making sure the scalar is of order N
	challBytes := trPrg.GetRandomness(impl.SCALAR_SIZE)
	challScalar := new(big.Int).SetBytes(challBytes)
	challScalar = challScalar.Mod(challScalar, curveParams.N)

	cPointCompressed, challBytes, result := impl.SimulatorDlog(challScalar.Bytes(), trPrg, pPoint, curve)

	proof := impl.NewProofExtended(impl.DLOG_EQ_LABEL, curve, pPointCompressed, cPointCompressed, challBytes, result)

	isTrue := impl.VerifyDlogRelation(proof)

	require.Equal(t, isTrue, true)
}

func Test_ZKP_DlogOr_True(t *testing.T) {
	curve := elliptic.P256()
	secret, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	fmt.Printf("In Test_ZKP_Dlog_True, secret length: %v\n", len(secret))

	if err != nil {
		fmt.Printf("In Test_ZKP_Dlog_True, error in key generation")
		return
	}

	pPoint := impl.NewPoint(px, py)

	_, pox, poy, err := elliptic.GenerateKey(curve, cryptorand.Reader)

	secretOther := make([]byte, impl.SCALAR_SIZE)
	secretOther[31] = 1 //set other secret scalar to 1

	fmt.Printf("In Test_ZKP_DlogOr_True, length of secret is: %d \n", len(secret))
	fmt.Printf("In Test_ZKP_DlogOr_True, length of secretOther is: %d \n", len(secretOther))

	pPointOther := impl.NewPoint(pox, poy)

	secretBit := true

	fmt.Printf("In Test_ZKP_DlogOr_True, secret is: %v \n", secret)
	fmt.Printf("In Test_ZKP_DlogOr_True, secretOther is: %v \n", secretOther)

	fmt.Printf("In Test_ZKP_DlogOr_True, pPoint is: (%v, %v) \n", pPoint.X, pPoint.Y)
	fmt.Printf("In Test_ZKP_DlogOr_True, pPointOther is: (%v, %v) \n", pPointOther.X, pPointOther.Y)

	proof, err := impl.ProveDlogOr(secret, pPoint, secretOther, pPointOther, secretBit, curve)
	if err != nil {
		fmt.Printf("In Test_ZKP_Dlog_True, error in ProveDlogOr")
		return
	}

	isTrue, err := impl.VerifyDlogOr(proof)
	if err != nil {
		fmt.Printf("In Test_ZKP_Dlog_True, error in VerifyDlogOr")
		return
	}

	fmt.Printf("In Test_ZKP_DlogOr_True, verifier returns: %v \n", isTrue)

	require.Equal(t, isTrue, true)
}

func Test_ZKP_ElGamalReEncryption(t *testing.T) {
	curve := elliptic.P256()
	curveParams := curve.Params()
	pPoint := impl.Point{}

	_, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)
	pPoint.X = px
	pPoint.Y = py

	fmt.Printf("Test_ZKP_ReEncryption: Generated keypair\n")
	if err != nil {
		return
	}

	fmt.Printf("Test_ZKP_ReEncryption: Check if pPoint is on curve: %v\n", curve.IsOnCurve(pPoint.X, pPoint.Y))

	encScalar, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}
	reEncScalar, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	msg := make([]byte, 32)
	msg[31] = 1 //Msg is 1
	msgScalar := new(big.Int).SetBytes(msg)

	msgPoint := impl.Point{}
	msgPoint.X, msgPoint.Y = curve.ScalarBaseMult(msg)

	// fmt.Printf("Test_ZKP_ReEncryption: Check if msgPoint is on curve: %v\n", curve.IsOnCurve(msgPoint.X, msgPoint.Y))

	ctBefore := impl.ElGamalEncryption(curve, &pPoint, encScalar, msgScalar)

	// fmt.Printf("Test_ZKP_ReEncryption: ctBefore ct1 is: (%v,%v)\n", ctBeforeCt01.X, ctBeforeCt01.Y)
	// fmt.Printf("Test_ZKP_ReEncryption: ctBefore ct2 is: (%v,%v)\n", ctBeforeCt02.X, ctBeforeCt02.Y)

	ctAfter := impl.ElGamalReEncryption(curve, &pPoint, reEncScalar, ctBefore)

	checkScalar := new(big.Int).Add(encScalar, reEncScalar)
	checkScalar = checkScalar.Mod(checkScalar, curveParams.N)

	//ctCheck := impl.ElGamalCipherText{}
	ctCheck01Point := impl.Point{}
	ctCheck01Point.X, ctCheck01Point.Y = curve.ScalarBaseMult(checkScalar.Bytes())
	ctCheck02Point := impl.Point{}

	//ctCheck02Point.X, ctCheck02Point.Y = curve.ScalarMult(pPoint.X, pPoint.Y, checkScalar.Bytes())
	ctCheck02Point.X, ctCheck02Point.Y = curve.ScalarMult(pPoint.X, pPoint.Y, checkScalar.Bytes())
	ctCheck02Point.X, ctCheck02Point.Y = curve.Add(ctCheck02Point.X, ctCheck02Point.Y, msgPoint.X, msgPoint.Y)

	ctAfterCt01 := ctAfter.GetCt1()
	ctAfterCt02 := ctAfter.GetCt2()

	// fmt.Printf("Test_ZKP_ReEncryption: ctAfter ct1 is: (%v,%v)\n", ctAfterCt01.X, ctAfterCt01.Y)
	// fmt.Printf("Test_ZKP_ReEncryption: ctAfter ct2 is: (%v,%v)\n", ctAfterCt02.X, ctAfterCt02.Y)

	// fmt.Printf("Test_ZKP_ReEncryption: ctCheck01Point is: (%v,%v)\n", ctCheck01Point.X, ctCheck01Point.Y)
	// fmt.Printf("Test_ZKP_ReEncryption: ctCheck02Point is: (%v,%v)\n", ctCheck02Point.X, ctCheck02Point.Y)

	require.Equal(t, ctAfterCt01.X.Cmp(ctCheck01Point.X), 0)
	require.Equal(t, ctAfterCt01.Y.Cmp(ctCheck01Point.Y), 0)

	require.Equal(t, ctAfterCt02.X.Cmp(ctCheck02Point.X), 0)
	require.Equal(t, ctAfterCt02.Y.Cmp(ctCheck02Point.Y), 0)

}

func Test_ZKP_Shuffle_Simple(t *testing.T) {
	// Secret permutation for the proof
	curve := elliptic.P256()
	curveParams := curve.Params()
	pPoint := impl.Point{}
	//var secret []byte
	_, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)
	pPoint.X = px
	pPoint.Y = py

	if err != nil {
		return
	}
	permList := make([]uint32, 1)
	permList[0] = 0

	encRandomizerList := make([]*big.Int, 1)
	encRandomizerList[0], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	reEncRandomizerList := make([]*big.Int, 1)
	reEncRandomizerList[0], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	msg0 := new(big.Int).SetInt64(1)

	ctListBefore := make([]impl.ElGamalCipherText, 1)
	ctListBefore[0] = *impl.ElGamalEncryption(curve, &pPoint, encRandomizerList[0], msg0)

	ctListMed := make([]impl.ElGamalCipherText, 1)
	ctListMed[0] = *impl.ElGamalReEncryption(curve, &pPoint, reEncRandomizerList[0], &ctListBefore[0])

	ctListAfter := make([]impl.ElGamalCipherText, 1)
	ctListAfter[permList[0]] = ctListMed[0]

	shuffleInstance := impl.NewShuffleInstance(curve, pPoint, ctListBefore, ctListAfter)
	shuffleWitness := impl.NewShuffleWitness(permList, reEncRandomizerList)

	shuffleProof, err := impl.ProveShuffle(shuffleInstance, shuffleWitness)
	if err != nil {
		return
	}

	isTrue := impl.VerifyShuffle(shuffleProof)

	require.Equal(t, true, isTrue)
}

func Test_ZKP_Shuffle(t *testing.T) {
	// Secret permutation for the proof
	curve := elliptic.P256()
	curveParams := curve.Params()

	pPoint := impl.Point{}
	//var secret []byte
	_, px, py, err := elliptic.GenerateKey(curve, cryptorand.Reader)
	pPoint.X = px
	pPoint.Y = py

	if err != nil {
		return
	}

	/*
		permList := make([]uint32, 1)
		permList[0] = 0

		encRandomizerList := make([]*big.Int, 1)
		encRandomizerList[0], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
		if err != nil {
			return
		}

		reEncRandomizerList := make([]*big.Int, 1)
		reEncRandomizerList[0], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
		if err != nil {
			return
		}

	*/

	permList := make([]uint32, 3)
	permList[0] = 2
	permList[1] = 0
	permList[2] = 1

	encRandomizerList := make([]*big.Int, 3)
	encRandomizerList[0], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}
	encRandomizerList[1], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	encRandomizerList[2], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	reEncRandomizerList := make([]*big.Int, 3)
	reEncRandomizerList[0], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}
	reEncRandomizerList[1], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	reEncRandomizerList[2], err = cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return
	}

	msg0 := new(big.Int).SetInt64(1)

	msg1 := new(big.Int).SetInt64(1)
	msg2 := new(big.Int).SetInt64(1)

	ctListBefore := make([]impl.ElGamalCipherText, 3)
	ctListBefore[0] = *impl.ElGamalEncryption(curve, &pPoint, encRandomizerList[0], msg0)
	ctListBefore[1] = *impl.ElGamalEncryption(curve, &pPoint, encRandomizerList[1], msg1)
	ctListBefore[2] = *impl.ElGamalEncryption(curve, &pPoint, encRandomizerList[2], msg2)

	ctListMed := make([]impl.ElGamalCipherText, 3)
	ctListMed[0] = ctListBefore[permList[0]]
	ctListMed[1] = ctListBefore[permList[1]]
	ctListMed[2] = ctListBefore[permList[2]]

	ctListAfter := make([]impl.ElGamalCipherText, 3)
	ctListAfter[0] = *impl.ElGamalReEncryption(curve, &pPoint, reEncRandomizerList[0], &ctListMed[0])
	ctListAfter[1] = *impl.ElGamalReEncryption(curve, &pPoint, reEncRandomizerList[1], &ctListMed[1])
	ctListAfter[2] = *impl.ElGamalReEncryption(curve, &pPoint, reEncRandomizerList[2], &ctListMed[2])

	shuffleInstance := impl.NewShuffleInstance(curve, pPoint, ctListBefore, ctListAfter)
	shuffleWitness := impl.NewShuffleWitness(permList, reEncRandomizerList)

	shuffleProof, err := impl.ProveShuffle(shuffleInstance, shuffleWitness)
	if err != nil {
		return
	}

	isTrue := impl.VerifyShuffle(shuffleProof)

	require.Equal(t, true, isTrue)

}

func Test_MarshalPointList(t *testing.T) {
	curve := elliptic.P256()
	aPoint := impl.Point{}
	bPoint := impl.Point{}
	cPoint := impl.Point{}

	one := make([]byte, 32)
	one[31] = 1 //Scalar is 1

	two := make([]byte, 32)
	two[31] = 2 //Scalar is 2

	three := make([]byte, 32)
	three[31] = 3 //Scalar is 3

	aPoint.X, aPoint.Y = curve.ScalarBaseMult(one)
	bPoint.X, bPoint.Y = curve.ScalarBaseMult(two)
	cPoint.X, cPoint.Y = curve.ScalarBaseMult(three)

	aCompressed := elliptic.MarshalCompressed(curve, aPoint.X, aPoint.Y)
	bCompressed := elliptic.MarshalCompressed(curve, bPoint.X, bPoint.Y)
	cCompressed := elliptic.MarshalCompressed(curve, cPoint.X, cPoint.Y)

	pointList := make([]impl.Point, 3)
	pointList[0] = aPoint
	pointList[1] = bPoint
	pointList[2] = cPoint

	resultCompressed := impl.MarshalPointList(pointList, curve)

	listExpected := make([][]byte, 3)
	listExpected[0] = aCompressed
	listExpected[1] = bCompressed
	listExpected[2] = cCompressed

	for i := 0; i < 3; i++ {
		// fmt.Printf("In Test_MarshalPointList, Checking for entry %d, expected: %v\n", i, listExpected[i])
		// fmt.Printf("In Test_MarshalPointList, Checking for entry %d, actual: %v\n", i, resultCompressed[i])

		require.Equal(t, listExpected[i], resultCompressed[i])
	}

}

func Test_UnmarshalPointList(t *testing.T) {
	curve := elliptic.P256()
	aPoint := impl.Point{}
	bPoint := impl.Point{}
	cPoint := impl.Point{}

	one := make([]byte, 32)
	one[31] = 1 //Scalar is 1

	two := make([]byte, 32)
	two[31] = 2 //Scalar is 2

	three := make([]byte, 32)
	three[31] = 3 //Scalar is 3

	aPoint.X, aPoint.Y = curve.ScalarBaseMult(one)
	bPoint.X, bPoint.Y = curve.ScalarBaseMult(two)
	cPoint.X, cPoint.Y = curve.ScalarBaseMult(three)

	pointList := make([]impl.Point, 3)
	pointList[0] = aPoint
	pointList[1] = bPoint
	pointList[2] = cPoint

	resultCompressed := impl.MarshalPointList(pointList, curve)
	resultReturned := impl.UnmarshalPointList(resultCompressed, curve)

	for i := 0; i < 3; i++ {
		// fmt.Printf("In Test_MarshalPointList, Checking for entry %d, expected: %v\n", i, listExpected[i])
		// fmt.Printf("In Test_MarshalPointList, Checking for entry %d, actual: %v\n", i, resultCompressed[i])

		require.Equal(t, resultReturned[i].X, pointList[i].X)
		require.Equal(t, resultReturned[i].Y, pointList[i].Y)

	}

}

func Test_makePermutationMatrix(t *testing.T) {
	permList := make([]uint32, 3)
	permList[0] = 1
	permList[1] = 2
	permList[2] = 0

	resultExpected := make([][]uint32, 0)
	for i := 0; i < len(permList); i++ {
		row := make([]uint32, len(permList))
		resultExpected = append(resultExpected, row)
	}

	resultExpected[1][0] = 1
	resultExpected[2][1] = 1
	resultExpected[0][2] = 1

	result := impl.MakePermutationMatrix(permList)

	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			require.Equal(t, resultExpected[i][j], result[i][j])
		}
	}

}
