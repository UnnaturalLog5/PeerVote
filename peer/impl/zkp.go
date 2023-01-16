package impl

//NOTES:
// Check JP. Aumasson's crypto gotchas for const time arithmeti
// The choice of the group is based on the RFC and standardization proposal
//https://datatracker.ietf.org/doc/html/draft-hao-schnorr-03#section-3.1
//https://docs.zkproof.org/pages/standards/accepted-workshop4/proposal-sigma.pdf

//TODO LIST:
// 1. Generate new g-base, given an old one
// 2. Verification needs to check challenge bytes
import (
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"math/big"

	"go.dedis.ch/cs438/types"
	"golang.org/x/xerrors"
)

const (
	DLOG_LABEL       = "dlog_LABEL"
	DLOG_EQ_LABEL    = "dlog_EQ_LABEL"
	DLOG_OR_EQ_LABEL = "dlog_EQ_LABEL"
	DLOG_OR_LABEL    = "dlog_OR_LABEL"
	SHUFFLE_LABEL    = "shuffle_LABEL"
	SCALAR_SIZE      = 32
)

type Value []byte

func NewPoint(px, py *big.Int) types.Point {
	return types.Point{
		X: *px,
		Y: *py,
	}
}

func NewProof(proofType string) types.Proof {
	return types.Proof{
		ProofType: proofType,
	}
}

func NewProofExtended(proofType string, curve elliptic.Curve, pPoint, cPoint, challBytes []byte, result *big.Int) *types.Proof {
	return &types.Proof{
		ProofType:     proofType,
		Curve:         curve,
		PPoint:        pPoint,
		CPoint:        cPoint,
		VerifierChall: challBytes,
		Result:        *result,
	}
}

func NewShuffleInstance(curve elliptic.Curve, pPoint types.Point, ctBefore, ctAfter []types.ElGamalCipherText) *types.ShuffleInstance {
	return &types.ShuffleInstance{
		Curve:    curve,
		PPoint:   pPoint,
		CtBefore: ctBefore,
		CtAfter:  ctAfter,
	}
}

func NewShuffleWitness(permList []uint32, RscalarList []big.Int) *types.ShuffleWitness {
	return &types.ShuffleWitness{
		PermList:    permList,
		RscalarList: RscalarList,
	}
}

// The function computes the non-interactive proof of knowledge of the DLOG (a.k.a Schnorr's proof)
func ProveDlog(secret Value, pPoint types.Point, curve elliptic.Curve) (*types.Proof, error) {

	// Derive parameters of the elliptic curve
	curveParams := curve.Params()

	// Marshal the instance point in order to place it into the protocol transcript
	pPointCompressed := elliptic.MarshalCompressed(curve, &pPoint.X, &pPoint.Y)

	// Appends public info about the proof instance into the transcript
	proofTypeBytes := []byte(DLOG_LABEL)
	proof := NewProof(DLOG_LABEL)
	transcript := NewTranscript(DLOG_LABEL)
	transcript.AppendMessage(proofTypeBytes, pPointCompressed)

	// Begin derving commitment scalar

	// Generate random commitment seed using order of the group
	commitRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlog: %v", err)
	}

	// Build randomness generator for the commitment value
	trPRGbuilder := transcript.BuildRng()
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.ProofType), secret)
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.ProofType), commitRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlog: %v\n", err)
	}
	commitScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	//fmt.Printf("In ProveDlog, commitScalarBytes length: %v\n", len(commitScalarBytes))

	// Create commitment Point (cPoint=c*B, where B is the base point of the curve)
	cPointX, cPointY := curve.ScalarBaseMult(commitScalarBytes)

	// cPoint := NewPoint(cPointX, cPointY)

	cPointCompressed := elliptic.MarshalCompressed(curve, cPointX, cPointY)

	// Append derived cPoint to the protocol transcript
	transcript.AppendMessage(proofTypeBytes, cPointCompressed)

	// Derive public coins (challenge bytes) from the verifier based on the current
	// Trancript state
	challBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	//fmt.Printf("In VerifyDlog, challBytes: %v\n", challBytes)

	// Cast scalars as big.Ints
	secretScalar := new(big.Int).SetBytes(secret)
	challScalar := new(big.Int).SetBytes(challBytes)
	commitScalar := new(big.Int).SetBytes(commitScalarBytes)

	// Computes chall*x (as scalars mod N, where N is the order of the base point)
	blindedScalar := new(big.Int).Mod(new(big.Int).Mul(secretScalar, challScalar), curveParams.N)

	// Computes z=chall*x+c (as scalars mod N, where N is the order of the base point)
	result := new(big.Int).Mod(new(big.Int).Add(commitScalar, blindedScalar), curveParams.N)

	// Store into the proof
	proof.Curve = curve
	proof.PPoint = pPointCompressed
	proof.CPoint = cPointCompressed
	proof.VerifierChall = challBytes
	proof.Result = *result

	//fmt.Printf("In ProveDlog, pPoint: %v\n", proof.PPoint)
	//fmt.Printf("In ProveDlog, cPoint: %v\n", proof.CPoint)
	//fmt.Printf("In ProveDlog, result: %v\n", proof.Result)
	return &proof, nil
}

// Verifies the Schnorr's non-interactive proof of the knowledge of DLOG
func VerifyDlog(proof *types.Proof) (bool, error) {
	// Recreate the state of the transcript to get challenge scalar
	transcript := NewTranscript(proof.ProofType)
	proofTypeBytes := []byte(proof.ProofType)

	// Appends information about the proof instance
	transcript.AppendMessage(proofTypeBytes, proof.PPoint)

	// Appends the commitment point (the first message of the protocol)
	transcript.AppendMessage(proofTypeBytes, proof.CPoint)

	// Derives verifier's challenge based on the current transcript state
	challBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	checkBytes := checkChallBytes(challBytes, proof.VerifierChall)

	//fmt.Printf("In VerifyDlog, challBytes: %v\n", challBytes)

	// Create placeholder for the l.h.S and the r.h.S of the final check
	// point01 := types.Point{}
	// point02 := types.Point{}

	// Create placeholder for the instance Pand the commitment Point in the proof
	// pPoint := types.Point{}
	// cPoint := types.Point{}

	// Computes z*G, where G is the base point, and z (a.k.a result) is z=chall*x+c
	// This is what is "received" by the verifier from the prover
	point01X, point01Y := proof.Curve.ScalarBaseMult(proof.Result.Bytes())

	// Unmarshalls both pPoint = x*G and cPoint = c*G
	pPointX, pPointY := elliptic.UnmarshalCompressed(proof.Curve, proof.PPoint)
	cPointX, cPointY := elliptic.UnmarshalCompressed(proof.Curve, proof.CPoint)

	// Computes chall*x*G
	point02X, point02Y := proof.Curve.ScalarMult(pPointX, pPointY, challBytes)

	// Computes c*G+(chall*x)*G
	point02X, point02Y = proof.Curve.Add(point02X, point02Y, cPointX, cPointY)

	// Finally compare if the claimed value (point01) is equal to the actual value (point02)
	return checkBytes && point01X.Cmp(point02X) == 0 && point01Y.Cmp(point02Y) == 0, nil
}

// Proves that the two values P = x*G and P' = x*G' have the same DLOG x (a.k.a the Chaum-Pedersen proof)
// Essentially, this corresponds to running two Schnorr proofs in parallel.
// For details, see e.x: https://crypto.Stackexchange.com/questions/99262/chaum-pedersen-protocol
func ProveDlogEq(secret Value, pPoint types.Point, bPointOther types.Point, pPointOther types.Point,
	curve elliptic.Curve) (*types.Proof, error) {

	// Derive parameters of the elliptic curve
	curveParams := curve.Params()

	// Marshall proof instance to bytes
	pPointCompressed := elliptic.MarshalCompressed(curve, &pPoint.X, &pPoint.Y)
	bPointOtherCompressed := elliptic.MarshalCompressed(curve, &bPointOther.X, &bPointOther.Y)
	pPointOtherCompressed := elliptic.MarshalCompressed(curve, &pPointOther.X, &pPointOther.Y)

	proofTypeBytes := []byte(DLOG_EQ_LABEL)

	// Create placeholder for the proof
	proof := NewProof(DLOG_EQ_LABEL)

	// Initialize protocol's transcript
	transcript := NewTranscript(DLOG_EQ_LABEL)

	// Append proof instance values to the transcript
	transcript.AppendMessage(proofTypeBytes, bPointOtherCompressed)
	transcript.AppendMessage(proofTypeBytes, pPointCompressed)
	transcript.AppendMessage(proofTypeBytes, pPointOtherCompressed)

	// Begin deriving commitment scalar

	// Derive seed based on which the commitment scalar is derived
	commitRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogEq: %v", err)
	}

	// Build randomness generator for the commitment value
	trPRGbuilder := transcript.BuildRng()
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.ProofType), secret)
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.ProofType), commitRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {

	}

	commitScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)

	// Create placeholders for the two commitment points

	// Compute cPoint = c*G where G is the base point of the curve
	cPointX, cPointY := curve.ScalarBaseMult(commitScalarBytes)
	cPointCompressed := elliptic.MarshalCompressed(curve, cPointX, cPointY)

	// Compute cPoint = c*G' where G' is the base point of the curve (and G != G')
	cPointOtherX, cPointOtherY := curve.ScalarMult(&bPointOther.X, &bPointOther.Y, commitScalarBytes)
	cPointOtherCompressed := elliptic.MarshalCompressed(curve, cPointOtherX, cPointOtherY)

	// Append derived commitment points to the transcript
	transcript.AppendMessage(proofTypeBytes, cPointCompressed)
	transcript.AppendMessage(proofTypeBytes, cPointOtherCompressed)

	// Derive a public coin challenge based on the current state of the transcript
	challBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	// Cast scalars as big.Ints
	secretScalar := new(big.Int).SetBytes(secret)
	commitScalar := new(big.Int).SetBytes(commitScalarBytes)
	challScalar := new(big.Int).SetBytes(challBytes)

	// Computes chall*x (mod N, where N is the order of the base point)
	blindedScalar := new(big.Int).Mod(new(big.Int).Mul(secretScalar, challScalar), curveParams.N)

	// Computes z=c-chall*x (mod N, where N is the order of the base point)
	result := new(big.Int).Mod(new(big.Int).Sub(commitScalar, blindedScalar), curveParams.N)

	// Store the results into the proof structure
	proof.Curve = curve
	proof.BPointOther = bPointOtherCompressed
	proof.PPoint = pPointCompressed
	proof.PPointOther = pPointOtherCompressed
	proof.CPoint = cPointCompressed
	proof.CPointOther = cPointOtherCompressed
	proof.VerifierChall = challBytes
	proof.Result = *result

	return &proof, nil
}

// Verifies that the two values P = x*G and P' = x*G' have the same DLOG x (a.k.a the Chaum-Pedersen proof)
func VerifyDlogEq(proof *types.Proof) (bool, error) {

	// Recreate the state of the transcript to get challenge scalar
	transcript := NewTranscript(proof.ProofType)
	proofTypeBytes := []byte(proof.ProofType)

	// Appends information about the proof instance
	transcript.AppendMessage(proofTypeBytes, proof.BPointOther)
	transcript.AppendMessage(proofTypeBytes, proof.PPoint)
	transcript.AppendMessage(proofTypeBytes, proof.PPointOther)

	// Append commitment points (the first message pair of the protocol)
	transcript.AppendMessage(proofTypeBytes, proof.CPoint)
	transcript.AppendMessage(proofTypeBytes, proof.CPointOther)

	// Generate public challege from the current state of the transcript
	challBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)
	checkBytes := checkChallBytes(challBytes, proof.VerifierChall)

	// Begin deriving components for checking if P = x*G

	// Derive P from the proof
	// pPoint := types.Point{}
	pPointX, pPointY := elliptic.UnmarshalCompressed(proof.Curve, proof.PPoint)

	// Compute chall*P
	// gAddend01 := types.Point{}
	gAddend01X, gAddend01Y := proof.Curve.ScalarMult(pPointX, pPointY, challBytes)

	// Compute z*G (where z=c-chall*x)
	// gAddend02 := types.Point{}
	gAddend02X, gAddend02Y := proof.Curve.ScalarBaseMult(proof.Result.Bytes())

	// Compute chall*P + z*G
	// resultFirst := types.Point{}
	resultFirstX, resultFirstY := proof.Curve.Add(gAddend01X, gAddend01Y, gAddend02X, gAddend02Y)

	// Begin deriving components for checking if P=x*G

	// gPrimeAddend01 := types.Point{}
	// pPointOther := types.Point{}
	pPointOtherX, pPointOtherY := elliptic.UnmarshalCompressed(proof.Curve, proof.PPointOther)
	gPrimeAddend01X, gPrimeAddend01Y := proof.Curve.ScalarMult(pPointOtherX, pPointOtherY, challBytes)

	// Checks for the other pair (corresponds to checks for G')
	// bPointOther := types.Point{}
	// gPrimeAddend02 := types.Point{}
	bPointOtherX, bPointOtherY := elliptic.UnmarshalCompressed(proof.Curve, proof.BPointOther)
	gPrimeAddend02X, gPrimeAddend02Y := proof.Curve.ScalarMult(bPointOtherX, bPointOtherY, proof.Result.Bytes())

	// resultSecond := types.Point{}
	resultSecondX, resultSecondY := proof.Curve.Add(gPrimeAddend01X, gPrimeAddend01Y, gPrimeAddend02X, gPrimeAddend02Y)

	// cPoint := types.Point{}
	cPointX, cPointY := elliptic.UnmarshalCompressed(proof.Curve, proof.CPoint)

	// cPointOther := types.Point{}
	cPointOtherX, cPointOtherY := elliptic.UnmarshalCompressed(proof.Curve, proof.CPointOther)
	return checkBytes &&
		cPointX.Cmp(resultFirstX) == 0 && cPointY.Cmp(resultFirstY) == 0 &&
		cPointOtherX.Cmp(resultSecondX) == 0 && cPointOtherY.Cmp(resultSecondY) == 0, nil

}

// Computes the non-interactive zero-knowledge proof that secret x is the DLOG of either P or P'
// The proof generation can be parsed into the two cases:
// 1. For the true case: Run the regular Schnorr protocol
// 2. For the fake case: Use simulator to create an accepting transcript
func ProveDlogOr(secret Value, pPoint types.Point, secretOther Value, pPointOther types.Point, secretBit bool, curve elliptic.Curve) (*types.Proof, error) {

	curveParams := curve.Params()
	var trueSecret Value
	var truepPoint types.Point
	var fakepPoint types.Point
	if secretBit {
		trueSecret = secret
		truepPoint = pPoint
		fakepPoint = pPointOther
	} else {
		trueSecret = secretOther
		truepPoint = pPointOther
		fakepPoint = pPoint
	}

	// //fmt.Printf("In ProveDlogOr, trueSecret is: %v \n ", trueSecret)
	// //fmt.Printf("In ProveDlogOr, truepPoint is: (%v, %v) \n ", pPoint.X, pPoint.Y)
	// //fmt.Printf("In ProveDlogOr, fakepPoint is: (%v, %v) \n ", pPointOther.X, pPointOther.Y)

	// Marshall the information about the proof instance
	pPointCompressed := elliptic.MarshalCompressed(curve, &pPoint.X, &pPoint.Y)
	pPointOtherCompressed := elliptic.MarshalCompressed(curve, &pPointOther.X, &pPointOther.Y)

	// Create the placeholder for the proof
	proofTypeBytes := []byte(DLOG_OR_LABEL)
	proof := NewProof(DLOG_OR_LABEL)

	// Initialize protocol's transcript
	transcript := NewTranscript(DLOG_OR_LABEL)

	// Append public proof instance to the transcript
	transcript.AppendMessage(proofTypeBytes, pPointCompressed)
	transcript.AppendMessage(proofTypeBytes, pPointOtherCompressed)

	// For the true case: Derive randomness for the commitment scalar generation
	trueRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogOR: %v", err)
	}

	// Build randomness generator out of randomness for the commitment value
	trPRGbuilder := transcript.BuildRng()
	trPRGbuilder.RekeyWitnessBytes(proofTypeBytes, trueSecret)
	trPRGbuilder.RekeyWitnessBytes(proofTypeBytes, trueRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogOR: %v", err)
	}

	// Derive commitment scalar based on the current state of the transcript
	commitScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)

	// For the true case: Generate cPoint =  c*G, where G is the base point
	cPoint := types.Point{}
	cPointX, cPointY := curve.ScalarBaseMult(commitScalarBytes)
	cPoint.X = *cPointX
	cPoint.Y = *cPointY
	cPointCompressed := elliptic.MarshalCompressed(curve, &cPoint.X, &cPoint.Y)

	// For the fake case: Derive random challenge for the simulation using the transcript
	simRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogOR: %v", err)
	}

	trPRGbuilder = transcript.BuildRng()
	trPRGbuilder.RekeyWitnessBytes(proofTypeBytes, simRandSeed.Bytes())
	trPRG, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogOR: %v", err)
	}

	// For the fake case: Generate fake challenge bytes (As if they came from the verifier)
	fakeChallBytes := trPRG.GetRandomness(SCALAR_SIZE)
	//fmt.Printf("In ProveDlogOr, fakeChallBytes: %v\n", fakeChallBytes)

	// Use simulator for the proof ot the DLOG to create the fake (but accepting transcirpt)
	fakeCPointCompressed, fakeChallBytes, fakeResult := SimulatorDlog(fakeChallBytes, trPRG, fakepPoint, curve)

	// Append commitment points for both cases to the transcript
	if secretBit {
		transcript.AppendMessage(proofTypeBytes, cPointCompressed)
		transcript.AppendMessage(proofTypeBytes, fakeCPointCompressed)
	} else {
		transcript.AppendMessage(proofTypeBytes, fakeCPointCompressed)
		transcript.AppendMessage(proofTypeBytes, cPointCompressed)
	}

	// Generate verifier's challenge bytes from the current transcript state
	verifierChallBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	// Derive challenge bytes for the true case  by xoring the chall bytes received
	// from the verifier with the fake challenge bytes
	trueChallBytes := make([]byte, len(verifierChallBytes))
	for i, val := range verifierChallBytes {
		trueChallBytes[i] = val ^ fakeChallBytes[i]
	}
	//fmt.Printf("In ProveDlogOr, trueChallBytes: %v\n", trueChallBytes)

	// Cast the secret x as a scalar
	trueSecretScalar := new(big.Int).SetBytes(trueSecret)

	// Cast the commitment c as a scalar
	trueCommitScalar := new(big.Int).SetBytes(commitScalarBytes)

	// Cast chall as scalar (verifier's public coins)
	trueChallScalar := new(big.Int).SetBytes(trueChallBytes)

	// Compute x*chall (mod N, where N is the order of base point)
	trueBlindedScalar := new(big.Int).Mod(new(big.Int).Mul(trueSecretScalar, trueChallScalar), curveParams.N)

	// Finish blinded scalar
	trueResult := new(big.Int).Mod(new(big.Int).Add(trueCommitScalar, trueBlindedScalar), curveParams.N)

	truepPointCompressed := elliptic.MarshalCompressed(curve, &truepPoint.X, &truepPoint.Y)
	fakepPointCompressed := elliptic.MarshalCompressed(curve, &fakepPoint.X, &fakepPoint.Y)

	if secretBit {
		proof.Curve = curve
		proof.Result = *trueResult
		proof.ResultOther = *fakeResult
		proof.CPoint = cPointCompressed
		proof.CPointOther = fakeCPointCompressed
		proof.PPoint = truepPointCompressed
		proof.PPointOther = fakepPointCompressed
		proof.VerifierChall = verifierChallBytes
		proof.ProverChall = trueChallBytes
		proof.ProverChallOther = fakeChallBytes

	} else {
		proof.Curve = curve
		proof.Result = *fakeResult
		proof.ResultOther = *trueResult
		proof.CPoint = fakeCPointCompressed
		proof.CPointOther = cPointCompressed
		proof.PPoint = fakepPointCompressed
		proof.PPointOther = truepPointCompressed
		proof.VerifierChall = verifierChallBytes
		proof.ProverChall = fakeChallBytes
		proof.ProverChallOther = trueChallBytes
	}

	return &proof, nil
}

// Verifies that one of the two proof instances satisfies the DLOG relation
// (a.k.a the OR-proof for the DLOG relation)
func VerifyDlogOr(proof *types.Proof) (bool, error) {

	proofTypeBytes := []byte(DLOG_OR_LABEL)

	// Initialize protocol transcript
	transcript := NewTranscript(DLOG_OR_LABEL)

	// Append public parameters corresponding to the
	transcript.AppendMessage(proofTypeBytes, proof.PPoint)
	transcript.AppendMessage(proofTypeBytes, proof.PPointOther)

	// Append the commitment points to the trasncript
	transcript.AppendMessage(proofTypeBytes, proof.CPoint)
	transcript.AppendMessage(proofTypeBytes, proof.CPointOther)

	//fmt.Printf("In VerifyDlog, proverChall: %v\n", proof.ProverChall)
	//fmt.Printf("In VerifyDlog, proverChallOther: %v\n", proof.ProverChallOther)
	//fmt.Printf("In VerifyDlog, PROOF verifierChall: %v\n", proof.VerifierChall)

	// Derive challenge bytes based on the state of the current transcript
	verifierChallBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)
	//fmt.Printf("In VerifyDlog, DERIVED verifierChall: %v\n", verifierChallBytes)

	// Begin checking if the verifier challenge is correctly derived
	checkBytesXor := true
	for i, val := range proof.VerifierChall {
		// 1. Check if the xor of two byte streams corresponds to the byte stream from verifier
		checkBytesXor = checkBytesXor && (val == (proof.ProverChall[i] ^ proof.ProverChallOther[i]))

		// 2. Check if the derived verifier stream from the transcript and the actual stream are equal
		checkBytesXor = checkBytesXor && (val == verifierChallBytes[i])
	}

	// Create two proof instances which need to be checked

	proof01 := types.Proof{}
	proof01.Curve = proof.Curve
	proof01.PPoint = proof.PPoint
	proof01.CPoint = proof.CPoint
	proof01.VerifierChall = proof.ProverChall
	proof01.Result = proof.Result

	proof02 := types.Proof{}
	proof02.Curve = proof.Curve
	proof02.PPoint = proof.PPointOther
	proof02.CPoint = proof.CPointOther
	proof02.VerifierChall = proof.ProverChallOther
	proof02.Result = proof.ResultOther

	// Both proof instances need to satisfy the DLOG (Schnorr's proof check)
	res01 := VerifyDlogRelation(&proof01)
	res02 := VerifyDlogRelation(&proof02)

	//fmt.Printf("In VerifyDlogOr, checkBytesXor result %v\n", checkBytesXor)
	//fmt.Printf("In VerifyDlogOr, VerifyDlogRelation for proof01 result: %v\n", res01)
	//fmt.Printf("In VerifyDlogOr, VerifyDlogRelation for proof02 result %v\n", res02)

	// Return the AND of all the checks as a result
	return checkBytesXor && res01 && res02, nil
}

// Based on the choise of the chall, derives the fake simulated (a.k.a) fake transcript for the Schnorr's proof
// Utilizes the c-simultability property of the Sigma protocols
func SimulatorDlog(challBytes []byte, trPRG *TranscriptRng, pPoint types.Point, curve elliptic.Curve) ([]byte, []byte, *big.Int) {

	curveParams := curve.Params()

	// Derive scalar z
	blindBytes := trPRG.GetRandomness(SCALAR_SIZE)
	blindScalar := new(big.Int).SetBytes(blindBytes)
	blindScalar = blindScalar.Mod(blindScalar, curveParams.N)

	// Compute z*G
	blindPoint := types.Point{}
	//fmt.Printf("In SimulatorDlog, multiplying base point with value %v\n", blindScalar.Bytes())
	blindPointX, blindPointY := curve.ScalarBaseMult(blindScalar.Bytes())

	blindPoint.X, blindPoint.Y = *blindPointX, *blindPointY

	// Compute -chall*P, where P is the point from the proof intance
	minusOneScalar := new(big.Int).Sub(curveParams.N, big.NewInt(1))
	challScalar := new(big.Int).SetBytes(challBytes)

	// Create placeholder for the -chall*P point
	// challpPoint := types.Point{}

	// First compute -P given P
	challpPointX, challpPointY := curve.ScalarMult(&pPoint.X, &pPoint.Y, minusOneScalar.Bytes())

	// challpPoint.X, challpPoint.Y = *challpPointX, *challpPointY

	// Then computer chall*(-P)
	challpPointX, challpPointY = curve.ScalarMult(challpPointX, challpPointY, challScalar.Bytes())

	// Finally compute the the first message (in the original proof c*G)
	// As: c*G = z*G - chall*P
	// cPoint := types.Point{}
	cPointX, cPointY := curve.Add(&blindPoint.X, &blindPoint.Y, challpPointX, challpPointY)
	cPointCompressed := elliptic.MarshalCompressed(curve, cPointX, cPointY)

	//fmt.Printf("In SimulatorDlog, BlindScalar value %v\n", blindScalar.Bytes())
	//fmt.Printf("In SimulatorDlog, Is blindPoint on curve: %v\n", curve.IsOnCurve(blindPoint.X, blindPoint.Y))
	//fmt.Printf("In SimulatorDlog, Is challpPoint on curve: %v\n", curve.IsOnCurve(challpPoint.X, challpPoint.Y))
	//fmt.Printf("In SimulatorDlog, Is cPoint on curve: %v\n", curve.IsOnCurve(cPoint.X, cPoint.Y))

	//fmt.Printf("In SimulatorDlog, blindPoint coordinates: (%v, %v) \n", blindPoint.X, blindPoint.Y)
	//fmt.Printf("In SimulatorDlog, challpPoint coordinates: (%v, %v) \n", challpPoint.X, challpPoint.Y)
	//fmt.Printf("In SimulatorDlog, cPoint coordinates: (%v, %v) \n", cPoint.X, cPoint.Y)

	//fmt.Printf("In SimulatorDlog, cPointCompressed %v\n", cPointCompressed)
	//fmt.Printf("In SimulatorDlog, challBytes %v\n", challBytes)
	//fmt.Printf("In SimulatorDlog, blindScalar %v\n", blindScalar.Bytes())
	return cPointCompressed, challBytes, blindScalar
}

// Verifies that the values stored in the proof satisfies the DLOG (Schnorr's) relation
func VerifyDlogRelation(proof *types.Proof) bool {
	curve := proof.Curve

	//fmt.Printf("In VerifyDlogRelation, cPointCompressed %v\n", proof.CPoint)
	//fmt.Printf("In VerifyDlogRelation, challBytes %v\n", proof.VerifierChall)
	//fmt.Printf("In VerifyDlogRelation, blindScalar %v\n", proof.Result.Bytes())

	//fmt.Printf("In VerifyDlogRelation result scalar: %v\n", proof.Result.Bytes())

	//fmt.Printf("In VerifyDlogRelation, multiplying base point with value %v\n", proof.Result.Bytes())

	// Computes z*G, which acts as the l.h.S of the check
	pointlhsX, pointlhsY := curve.ScalarBaseMult(proof.Result.Bytes())

	// Cast the proof instance and the commitment point as Point structs
	pPointX, pPointY := elliptic.UnmarshalCompressed(curve, proof.PPoint)
	cPointX, cPointY := elliptic.UnmarshalCompressed(curve, proof.CPoint)

	//Compute the r.h.S as a chall*P+cPoint
	pointrhsX, pointrhsY := proof.Curve.ScalarMult(pPointX, pPointY, proof.VerifierChall)
	pointrhsX, pointrhsY = proof.Curve.Add(pointrhsX, pointrhsY, cPointX, cPointY)

	//fmt.Printf("In VerifyDlogRelation, Comparing X points %v\n", pointlhs.X.Cmp(pointrhs.X) == 0)
	//fmt.Printf("In VerifyDlogRelation, Comparing Y points %v\n", pointlhs.Y.Cmp(pointrhs.Y) == 0)

	//Finally, check if the l.h.S and the r.h.S match
	return pointlhsX.Cmp(pointrhsX) == 0 && pointlhsY.Cmp(pointrhsY) == 0
}

func Verify(proof *types.Proof) (bool, error) {

	var result bool
	var err error
	switch proof.ProofType {
	case DLOG_LABEL:
		result, err = VerifyDlog(proof)
	case DLOG_EQ_LABEL:
		result, err = VerifyDlogEq(proof)
	case DLOG_OR_LABEL:
		result, err = VerifyDlogOr(proof)
	default:
		result = false
		err = xerrors.Errorf("Error in verify, wrong proof type")
	}

	return result, err
}

// Computes the proof of the Sako's verifiable shuffle
// Effectively, it acts as  4 Sigma proofs run in parallel, which are
// 1.
func ProveShuffle(instance *types.ShuffleInstance, witness *types.ShuffleWitness) (*types.ShuffleProof, error) {
	curveParams := instance.Curve.Params()
	proofTypeBytes := []byte(SHUFFLE_LABEL)

	transcript := NewTranscript(SHUFFLE_LABEL)

	// Initialize transcript with the proof instance (which consists)
	pPointCompressed := elliptic.MarshalCompressed(instance.Curve, &instance.PPoint.X, &instance.PPoint.Y)

	// If a ciphertext consists of a pair ct=(ct_1, ct_2), then these are
	// The lists of ct_2,s for each ciphertext
	reEncBeforeList := MakeReencList(instance.CtBefore)
	reEncAfterList := MakeReencList(instance.CtAfter)

	// If a ciphertext consists of a pair ct=(ct_1, ct_2), then these are
	// The lists of ct_2,s for each ciphertext
	ctMsgBeforeList := MakeCtMsgList(instance.CtBefore)
	ctMsgAfterList := MakeCtMsgList(instance.CtAfter)

	reEncBeforeByteList := MarshalPointList(reEncBeforeList, instance.Curve)
	reEncAfterByteList := MarshalPointList(reEncAfterList, instance.Curve)
	ctMsgBeforeByteList := MarshalPointList(ctMsgBeforeList, instance.Curve)
	ctMsgAfterByteList := MarshalPointList(ctMsgAfterList, instance.Curve)

	// Append proof instance parameters to the transcript
	transcript.BatchAppendMessages(proofTypeBytes, reEncBeforeByteList)
	transcript.BatchAppendMessages(proofTypeBytes, reEncAfterByteList)
	transcript.BatchAppendMessages(proofTypeBytes, ctMsgBeforeByteList)
	transcript.BatchAppendMessages(proofTypeBytes, ctMsgAfterByteList)
	transcript.AppendMessage(proofTypeBytes, pPointCompressed)

	// Prover STEP 01: Derive randomness for the prover's masking scalars
	commitRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveReEncListShuffle: %v\n", err)
	}

	byteRandList, err := MarshalBIntList(witness.RscalarList)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveReEncListShuffle: %v\n", err)
	}
	bytePermList := MarshalUIntList(witness.PermList)

	// Build randomness generator for the commitment value
	trPRGbuilder := transcript.BuildRng()
	trPRGbuilder.BatchRekeyWitnessBytes(proofTypeBytes, byteRandList)
	trPRGbuilder.BatchRekeyWitnessBytes(proofTypeBytes, bytePermList)
	trPRGbuilder.RekeyWitnessBytes(proofTypeBytes, commitRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveReEncListShuffle: %v\n", err)
	}

	// Prover STEP 01: Derive prover's masking scalars
	tauScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	thetaScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	sigmaScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	lambdaScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	phiScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)

	//fmt.Printf("In ProveShuffle, public point is: (%v,%v)\n", instance.PPoint.X, instance.PPoint.Y)
	phiScalar := new(big.Int).SetBytes(phiScalarBytes)
	phiList := [][]byte{}

	for i := 0; i < len(witness.PermList); i++ {
		phiList = append(phiList, trPrg.GetRandomness(SCALAR_SIZE))
	}

	lambdaList := [][]byte{}
	for i := 0; i < len(witness.PermList); i++ {
		lambdaList = append(phiList, trPrg.GetRandomness(SCALAR_SIZE))
	}

	// Prover STEP 01: do the following
	//Compute T=\tau*G
	//Compute v=\theta*G
	//Compute w=\sigma*G
	//Compute u=\lambda*G

	tPointX, tPointY := instance.Curve.ScalarBaseMult(tauScalarBytes)
	vPointX, vPointY := instance.Curve.ScalarBaseMult(thetaScalarBytes)
	wPointX, wPointY := instance.Curve.ScalarBaseMult(sigmaScalarBytes)
	uPointX, uPointY := instance.Curve.ScalarBaseMult(lambdaScalarBytes)

	//fmt.Printf("In ProveShuffle, tauScalar is: %v\n", new(big.Int).SetBytes(tauScalarBytes))
	//fmt.Printf("In ProveShuffle, thetaScalar is: %v\n", new(big.Int).SetBytes(thetaScalarBytes))
	//fmt.Printf("In ProveShuffle, sigmaScalar is: %v\n", new(big.Int).SetBytes(sigmaScalarBytes))
	//fmt.Printf("In ProveShuffle, lambdaScalar is: %v\n", new(big.Int).SetBytes(lambdaScalarBytes))

	//fmt.Printf("In ProveShuffle, tPoint result is (%v,%v)\n", tPoint.X, tPoint.Y)
	//fmt.Printf("In ProveShuffle, vPoint result is (%v,%v)\n", vPoint.X, vPoint.Y)
	//fmt.Printf("In ProveShuffle, wPoint result is (%v,%v)\n", wPoint.X, wPoint.Y)
	//fmt.Printf("In ProveShuffle, uPoint result is (%v,%v)\n", uPoint.X, uPoint.Y)

	// Prover STEP 01: Compute U_i = \lambda_i * G, where G is the base point
	uPointList := make([]types.Point, 0)
	for i := 0; i < len(witness.PermList); i++ {
		uP := types.Point{}
		//fmt.Printf("In ProveShuffle, for index %d, lambdaScalar[i] is: %v\n", i, new(big.Int).SetBytes(lambdaList[i]))
		uPX, uPY := instance.Curve.ScalarBaseMult(lambdaList[i])
		//fmt.Printf("In ProveShuffle, for index %d uPoint result is (%v,%v)\n", i, uP.X, uP.Y)

		uP.X = *uPX
		uP.Y = *uPY
		uPointList = append(uPointList, uP)
	}

	// Prover STEP 01: Compute G'=\phi*G + \sum_i \phi_i*ct_{i,1}

	//First compute the \phi*G

	gPrimePointX, gPrimePointY := instance.Curve.ScalarBaseMult(phiScalarBytes)
	//fmt.Printf("In ProveShuffle, PhiScalar is: %v\n", new(big.Int).SetBytes(phiScalarBytes))
	//fmt.Printf("In ProveShuffle, gPrimePoint, initial result is (%v,%v)\n", gPrimePoint.X, gPrimePoint.Y)

	// Then compute the sum by calcluating addends and add them at each step to the running value of G'
	for i := 0; i < len(witness.PermList); i++ {
		// addend := types.Point{}
		//fmt.Printf("In ProveShuffle, for i: %d, PhiScalar[i] is: %v\n", i, new(big.Int).SetBytes(phiList[i]))
		//fmt.Printf("In ProveShuffle, for i: %d, reEncBeforeList[i] is (%v,%v)\n", i, reEncBeforeList[i].X, reEncBeforeList[i].Y)

		addendX, addendY := instance.Curve.ScalarMult(&reEncBeforeList[i].X, &reEncBeforeList[i].Y, phiList[i])

		//fmt.Printf("In ProveShuffle, for i: %d, addend for gPrimePoint is (%v,%v)\n", i, addend.X, addend.Y)

		gPrimePointX, gPrimePointY = instance.Curve.Add(gPrimePointX, gPrimePointY, addendX, addendY)

		//fmt.Printf("In ProveShuffle, gPrimePoint, partial result is (%v,%v)\n", gPrimePoint.X, gPrimePoint.Y)
	}
	//fmt.Printf("In ProveShuffle, gPrimePoint final result is (%v,%v)\n", gPrimePoint.X, gPrimePoint.Y)

	//Compute M'=\phi*P + \sum_i \phi_i*ct_{i,2}

	//First compute  \phi*P
	// mPrimePoint := types.Point{}
	mPrimePointX, mPrimePointY := instance.Curve.ScalarMult(&instance.PPoint.X, &instance.PPoint.Y, phiScalarBytes)
	//fmt.Printf("In ProveShuffle, mPrimePoint initial result is (%v,%v)\n", mPrimePoint.X, mPrimePoint.Y)

	// Then compute the sum by calcluating addends and add them at each step to the running value of M'
	for i := 0; i < len(instance.CtBefore); i++ {
		// Computes addend = phi[i] * ct_{i,2}
		// addend := types.Point{}
		addendX, addendY := instance.Curve.ScalarMult(&ctMsgBeforeList[i].X, &ctMsgBeforeList[i].Y, phiList[i])
		//fmt.Printf("In ProveShuffle, reEncBlindedPoint result is (%v,%v)\n", addend.X, addend.Y)
		mPrimePointX, mPrimePointY = instance.Curve.Add(mPrimePointX, mPrimePointY, addendX, addendY)
		//fmt.Printf("In ProveShuffle, mPrimePoint partial result is (%v,%v)\n", mPrimePoint.X, mPrimePoint.Y)
	}
	//fmt.Printf("In ProveShuffle, mPrimePoint final result is (%v,%v)\n", mPrimePoint.X, mPrimePoint.Y)

	// Compute \cap{T_i}
	tauScalar := new(big.Int).SetBytes(tauScalarBytes)
	//fmt.Printf("In ProveShuffle, tauScalar is: %v\n", tauScalar)

	tCapPointList := make([]types.Point, 0)
	for i := 0; i < len(witness.PermList); i++ {
		tCapBlindPoint := types.Point{}

		// Derive \lambda_i
		lambdaListScalar := new(big.Int).SetBytes(lambdaList[i])

		//fmt.Printf("In ProveShuffle, for i: %d, lambdaList[i] is: %v\n", i, lambdaListScalar)
		// Compute product of tau*lambda_i
		tauLambdaScalar := new(big.Int).SetUint64(0)
		tauLambdaScalar.Mul(tauScalar, lambdaListScalar)
		tauLambdaScalar.Mod(tauLambdaScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, for i: %d, tauLambdaScalar is: %v\n", i, tauLambdaScalar)

		// Find the image of i under the secret permutation \pi
		permImg := witness.PermList[i]

		// Derive phi_{\pi(i)} as a scalar
		phiListScalar := new(big.Int).SetBytes(phiList[permImg])
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, chosen phiScalar is: %v\n", i, permImg, phiListScalar)

		//Compute resultScalar =  3*phi_{\pi(i)}
		threeScalar := new(big.Int).SetUint64(3)
		resultScalar := new(big.Int).SetUint64(0)
		resultScalar.Mul(threeScalar, phiListScalar)
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (after *3) is: %v\n", i, permImg, resultScalar)

		//Set resultScalar=resultScalar+tau*Lambda_i
		resultScalar.Add(resultScalar, tauLambdaScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (after adding tauLambda) final is: %v\n", i, permImg, resultScalar)

		//Compute result \cap{T_i} = result*G
		tCapBlindPointX, tCapBlindPointY := instance.Curve.ScalarBaseMult(resultScalar.Bytes())

		tCapBlindPoint.X = *tCapBlindPointX
		tCapBlindPoint.Y = *tCapBlindPointY
		//fmt.Printf("In ProveShuffle, for i: %d, tCapBlindedPoint[i] is (%v,%v)\n", i, tCapBlindPoint.X, tCapBlindPoint.Y)
		tCapPointList = append(tCapPointList, tCapBlindPoint)
	}

	//Compute \cap{V_i}

	//First derive \theta as a scalar
	thetaScalar := new(big.Int).SetBytes(thetaScalarBytes)
	vCapPointList := make([]types.Point, 0)
	//fmt.Printf("In ProveShuffle, thetaScalar is: %v\n", thetaScalar)

	for i := 0; i < len(witness.PermList); i++ {
		vCapBlindedPoint := types.Point{}
		// Set the placeholder for \theta * r_i
		thetaRScalar := new(big.Int).SetUint64(0)

		//Derive r_i as a scalar
		rScalar := witness.RscalarList[i]

		//fmt.Printf("In ProveShuffle, for i: %d, rScalar is: %v\n", i, rScalar)

		//Compute  \theta * r_i
		thetaRScalar = thetaRScalar.Mul(thetaScalar, &rScalar)
		thetaRScalar = thetaRScalar.Mod(thetaRScalar, curveParams.N)

		//fmt.Printf("In ProveShuffle, for i: %d, thetaRsalar is: %v\n", i, thetaRScalar)

		// Find the image of i under the secret permutation \pi
		permImg := witness.PermList[i]

		// Derive phi_{\pi(i)} as a scalar
		phiListScalar := new(big.Int).SetBytes(phiList[permImg])
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, chosen phiScalar is: %v\n", i, permImg, phiListScalar)

		// Set 3 as a scalar
		threeScalar := new(big.Int).SetUint64(3)

		// Compute the exponent of the vCapPointList
		resultScalar := new(big.Int).SetUint64(0)
		// Compute result = phi_{\pi(i)} * phi_{\pi(i)}
		resultScalar.Mul(phiListScalar, phiListScalar)
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (phi*phi) is: %v\n", i, permImg, resultScalar)

		// Compute result = 3 * phi_{\pi(i)} * phi_{\pi(i)}
		resultScalar.Mul(threeScalar, resultScalar)
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (3*phi*phi) is: %v\n", i, permImg, resultScalar)

		// Compute result = result + (r_i * theta)
		resultScalar.Add(resultScalar, thetaRScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar *final(3*phi*phi+r_i * theta) is: %v\n", i, permImg, resultScalar)

		// Compute the point and add it to the vCapPointList
		vCapBlindedPointX, vCapBlindedPointY := instance.Curve.ScalarBaseMult(resultScalar.Bytes())
		//fmt.Printf("In ProveShuffle, for i: %d, vCapBlindedPoint[i] is (%v,%v)\n", i, vCapBlindedPoint.X, vCapBlindedPoint.Y)

		vCapBlindedPoint.X = *vCapBlindedPointX
		vCapBlindedPoint.Y = *vCapBlindedPointY

		vCapPointList = append(vCapPointList, vCapBlindedPoint)
	}

	//Compute \cap{V}
	// vCapPoint := types.Point{}

	// Compute the placeholders for \theta *\phi and \tau * \lambda
	thetaPhiScalar := new(big.Int).SetUint64(0)
	tauLambdaScalar := new(big.Int).SetUint64(0)

	// Set \lambda as a scalar
	lambdaScalar := new(big.Int).SetBytes(lambdaScalarBytes)

	//fmt.Printf("In ProveShuffle, computing vCapPoint, lambdaScalar is: %v\n", lambdaScalar)

	// Compute the product \tau*\lambda
	tauLambdaScalar.Mul(tauScalar, lambdaScalar)
	tauLambdaScalar.Mod(tauLambdaScalar, curveParams.N)
	//fmt.Printf("In ProveShuffle, computing vCapPoint, tauLambdaScalar is: %v\n", tauLambdaScalar)

	// Compute the product \theta *\phi
	thetaPhiScalar.Mul(thetaScalar, phiScalar)
	thetaPhiScalar.Mod(thetaPhiScalar, curveParams.N)
	//fmt.Printf("In ProveShuffle, computing vCapPoint, thetaPhiScalar is: %v\n", thetaPhiScalar)

	// Initialize the result for the dlog of \cap{V}
	vCapScalarResult := new(big.Int).SetUint64(0)
	vCapScalarResult.Add(tauLambdaScalar, thetaPhiScalar)
	vCapScalarResult.Mod(vCapScalarResult, curveParams.N)
	//fmt.Printf("In ProveShuffle, computing vCapPoint, vCapScalarResult initial (theta*phi + tau*lambda) is: %v\n", vCapScalarResult)

	for i := 0; i < len(witness.PermList); i++ {
		// Create the placeholders for \phi_i^2 and \phi_i^3
		phiSquared := new(big.Int).SetUint64(0)
		phiCubed := new(big.Int).SetUint64(0)

		phiListScalar := new(big.Int).SetBytes(phiList[i])
		//fmt.Printf("In ProveShuffle, for index %d, computing vCapPoint, phiListScalar is: %v\n", i, phiListScalar)

		// Compute the \phi_i^2
		phiSquared.Mul(phiListScalar, phiListScalar)
		phiSquared.Mod(phiSquared, curveParams.N)

		// Compute the \phi_i^3 as \phi_i^2 * \phi_i
		phiCubed.Mul(phiSquared, phiListScalar)
		phiCubed.Mod(phiCubed, curveParams.N)
		//fmt.Printf("In ProveShuffle, for index %d, computing vCapPoint, phiCubed is: %v\n", i, phiCubed)

		// Add the phi_i^3 to the running store for the exponent of \cap{V}
		vCapScalarResult.Add(phiCubed, vCapScalarResult)
		vCapScalarResult.Mod(vCapScalarResult, curveParams.N)
		//fmt.Printf("In ProveShuffle, for index %d, computing vCapPoint, vCapScalarResult partial is: %v\n", i, phiCubed)
	}
	//fmt.Printf("In ProveShuffle, computing vCapPoint, vCapScalarResult final is: %v\n", vCapScalarResult)

	// Compute the \cap{V} point based on the computed scalar as
	vCapPointX, vCapPointY := instance.Curve.ScalarBaseMult(vCapScalarResult.Bytes())
	//fmt.Printf("In ProveShuffle, vCapPoint final is (%v,%v)\n", vCapPoint.X, vCapPoint.Y)

	// Compute \cap{W_i}
	wCapPointList := make([]types.Point, 0)
	sigmaScalar := new(big.Int).SetBytes(sigmaScalarBytes)
	//fmt.Printf("In ProveShuffle, computing wCapPointList, value of sigmaScalar is: %v\n", sigmaScalar)

	for i := 0; i < len(witness.PermList); i++ {

		// Choose r_i
		rScalar := witness.RscalarList[i]
		//fmt.Printf("In ProveShuffle, loop for ^w_i, index %d, witness.RscalarList[i] is: %v\n", i, witness.RscalarList[i])

		//Compute \sigma * r_i
		sigmarScalar := new(big.Int).Mul(sigmaScalar, &rScalar)
		sigmarScalar.Mod(sigmarScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, loop for ^w_i, index %d, sigmarScalar is: %v\n", i, sigmarScalar)

		// Find the image of i under the secret permutation \pi
		ind := witness.PermList[i]
		//fmt.Printf("In ProveShuffle, loop for ^w_i, index %d, witness.PermList is: %v\n", i, ind)

		// Derive phi_{\pi(i)}
		phiListScalar := new(big.Int).SetBytes(phiList[ind])
		//fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, chosen phiListScalar is: %v\n", i, ind, phiListScalar)

		// Initialize 2 as a scalar
		twoScalar := new(big.Int).SetUint64(2)

		// Compute the product of 2*phi_{\pi(i)}
		resultScalar := new(big.Int).Mul(twoScalar, phiListScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, 2*phiListScalar is: %v\n", i, ind, resultScalar)

		// Compute the 2*phi_{\pi(i)} + \sigma * r_i
		resultScalar.Add(resultScalar, sigmarScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, resultScalar is: %v\n", i, ind, resultScalar)

		// Compute \cap{W_i} as result*G
		wCapBlindPoint := types.Point{}
		wCapBlindPointX, wCapBlindPointY := instance.Curve.ScalarBaseMult(resultScalar.Bytes())

		wCapBlindPoint.X = *wCapBlindPointX
		wCapBlindPoint.Y = *wCapBlindPointY

		//fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, wCapBlindPoint is (%v,%v)\n", i, ind, wCapBlindPoint.X, wCapBlindPoint.Y)
		wCapPointList = append(wCapPointList, wCapBlindPoint)
	}

	//Compute  \cap{W}
	// wCapPoint := types.Point{}

	// \cap{W} =
	wCapScalar := new(big.Int).SetUint64(0)
	wCapScalar.Mul(phiScalar, sigmaScalar)
	wCapScalar.Mod(wCapScalar, curveParams.N)
	//fmt.Printf("In ProveShuffle, loop for wCapPoint, inital result for exponent is %v\n", wCapScalar)

	for i := 0; i < len(witness.PermList); i++ {
		phiSquared := new(big.Int).SetUint64(0)
		phiListScalar := new(big.Int).SetBytes(phiList[i])
		//fmt.Printf("In ProveShuffle, loop for wCapPoint, phiListScalar is %v\n", phiListScalar)

		phiSquared.Mul(phiListScalar, phiListScalar)
		phiSquared.Mod(phiSquared, curveParams.N)
		//fmt.Printf("In ProveShuffle, loop for wCapPoint, phiListScalar is %v\n", phiSquared)

		wCapScalar.Add(wCapScalar, phiSquared)
		wCapScalar.Mod(wCapScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, loop for wCapPoint, partial result for exponent is %v\n", wCapScalar)

	}
	//fmt.Printf("In ProveShuffle, loop for wCapPoint, final result for exponent is %v\n", wCapScalar)
	wCapScalar.Mod(wCapScalar, curveParams.N)
	wCapPointX, wCapPointY := instance.Curve.ScalarBaseMult(wCapScalar.Bytes())
	//fmt.Printf("In ProveShuffle, loop for wCapPoint, final result is (%v,%v)\n", wCapPoint.X, wCapPoint.Y)

	//Begin preparing derived points for appending to the transcript

	tPointCompressed := elliptic.MarshalCompressed(instance.Curve, tPointX, tPointY)
	vPointCompressed := elliptic.MarshalCompressed(instance.Curve, vPointX, vPointY)
	wPointCompressed := elliptic.MarshalCompressed(instance.Curve, wPointX, wPointY)
	uPointCompressed := elliptic.MarshalCompressed(instance.Curve, uPointX, uPointY)
	uPointListCompressed := MarshalPointList(uPointList, instance.Curve)
	//TODO: missing is ^g'-list and ^g' point

	gPrimePointCompressed := elliptic.MarshalCompressed(instance.Curve, gPrimePointX, gPrimePointY)
	mPrimePointCompressed := elliptic.MarshalCompressed(instance.Curve, mPrimePointX, mPrimePointY)
	tCapPointListCompressed := MarshalPointList(tCapPointList, instance.Curve)
	vCapPointListCompressed := MarshalPointList(vCapPointList, instance.Curve)
	vCapPointCompressed := elliptic.MarshalCompressed(instance.Curve, vCapPointX, vCapPointY)
	wCapPointListCompressed := MarshalPointList(wCapPointList, instance.Curve)
	wCapPointCompressed := elliptic.MarshalCompressed(instance.Curve, wCapPointX, wCapPointY)

	//Putting commitment messages into the transcript

	transcript.AppendMessage(proofTypeBytes, tPointCompressed)
	transcript.AppendMessage(proofTypeBytes, vPointCompressed)
	transcript.AppendMessage(proofTypeBytes, wPointCompressed)
	transcript.AppendMessage(proofTypeBytes, uPointCompressed)
	transcript.BatchAppendMessages(proofTypeBytes, uPointListCompressed)
	//TODO: extra missing ^g'_i, ^g' point

	transcript.AppendMessage(proofTypeBytes, gPrimePointCompressed)
	transcript.AppendMessage(proofTypeBytes, mPrimePointCompressed)
	transcript.BatchAppendMessages(proofTypeBytes, tCapPointListCompressed)
	transcript.BatchAppendMessages(proofTypeBytes, vCapPointListCompressed)
	transcript.AppendMessage(proofTypeBytes, vCapPointCompressed)
	transcript.BatchAppendMessages(proofTypeBytes, wCapPointListCompressed)
	transcript.AppendMessage(proofTypeBytes, wCapPointCompressed)

	//Verifier's step: derive public coins based on the
	challScalarList := make([][]byte, 0)
	for i := 0; i < len(witness.PermList); i++ {
		challScalarList = append(challScalarList, transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE))
	}

	//fmt.Printf("In ProveShuffle, challScalarList is %v\n", challScalarList)

	//Compute s_0 scalar
	sZeroScalar := new(big.Int).Set(phiScalar)
	//fmt.Printf("In ProveShuffle, sZeroScalar initial: %v\n", sZeroScalar)

	for i := 0; i < len(witness.PermList); i++ {
		//Corresponds to \beta_j
		challScalar := new(big.Int).SetBytes(challScalarList[i])
		//fmt.Printf("In ProveShuffle, challScalar is: %v\n", challScalar)
		//multiplied by r_j
		//fmt.Printf("In ProveShuffle, loop for s_0, witness.RscalarList[i] is: %v\n", witness.RscalarList[i])
		rBeta := challScalar.Mul(challScalar, &witness.RscalarList[i])
		rBeta = rBeta.Mod(rBeta, curveParams.N)

		//fmt.Printf("In ProveShuffle, for sZeroScalar addend is : %v\n", rBeta)

		//Add result to the sum
		sZeroScalar = sZeroScalar.Add(sZeroScalar, rBeta)
		sZeroScalar = sZeroScalar.Mod(sZeroScalar, curveParams.N)

		//fmt.Printf("In ProveShuffle, sZeroScalar partial: %v\n", sZeroScalar)

	}
	//fmt.Printf("In ProveShuffle, sZeroScalar final: %v\n", sZeroScalar)

	sList := make([]big.Int, 0)
	//fmt.Printf("In ProveShuffle, PermList is: %v\n", witness.PermList)
	permMatrix := MakePermutationMatrix(witness.PermList)
	//fmt.Printf("In ProveShuffle, PermMatrix is:\n")
	printPermutationMatrix(permMatrix)

	// Compute s_i scalars
	for i := 0; i < len(witness.PermList); i++ {
		sScalar := new(big.Int).SetBytes(phiList[i])
		//fmt.Printf("In ProveShuffle, for index %d, sScalar initial %v\n", i, sScalar)

		ind := findNonZeroIndex(permMatrix[i])
		//fmt.Printf("In ProveShuffle, for index %d, chosen index in permutation matrix %d\n", i, ind)

		//fmt.Printf("In ProveShuffle, Beta value chosen %v\n", challScalarList[ind])
		challScalar := new(big.Int).SetBytes(challScalarList[ind])
		//fmt.Printf("In ProveShuffle, for index %d, challScalar is %v\n", i, challScalar)

		sScalar = sScalar.Add(sScalar, challScalar)
		sScalar = sScalar.Mod(sScalar, curveParams.N)
		//fmt.Printf("In ProveShuffle, for index %d, sScalar final %v\n", i, sScalar)
		sList = append(sList, *sScalar)
	}

	// Compute d scalar

	//Set it to initially be lambda

	dScalar := new(big.Int).SetBytes(lambdaScalarBytes)
	for i := 0; i < len(witness.PermList); i++ {
		lambda := new(big.Int).SetBytes(lambdaList[i])
		chall := new(big.Int).SetBytes(challScalarList[i])

		//compute chall_i*chall_i
		challSquared := chall.Mul(chall, chall)
		challSquared = challSquared.Mod(challSquared, curveParams.N)
		//fmt.Printf("In ProveShuffle, for dScalar, for index %d, partial value is %v\n", i, challSquared)

		//compute lambda_i*chall_i*chall_i
		prod := challSquared.Mul(challSquared, lambda)
		dScalar = dScalar.Add(dScalar, prod)
		dScalar = dScalar.Mod(dScalar, curveParams.N)

		//fmt.Printf("In ProveShuffle, for dScalar,for index %d, dScalar partial %v\n", i, dScalar)

	}

	//fmt.Printf("In ProveShuffle, dScalar final %v\n", dScalar)

	shuffleProof := types.ShuffleProof{
		ProofType:          SHUFFLE_LABEL,
		Instance:           *instance,
		VerifierChallList:  challScalarList,
		TPoint:             tPointCompressed,
		VPoint:             vPointCompressed,
		WPoint:             wPointCompressed,
		UPoint:             uPointCompressed,
		UPointListBytes:    uPointListCompressed,
		GPrimePoint:        gPrimePointCompressed,
		MPrimePoint:        mPrimePointCompressed,
		TCapPointListBytes: tCapPointListCompressed,
		VCapPointListBytes: vCapPointListCompressed,
		VCapPoint:          vCapPointCompressed,
		WCapPointListBytes: wCapPointListCompressed,
		WCapPoint:          wCapPointCompressed,
		SZeroScalar:        *sZeroScalar,
		SList:              sList,
		DScalar:            *dScalar,
	}
	return &shuffleProof, nil
}

func VerifyShuffle(proof *types.ShuffleProof) bool {
	curve := proof.Instance.Curve
	curveParams := proof.Instance.Curve.Params()

	transcript := NewTranscript(proof.ProofType)
	proofTypeBytes := []byte(proof.ProofType)
	reEncBeforeList := MakeReencList(proof.Instance.CtBefore)
	reEncAfterList := MakeReencList(proof.Instance.CtAfter)
	ctMsgBeforeList := MakeCtMsgList(proof.Instance.CtBefore)
	ctMsgAfterList := MakeCtMsgList(proof.Instance.CtAfter)

	reEncBeforeByteList := MarshalPointList(reEncBeforeList, curve)
	reEncAfterByteList := MarshalPointList(reEncAfterList, curve)
	ctMsgBeforeByteList := MarshalPointList(ctMsgBeforeList, curve)
	ctMsgAfterByteList := MarshalPointList(ctMsgAfterList, curve)

	pPoint := types.Point{
		X: proof.Instance.PPoint.X,
		Y: proof.Instance.PPoint.Y,
	}

	pPointCompressed := elliptic.MarshalCompressed(curve, &pPoint.X, &pPoint.Y)

	//Putting public parameters into the transcript
	transcript.BatchAppendMessages(proofTypeBytes, reEncBeforeByteList)
	transcript.BatchAppendMessages(proofTypeBytes, reEncAfterByteList)
	transcript.BatchAppendMessages(proofTypeBytes, ctMsgBeforeByteList)
	transcript.BatchAppendMessages(proofTypeBytes, ctMsgAfterByteList)
	transcript.AppendMessage(proofTypeBytes, pPointCompressed)

	//Putting commitment messages into the transcript

	transcript.AppendMessage(proofTypeBytes, proof.TPoint)
	transcript.AppendMessage(proofTypeBytes, proof.VPoint)
	transcript.AppendMessage(proofTypeBytes, proof.WPoint)
	transcript.AppendMessage(proofTypeBytes, proof.UPoint)
	transcript.BatchAppendMessages(proofTypeBytes, proof.UPointListBytes)
	//TODO: extra missing ^g'_i, ^g' point

	transcript.AppendMessage(proofTypeBytes, proof.GPrimePoint)
	transcript.AppendMessage(proofTypeBytes, proof.MPrimePoint)
	transcript.BatchAppendMessages(proofTypeBytes, proof.TCapPointListBytes)
	transcript.BatchAppendMessages(proofTypeBytes, proof.VCapPointListBytes)
	transcript.AppendMessage(proofTypeBytes, proof.VCapPoint)
	transcript.BatchAppendMessages(proofTypeBytes, proof.WCapPointListBytes)
	transcript.AppendMessage(proofTypeBytes, proof.WCapPoint)

	//Verifier's step: derive public coins based on the
	challBytesList := make([][]byte, 0)
	for i := 0; i < len(proof.Instance.CtBefore); i++ {
		challBytesList = append(challBytesList, transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE))
	}

	//fmt.Printf("In VerifyShuffle, challBytesList is %v\n", challBytesList)

	checkBytes := checkChallBytesLists(challBytesList, proof.VerifierChallList)

	//Parse all the points for the final verifier's check

	tPointX, tPointY := elliptic.UnmarshalCompressed(curve, proof.TPoint)
	wPointX, wPointY := elliptic.UnmarshalCompressed(curve, proof.WPoint)
	vPointX, vPointY := elliptic.UnmarshalCompressed(curve, proof.VPoint)
	uPointX, uPointY := elliptic.UnmarshalCompressed(curve, proof.UPoint)

	gPrimePointX, gPrimePointY := elliptic.UnmarshalCompressed(curve, proof.GPrimePoint)
	mPrimePointX, mPrimePointY := elliptic.UnmarshalCompressed(curve, proof.MPrimePoint)
	vCapPointX, vCapPointY := elliptic.UnmarshalCompressed(curve, proof.VCapPoint)
	wCapPointX, wCapPointY := elliptic.UnmarshalCompressed(curve, proof.WCapPoint)

	uPointList := UnmarshalPointList(proof.UPointListBytes, curve)
	vCapPointList := UnmarshalPointList(proof.VCapPointListBytes, curve)
	wCapPointList := UnmarshalPointList(proof.WCapPointListBytes, curve)
	tCapPointList := UnmarshalPointList(proof.TCapPointListBytes, curve)
	// //fmt.Printf("wCapPointList, %v\n", wCapPointList)

	//Corresponds to check (5.20) in notes
	// sGpoint := types.Point{}
	sGpointX, sGpointY := curve.ScalarBaseMult(proof.SZeroScalar.Bytes())

	//fmt.Printf("In VerifyShuffle, sZeroScalar is %v\n", proof.SZeroScalar)
	//fmt.Printf("In VerifyShuffle, sGpoint, initial value is (%v,%v)\n", sGpoint.X, sGpointY)

	for i, sScalar := range proof.SList {
		// addend := types.Point{}
		//fmt.Printf("In VerifyShuffle, reEncBeforeList[i] is (%v,%v)\n", reEncBeforeList[i].X, reEncBeforeList[i].Y)
		//fmt.Printf("In VerifyShuffle, sScalar is %v\n", sScalar)

		addendX, addendY := curve.ScalarMult(&reEncBeforeList[i].X, &reEncBeforeList[i].Y, sScalar.Bytes())
		sGpointX, sGpointY = curve.Add(addendX, addendY, sGpointX, sGpointY)
		//fmt.Printf("In VerifyShuffle, sGpoint, partial result is (%v,%v)\n", sGpoint.X, sGpoint.Y)

	}
	//fmt.Printf("In VerifyShuffle, sGpoint,final is (%v,%v)\n", sGpoint.X, sGpoint.Y)

	betaGprimePointX := new(big.Int).Set(gPrimePointX)
	betaGprimePointY := new(big.Int).Set(gPrimePointY)
	//fmt.Printf("In VerifyShuffle, betaGprimePoint initial is (%v,%v)\n", betaGprimePoint.X, betaGprimePoint.Y)

	for i, challBytes := range challBytesList {
		// addend := types.Point{}
		//fmt.Printf("In VerifyShuffle, for index %d, reEncAfterList[i] is (%v,%v)\n", i, reEncAfterList[i].X, reEncAfterList[i].Y)
		addendX, addendY := curve.ScalarMult(&reEncAfterList[i].X, &reEncAfterList[i].Y, challBytes)
		//fmt.Printf("In VerifyShuffle, for index %d, addend is (%v,%v)\n", i, reEncAfterList[i].X, reEncAfterList[i].Y)
		betaGprimePointX, betaGprimePointY = curve.Add(addendX, addendY, betaGprimePointX, betaGprimePointY)
		// betaGprimePoint.X, betaGprimePoint.Y = *bpX, *bpY

		//fmt.Printf("In VerifyShuffle, betaGprimePoint partial result is (%v,%v)\n", betaGprimePoint.X, betaGprimePoint.Y)

	}
	//fmt.Printf("In VerifyShuffle, betaGprimePoint final is (%v,%v)\n", betaGprimePoint.X, betaGprimePoint.Y)

	checkO2 := sGpointX.Cmp(betaGprimePointX) == 0 && sGpointY.Cmp(betaGprimePointY) == 0

	//Corresponds to check (5.21) in notes

	// sMpoint := types.Point{}
	sMpointX, sMpointY := curve.ScalarMult(&pPoint.X, &pPoint.Y, proof.SZeroScalar.Bytes())
	//fmt.Printf("In VerifyShuffle, sMpoint initial is (%v,%v)\n", sMpoint.X, sMpoint.Y)

	for i, s := range proof.SList {
		// addend := types.Point{}
		//fmt.Printf("In VerifyShuffle, for %d, ctMsgBefore[i] is (%v,%v)\n", i, ctMsgBeforeList[i].X, ctMsgBeforeList[i].Y)

		addendX, addendY := curve.ScalarMult(&ctMsgBeforeList[i].X, &ctMsgBeforeList[i].Y, s.Bytes())
		//fmt.Printf("In VerifyShuffle, sMpoint addend is (%v,%v)\n", addend.X, addend.Y)
		sMpointX, sMpointY = curve.Add(addendX, addendY, sMpointX, sMpointY)
		//fmt.Printf("In VerifyShuffle, sMpoint partial is (%v,%v)\n", sMpoint.X, sMpoint.Y)
	}
	//fmt.Printf("In VerifyShuffle, sMpoint final is (%v,%v)\n", sMpoint.X, sMpoint.Y)

	challMprimePointX := new(big.Int).Set(mPrimePointX)
	challMprimePointY := new(big.Int).Set(mPrimePointY)

	//fmt.Printf("In VerifyShuffle, challMprimePoint initial is (%v,%v)\n", challMprimePoint.X, challMprimePoint.Y)

	for i, challBytes := range challBytesList {
		// addend := types.Point{}
		//fmt.Printf("In VerifyShuffle, for index %d, ctMsgAfterList is (%v,%v)\n", i, ctMsgAfterList[i].X, ctMsgAfterList[i].Y)
		addendX, addendY := curve.ScalarMult(&ctMsgAfterList[i].X, &ctMsgAfterList[i].Y, challBytes)
		//fmt.Printf("In VerifyShuffle,for index %d, challMprimePoint addend is (%v,%v)\n", i, addend.X, addend.Y)

		challMprimePointX, challMprimePointY = curve.Add(addendX, addendY, challMprimePointX, challMprimePointY)

		//fmt.Printf("In VerifyShuffle,for index %d, challMprimePoint partial is (%v,%v)\n", i, challMprimePoint.X, challMprimePoint.Y)
	}
	//fmt.Printf("In VerifyShuffle, challMprimePoint final is (%v,%v)\n", challMprimePoint.X, challMprimePoint.Y)

	checkO3 := sMpointX.Cmp(challMprimePointX) == 0 && sMpointY.Cmp(challMprimePointY) == 0

	//Corresponds to check (5.22) in notes
	// sBetaSqWGPoint := types.Point{}

	//Initialize point to be s0*W
	sBetaSqWGPointX, sBetaSqWGPointY := curve.ScalarMult(wPointX, wPointY, proof.SZeroScalar.Bytes())

	//fmt.Printf("In VerifyShuffle, challMprimePoint initial is (%v,%v)\n", sBetaSqWGPoint.X, sBetaSqWGPoint.Y)

	sqDiff := new(big.Int).SetUint64(0)
	for i := 0; i < len(challBytesList); i++ {
		//Compute s_i^2
		siSq := new(big.Int).Set(&proof.SList[i])

		siSq = siSq.Mul(siSq, siSq)
		siSq = siSq.Mod(siSq, curveParams.N)

		//fmt.Printf("In VerifyShuffle, for index %d, siSq is %v\n", i, siSq)

		//compute chall^2
		challScalar := new(big.Int).SetBytes(challBytesList[i])
		challSq := challScalar.Mul(challScalar, challScalar)
		challSq = challSq.Mod(challSq, curveParams.N)
		challSq = challSq.Neg(challSq)

		//fmt.Printf("In VerifyShuffle, for index %d, challSq is %v\n", i, challSq)

		//Compute addend = s_i^2-chall^2
		addend := siSq.Add(siSq, challSq)
		addend = addend.Mod(addend, curveParams.N)

		//fmt.Printf("In VerifyShuffle, for index %d, addend is %v\n", i, addend)

		//Add addend to the whole sum
		sqDiff = sqDiff.Add(sqDiff, addend)
		sqDiff = sqDiff.Mod(sqDiff, curveParams.N)

		//fmt.Printf("In VerifyShuffle, for index %d, sqDiff partial is %v\n", i, sqDiff)
	}
	//fmt.Printf("In VerifyShuffle, sqDiff final is %v\n", sqDiff)

	// sqDiffGPoint := types.Point{}
	sqDiffGPointX, sqDiffGPointY := curve.ScalarBaseMult(sqDiff.Bytes())
	//fmt.Printf("In VerifyShuffle, sqDiffGPoint is (%v,%v)\n", sqDiffGPoint.X, sqDiffGPoint.Y)

	sBetaSqWGPointX, sBetaSqWGPointY = curve.Add(sBetaSqWGPointX, sBetaSqWGPointY, sqDiffGPointX, sqDiffGPointY)
	//fmt.Printf("In VerifyShuffle, sBetaSqWGPoint final is (%v,%v)\n", sBetaSqWGPoint.X, sBetaSqWGPoint.Y)

	betawCapPointX := new(big.Int).Set(wCapPointX)
	betawCapPointY := new(big.Int).Set(wCapPointY)
	//fmt.Printf("In VerifyShuffle, betawCapPoint initial is (%v,%v)\n", betawCapPoint.X, betawCapPoint.Y)

	for i, challBytes := range challBytesList {
		// addend := types.Point{}
		addendX, addendY := curve.ScalarMult(&wCapPointList[i].X, &wCapPointList[i].Y, challBytes)
		//fmt.Printf("In VerifyShuffle, addend for betawCapPoint is (%v,%v)\n", addend.X, addend.Y)

		betawCapPointX, betawCapPointY = curve.Add(addendX, addendY, betawCapPointX, betawCapPointY)
		//fmt.Printf("In VerifyShuffle,  betawCapPoint partial is (%v,%v)\n", betawCapPoint.X, betawCapPoint.Y)
	}
	//fmt.Printf("In VerifyShuffle,  betawCapPoint final is (%v,%v)\n", betawCapPoint.X, betawCapPoint.Y)

	check04 := sBetaSqWGPointX.Cmp(betawCapPointX) == 0 && sBetaSqWGPointY.Cmp(betawCapPointY) == 0

	//Corresponds to check (5.23) in notes

	// dGpoint := types.Point{}
	dGpointX, dGpointY := curve.ScalarBaseMult(proof.DScalar.Bytes())

	//fmt.Printf("In VerifyShuffle, dGPoint final is (%v,%v)\n", dGpoint.X, dGpoint.Y)

	challSqUPointX := new(big.Int).Set(uPointX)
	challSqUPointY := new(big.Int).Set(uPointY)

	//fmt.Printf("In VerifyShuffle, challSqUPoint initial is (%v,%v)\n", challSqUPoint.X, challSqUPoint.Y)

	for i, challBytes := range challBytesList {
		// addend := types.Point{}
		challScalar := new(big.Int).SetBytes(challBytes)
		challSqScalar := challScalar.Mod(challScalar.Mul(challScalar, challScalar), curveParams.N)
		//fmt.Printf("In VerifyShuffle, for index %d challSq is %v\n", i, challSqScalar)

		addendX, addendY := curve.ScalarMult(&uPointList[i].X, &uPointList[i].Y, challSqScalar.Bytes())
		//fmt.Printf("In VerifyShuffle, for index %d addend is (%v,%v)\n", i, addend.X, addend.Y)

		challSqUPointX, challSqUPointY = curve.Add(addendX, addendY, challSqUPointX, challSqUPointY)
		//fmt.Printf("In VerifyShuffle, challSqUPoint partial is (%v,%v)\n", challSqUPoint.X, challSqUPoint.Y)
	}

	//fmt.Printf("In VerifyShuffle, challSqUPoint final is (%v,%v)\n", challSqUPoint.X, challSqUPoint.Y)

	check05 := dGpointX.Cmp(challSqUPointX) == 0 && dGpointY.Cmp(challSqUPointY) == 0

	//Corresponds to check (5.24) in notes

	//Compute lhs of the (5.24) check
	// dTPoint := types.Point{}
	dTPointX, dTPointY := curve.ScalarMult(tPointX, tPointY, proof.DScalar.Bytes())
	//fmt.Printf("In VerifyShuffle, value of dTPoint is (%v,%v)\n", dTPoint.X, dTPoint.Y)

	// sZeroVPoint := types.Point{}
	sZeroVPointX, sZeroVPointY := curve.ScalarMult(vPointX, vPointY, proof.SZeroScalar.Bytes())
	//fmt.Printf("In VerifyShuffle, value of sZeroVPoint is (%v,%v)\n", sZeroVPoint.X, sZeroVPoint.Y)

	cubeDiff := new(big.Int).SetUint64(0)
	for i := 0; i < len(challBytesList); i++ {
		//Compute s_i^3
		siScalar := new(big.Int).Set(&proof.SList[i])
		siCubed := new(big.Int).SetUint64(0)
		siCubed = siCubed.Mul(siScalar, siScalar)
		siCubed = siCubed.Mul(siCubed, siScalar)
		siCubed = siCubed.Mod(siCubed, curveParams.N)

		//fmt.Printf("In VerifyShuffle, for index %d, siCubed is %v\n", i, siCubed)

		//compute -chall^3
		challSc := new(big.Int).SetBytes(challBytesList[i])

		challCubed := new(big.Int).SetUint64(0)
		challCubed = challCubed.Mul(challSc, challSc)
		challCubed = challCubed.Mul(challCubed, challSc)
		challCubed = challCubed.Mod(challCubed, curveParams.N)
		//fmt.Printf("In VerifyShuffle, for index %d, challCubed is %v\n", i, challCubed)

		challCubed = challCubed.Neg(challCubed)

		//fmt.Printf("In VerifyShuffle, for index %d, -challCubed is %v\n", i, challCubed)

		//Compute addend = s_i^3-chall^3
		addend := new(big.Int).SetUint64(0)
		addend = addend.Add(siCubed, challCubed)
		addend = addend.Mod(addend, curveParams.N)

		//fmt.Printf("In VerifyShuffle, for index %d, value of addend (s_i^3 - chall^3) is %v\n", i, addend)

		// //fmt.Printf("In VerifyShuffle, for index %d, addend is %v\n", i, addend)

		//Add addend to the whole sum
		cubeDiff = cubeDiff.Add(cubeDiff, addend)
		cubeDiff = cubeDiff.Mod(cubeDiff, curveParams.N)
		//fmt.Printf("In VerifyShuffle, for index %d, cubeDiff partial is %v\n", i, cubeDiff)
	}
	//fmt.Printf("In VerifyShuffle, cubeDiff final is %v\n", cubeDiff)

	// cubeDiffGPoint := types.Point{}
	cubeDiffGPointX, cubeDiffGPointY := curve.ScalarBaseMult(cubeDiff.Bytes())

	//fmt.Printf("In VerifyShuffle, value of cubeDiffGPoint is (%v,%v)\n", cubeDiffGPoint.X, cubeDiffGPoint.Y)

	// lhs := types.Point{}
	lhsX, lhsY := curve.Add(dTPointX, dTPointY, sZeroVPointX, sZeroVPointY)
	//fmt.Printf("In VerifyShuffle, value of sume dT + sZeroV is (%v,%v)\n", lhs.X, lhs.Y)

	lhsX, lhsY = curve.Add(lhsX, lhsY, cubeDiffGPointX, cubeDiffGPointY)

	//fmt.Printf("In VerifyShuffle, final value of lhs is (%v,%v)\n", lhs.X, lhs.Y)

	//Compute rhs of (5.24) check
	rhsX := new(big.Int).Set(vCapPointX)
	rhsY := new(big.Int).Set(vCapPointY)

	//fmt.Printf("In VerifyShuffle, initial value of rhs is (%v,%v)\n", rhs.X, rhs.Y)

	for i := 0; i < len(challBytesList); i++ {
		// challVcapPoint := types.Point{}
		// challSqTCapPoint := types.Point{}

		chall := new(big.Int).SetBytes(challBytesList[i])

		//fmt.Printf("In VerifyShuffle, for index %d, value of vCapPoint (%v,%v)\n", i, vCapPointList[i].X, vCapPointList[i].Y)

		challVcapPointX, challVcapPointY := curve.ScalarMult(&vCapPointList[i].X, &vCapPointList[i].Y, challBytesList[i])
		//fmt.Printf("In VerifyShuffle, for index %d, value of challVcapPoint (%v,%v)\n", i, challVcapPoint.X, challVcapPoint.Y)

		challSq := new(big.Int).SetUint64(0)
		challSq = challSq.Mul(chall, chall)
		challSq = challSq.Mod(challSq, curveParams.N)

		//fmt.Printf("In VerifyShuffle, challSq final is %v\n", challSq)

		//fmt.Printf("In VerifyShuffle, for index %d, value of tCapPoint (%v,%v)\n", i, tCapPointList[i].X, tCapPointList[i].Y)
		challSqTCapPointX, challSqTCapPointY := curve.ScalarMult(&tCapPointList[i].X, &tCapPointList[i].Y, challSq.Bytes())
		//fmt.Printf("In VerifyShuffle, for index %d, value of chall^2*tCapPoint (%v,%v)\n", i, challSqTCapPoint.X, challSqTCapPoint.Y)

		rhsX, rhsY = curve.Add(rhsX, rhsY, challVcapPointX, challVcapPointY)
		rhsX, rhsY = curve.Add(rhsX, rhsY, challSqTCapPointX, challSqTCapPointY)
	}

	check06 := lhsX.Cmp(rhsX) == 0 && lhsY.Cmp(rhsY) == 0

	//fmt.Printf("Check02: %v, Check03: %v, Check04: %v, Check05: %v, Check06: %v\n", checkO2, checkO3, check04, check05, check06)

	return checkBytes && checkO2 && checkO3 && check04 && check05 && check06 //check04 && check05 //TODO: Missing checks for 5.22 (check04), 5.24 (check06)
}

/********************************************** New additions *******************************************************/

// Proves that one of the two statements satisfies the Chaum-Pedersen relation using the OR-Sigma proof composition
func ProveDlogEqOr(secret Value, pPoint, bPointOther, pPointOther types.Point, curve elliptic.Curve, secretBit bool) (*types.Proof, error) {

	// Derive parameters of the elliptic curve
	curveParams := curve.Params()

	//fmt.Printf("Secret scalar is %v\n", new(big.Int).SetBytes(secret).Uint64())
	//fmt.Printf("pPoint is (%v,%v)\n", pPoint.X, pPoint.Y)
	//fmt.Printf("bPointOther is (%v,%v)\n", pPoint.X, pPoint.Y)
	//fmt.Printf("pPointOther is (%v,%v)\n", pPoint.X, pPoint.Y)

	// Marshall proof instance to bytes
	pPointCompressed := elliptic.MarshalCompressed(curve, &pPoint.X, &pPoint.Y)
	bPointOtherCompressed := elliptic.MarshalCompressed(curve, &bPointOther.X, &bPointOther.Y)
	pPointOtherCompressed := elliptic.MarshalCompressed(curve, &pPointOther.X, &pPointOther.Y)

	proofTypeBytes := []byte(DLOG_OR_EQ_LABEL)

	// Create placeholder for the proof
	proof := NewProof(DLOG_OR_EQ_LABEL)

	// Initialize protocol's transcript
	transcript := NewTranscript(DLOG_OR_EQ_LABEL)

	// Generate the triple for the fake case
	fakepPointScalar := GenerateRandomBigInt(curveParams.N)
	fakepPointOtherScalar := GenerateRandomBigInt(curveParams.N)
	fakepPointX, fakepPointY := curve.ScalarBaseMult(fakepPointScalar.Bytes())
	fakePOtherX, fakePOtherY := curve.ScalarBaseMult(fakepPointOtherScalar.Bytes())

	fakepPoint := NewPoint(fakepPointX, fakepPointY)
	fakepPointOther := NewPoint(fakePOtherX, fakePOtherY)

	//fmt.Printf("fakepPoint is (%v,%v)\n", pPoint.X, pPoint.Y)
	//fmt.Printf("fakepPointOther is (%v,%v)\n", pPoint.X, pPoint.Y)

	fakepPointCompressed := elliptic.MarshalCompressed(curve, &fakepPoint.X, &fakepPoint.Y)
	fakepPointOtherCompressed := elliptic.MarshalCompressed(curve, &fakepPointOther.X, &fakepPointOther.Y)

	// Append proof instance values to the transcript
	if secretBit {
		// Append honest public points first
		transcript.AppendMessage(proofTypeBytes, bPointOtherCompressed)
		transcript.AppendMessage(proofTypeBytes, pPointCompressed)
		transcript.AppendMessage(proofTypeBytes, pPointOtherCompressed)

		//Then Append the fake generated public points
		transcript.AppendMessage(proofTypeBytes, bPointOtherCompressed)
		transcript.AppendMessage(proofTypeBytes, fakepPointCompressed)
		transcript.AppendMessage(proofTypeBytes, fakepPointOtherCompressed)
	} else {
		// Append the fake generated public points
		transcript.AppendMessage(proofTypeBytes, bPointOtherCompressed)
		transcript.AppendMessage(proofTypeBytes, fakepPointCompressed)
		transcript.AppendMessage(proofTypeBytes, fakepPointOtherCompressed)

		transcript.AppendMessage(proofTypeBytes, bPointOtherCompressed)
		transcript.AppendMessage(proofTypeBytes, pPointCompressed)
		transcript.AppendMessage(proofTypeBytes, pPointOtherCompressed)

	}

	// Begin deriving commitment scalar

	// Derive seed based on which the commitment scalar is derived
	commitRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogEqOr: %v", err)
	}

	// Build randomness generator for the commitment value
	trPRGbuilder := transcript.BuildRng()
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.ProofType), secret)
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.ProofType), commitRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {

	}

	commitScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	trueCommitScalar := new(big.Int).SetBytes(commitScalarBytes)
	trueCommitScalar.Mod(trueCommitScalar, curveParams.N)

	//fmt.Printf("trueCommitScalar scalar is %v\n", trueCommitScalar.Uint64())

	// Create placeholders for the two commitment points
	cPoint := types.Point{}
	cPointOther := types.Point{}

	// Compute cPoint = c*G where G is the base point of the curve
	cPointX, cPointY := curve.ScalarBaseMult(trueCommitScalar.Bytes())
	cPoint.X, cPoint.Y = *cPointX, *cPointY
	cPointCompressed := elliptic.MarshalCompressed(curve, &cPoint.X, &cPoint.Y)

	//fmt.Printf("cPoint is (%v,%v)\n", cPoint.X, cPoint.Y)

	// Compute cPoint = c*G' where G' is the base point of the curve (and G != G')
	cPointOtherX, cPointOtherY := curve.ScalarMult(&bPointOther.X, &bPointOther.Y, trueCommitScalar.Bytes())
	cPointOther.X, cPointOther.Y = *cPointOtherX, *cPointOtherY
	cPointOtherCompressed := elliptic.MarshalCompressed(curve, &cPointOther.X, &cPointOther.Y)

	//fmt.Printf("cPointOther is (%v,%v)\n", cPointOther.X, cPointOther.Y)

	// For the fake case: Derive random challenge for the simulation using the transcript
	simRandSeed, err := cryptorand.Int(cryptorand.Reader, curveParams.N)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogEqOr: %v", err)
	}

	trPRGbuilder = transcript.BuildRng()
	trPRGbuilder.RekeyWitnessBytes(proofTypeBytes, simRandSeed.Bytes())
	trPRG, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlogEqOr: %v", err)
	}

	// For the fake case: Generate fake challenge bytes (As if they came from the verifier)
	fakeChallBytes := trPRG.GetRandomness(SCALAR_SIZE)
	//fmt.Printf("In ProveDlogEqOr, fakeChallBytes: %v\n", fakeChallBytes)

	// Use simulator for the proof ot the DLOG to create the fake (but accepting transcirpt)

	// We will use the same bPoint and bPoint other as in the function arguments
	//  (these will correspond to the base point, and public point when they are actually used, respectively)
	fakeCPointCompressed, fakeCPointOtherCompressed, fakeChallBytes, fakeResult := SimulatorDlogEq(fakeChallBytes, trPRG, curve, fakepPoint, bPointOther, fakepPointOther)

	if secretBit {
		transcript.AppendMessage(proofTypeBytes, cPointCompressed)
		transcript.AppendMessage(proofTypeBytes, cPointOtherCompressed)

		transcript.AppendMessage(proofTypeBytes, fakeCPointCompressed)
		transcript.AppendMessage(proofTypeBytes, fakeCPointOtherCompressed)
	} else {

		transcript.AppendMessage(proofTypeBytes, fakeCPointCompressed)
		transcript.AppendMessage(proofTypeBytes, fakeCPointOtherCompressed)

		transcript.AppendMessage(proofTypeBytes, cPointCompressed)
		transcript.AppendMessage(proofTypeBytes, cPointOtherCompressed)
	}

	// Generate verifier's challenge bytes from the current transcript state
	verifierChallBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	//fmt.Printf("In ProveDlogEqOr, VerifierChallBytes: %v\n", verifierChallBytes)

	// Derive challenge bytes for the true case  by xoring the chall bytes received
	// from the verifier with the fake challenge bytes
	trueChallBytes := make([]byte, len(verifierChallBytes))
	for i, val := range verifierChallBytes {
		trueChallBytes[i] = val ^ fakeChallBytes[i]
	}

	//fmt.Printf("In ProveDlogEqOr, trueChallBytes: %v\n", trueChallBytes)

	// Cast the secret x as a scalar
	trueSecretScalar := new(big.Int).SetBytes(secret)

	//fmt.Printf("In ProveDlogEqOr, trueSecretScalar (redundant, but helpful): %v\n", trueSecretScalar.Uint64())

	// Cast the commitment c as a scalar
	// trueCommitScalar := new(big.Int).SetBytes(commitScalarBytes)

	// Cast chall as scalar (verifier's public coins)
	trueChallScalar := new(big.Int).SetBytes(trueChallBytes)

	//fmt.Printf("In ProveDlogEqOr, trueChallScalar is: %v\n", trueChallScalar.Uint64())

	// Compute x*chall (mod N, where N is the order of base point)
	trueBlindedScalar := new(big.Int).Mod(new(big.Int).Mul(trueSecretScalar, trueChallScalar), curveParams.N)

	//fmt.Printf("In ProveDlogEqOr, trueBlindedScalar is: %v\n", trueChallScalar.Uint64())

	// Computes z=c-chall*x (mod N, where N is the order of the base point)
	trueResult := new(big.Int).Mod(new(big.Int).Sub(trueCommitScalar, trueBlindedScalar), curveParams.N)

	//fmt.Printf("In ProveDlogEqOr, trueResult is: %v\n", trueChallScalar.Uint64())

	// Store the results into the proof structure
	if secretBit { //if secret bit is true we put honest first
		proof.Curve = curve
		proof.Result = *trueResult

		proof.BPointOther = bPointOtherCompressed
		proof.CPoint = cPointCompressed
		proof.CPointOther = cPointOtherCompressed
		proof.PPoint = pPointCompressed
		proof.PPointOther = pPointOtherCompressed

		proof.ResultOther = *fakeResult
		proof.OtherBPointOther = bPointOtherCompressed
		proof.OtherCPoint = fakeCPointCompressed
		proof.OtherCPointOther = fakeCPointOtherCompressed
		proof.OtherPPoint = fakepPointCompressed
		proof.OtherPPointOther = fakepPointOtherCompressed

		proof.VerifierChall = verifierChallBytes
		proof.ProverChall = trueChallBytes
		proof.ProverChallOther = fakeChallBytes

	} else { //Otherwise, fakes go first
		proof.Curve = curve
		proof.Result = *fakeResult
		proof.ResultOther = *trueResult

		proof.BPointOther = bPointOtherCompressed
		proof.CPoint = fakeCPointCompressed
		proof.CPointOther = fakeCPointOtherCompressed
		proof.PPoint = fakepPointCompressed
		proof.PPointOther = fakepPointOtherCompressed

		proof.OtherBPointOther = bPointOtherCompressed
		proof.OtherCPoint = cPointCompressed
		proof.OtherCPointOther = cPointOtherCompressed
		proof.OtherPPoint = pPointCompressed
		proof.OtherPPointOther = pPointOtherCompressed

		proof.VerifierChall = verifierChallBytes
		proof.ProverChall = fakeChallBytes
		proof.ProverChallOther = trueChallBytes
	}

	return &proof, nil
}

func SimulatorDlogEq(challBytes []byte, trPRG *TranscriptRng, curve elliptic.Curve, pPoint, bPointOther, pPointOther types.Point) ([]byte, []byte, []byte, *big.Int) {

	//Generate the 3rd message of the protocol first (this is the blinded scalar z)
	result := GenerateRandomBigInt(curve.Params().N)

	//fmt.Printf("In Simulator pPoint is:(%v, %v) \n", pPoint.X, pPoint.Y)
	//fmt.Printf("In Simulator bPointOther is:(%v, %v) \n", bPointOther.X, bPointOther.Y)
	//fmt.Printf("In Simulator pPointOther is:(%v, %v) \n", pPointOther.X, pPointOther.Y)
	//fmt.Printf("In Simulator chall is:%v \n", new(big.Int).SetBytes(challBytes))

	//fmt.Printf("In simulator, result (z) is %v\n", new(big.Int).Set(&result))

	// Generate the z*G point, where G is the generator
	resultbPointX, resultbPointY := curve.ScalarBaseMult(result.Bytes())

	//fmt.Printf("In Simulator z*G is:(%v, %v) \n", resultbPointX, resultbPointY)

	resultbPointOtherX, resultbPointOtherY := curve.ScalarMult(&bPointOther.X, &bPointOther.Y, result.Bytes())
	//fmt.Printf("In Simulator, z*G' is:(%v, %v) \n", resultbPointOtherX, resultbPointOtherY)

	challPpointX, challPpointY := curve.ScalarMult(&pPoint.X, &pPoint.Y, challBytes)
	challPpointOtherX, challPpointOtherY := curve.ScalarMult(&pPointOther.X, &pPointOther.Y, challBytes)

	//fmt.Printf("In Simulator, chall*P is:(%v, %v) \n", challPpointX, challPpointY)
	//fmt.Printf("In Simulator, chall*P' is:(%v, %v) \n", challPpointOtherX, challPpointOtherY)

	cPointX, cPointY := curve.Add(resultbPointX, resultbPointY, challPpointX, challPpointY)
	//fmt.Printf("In Simulator, a*G is:(%v, %v) \n", cPointX, cPointY)

	cPointOtherX, cPointOtherY := curve.Add(resultbPointOtherX, resultbPointOtherY, challPpointOtherX, challPpointOtherY)
	//fmt.Printf("In Simulator, a*G' is:(%v, %v) \n", cPointOtherX, cPointOtherY)

	cPointCompressed := elliptic.MarshalCompressed(curve, cPointX, cPointY)
	cPointOtherCompressed := elliptic.MarshalCompressed(curve, cPointOtherX, cPointOtherY)

	return cPointCompressed, cPointOtherCompressed, challBytes, &result

}

func VerifyDlogEqOr(proof *types.Proof) bool {

	proofTypeBytes := []byte(DLOG_OR_EQ_LABEL)

	// Initialize protocol transcript
	transcript := NewTranscript(DLOG_OR_EQ_LABEL)

	transcript.AppendMessage(proofTypeBytes, proof.BPointOther)
	transcript.AppendMessage(proofTypeBytes, proof.PPoint)
	transcript.AppendMessage(proofTypeBytes, proof.PPointOther)

	//Then Append the fake generated public points
	transcript.AppendMessage(proofTypeBytes, proof.OtherBPointOther)
	transcript.AppendMessage(proofTypeBytes, proof.OtherPPoint)
	transcript.AppendMessage(proofTypeBytes, proof.OtherPPointOther)

	transcript.AppendMessage(proofTypeBytes, proof.CPoint)
	transcript.AppendMessage(proofTypeBytes, proof.CPointOther)

	transcript.AppendMessage(proofTypeBytes, proof.OtherCPoint)
	transcript.AppendMessage(proofTypeBytes, proof.OtherCPointOther)

	// Derive challenge bytes based on the state of the current transcript
	verifierChallBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)
	//fmt.Printf("In VerifyDlogEqOr, DERIVED verifierChall: %v\n", verifierChallBytes)

	// Begin checking if the verifier challenge is correctly derived
	checkBytesXor := true
	for i, val := range proof.VerifierChall {
		// 1. Check if the xor of two byte streams corresponds to the byte stream from verifier
		checkBytesXor = checkBytesXor && (val == (proof.ProverChall[i] ^ proof.ProverChallOther[i]))

		// 2. Check if the derived verifier stream from the transcript and the actual stream are equal
		checkBytesXor = checkBytesXor && (val == verifierChallBytes[i])
	}

	proof01 := types.Proof{
		ProofType:     DLOG_EQ_LABEL,
		Curve:         proof.Curve,
		VerifierChall: proof.ProverChall,
		BPointOther:   proof.BPointOther,
		PPoint:        proof.PPoint,
		PPointOther:   proof.PPointOther,
		CPoint:        proof.CPoint,
		CPointOther:   proof.CPointOther,
		Result:        proof.Result,
	}

	proof02 := types.Proof{
		ProofType:     DLOG_EQ_LABEL,
		Curve:         proof.Curve,
		VerifierChall: proof.ProverChallOther,
		BPointOther:   proof.OtherBPointOther,
		PPoint:        proof.OtherPPoint,
		PPointOther:   proof.OtherPPointOther,
		CPoint:        proof.OtherCPoint,
		CPointOther:   proof.OtherCPointOther,
		Result:        proof.ResultOther,
	}

	res01 := VerifyDlogEqRelation(&proof01)
	res02 := VerifyDlogEqRelation(&proof02)
	//fmt.Printf("CheckBytesXor %v, Res01 %v, Res02 %v,", checkBytesXor, res01, res02)

	return checkBytesXor && res01 && res02

}

func VerifyDlogEqRelation(proof *types.Proof) bool {
	// Derive P from the proof
	// pPoint := types.Point{}
	pPointX, pPointY := elliptic.UnmarshalCompressed(proof.Curve, proof.PPoint)
	//fmt.Printf("In VerifyDlogEqRelation, pPoint is: (%v,%v)\n", pPoint.X, pPoint.Y)

	// Compute chall*P
	// gAddend01 := types.Point{}
	gAddend01X, gAddend01Y := proof.Curve.ScalarMult(pPointX, pPointY, proof.VerifierChall)
	//fmt.Printf("In VerifyDlogEqRelation, chall*P is: (%v,%v)\n", gAddend01.X, gAddend01.Y)

	// Compute z*G (where z=c-chall*x)
	// gAddend02 := types.Point{}
	gAddend02X, gAddend02Y := proof.Curve.ScalarBaseMult(proof.Result.Bytes())

	//fmt.Printf("In VerifyDlogEqRelation, result is: %v\n", proof.Result)
	//fmt.Printf("In VerifyDlogEqRelation, z*G is: (%v,%v)\n", gAddend02.X, gAddend02.Y)

	// Compute chall*P + z*G
	// resultFirst := types.Point{}
	resultFirstX, resultFirstY := proof.Curve.Add(gAddend01X, gAddend01Y, gAddend02X, gAddend02Y)
	//fmt.Printf("In VerifyDlogEqRelation, chall*P + z*G is: (%v,%v)\n", resultFirst.X, resultFirst.Y)

	// Begin deriving components for the check

	// gPrimeAddend01 := types.Point{}
	// pPointOther := types.Point{}
	pPointOtherX, pPointOtherY := elliptic.UnmarshalCompressed(proof.Curve, proof.PPointOther)
	//fmt.Printf("In VerifyDlogEqRelation, pPointOther is: (%v,%v)\n", pPointOther.X, pPointOther.Y)

	// Compute chall*P'
	gPrimeAddend01X, gPrimeAddend01Y := proof.Curve.ScalarMult(pPointOtherX, pPointOtherY, proof.VerifierChall)
	//fmt.Printf("In VerifyDlogEqRelation, chall*P' is: (%v,%v)\n", gPrimeAddend01.X, gPrimeAddend01.Y)

	// bPointOther := types.Point{}

	// gPrimeAddend02 := types.Point{}
	bPointOtherX, bPointOtherY := elliptic.UnmarshalCompressed(proof.Curve, proof.BPointOther)
	//fmt.Printf("In VerifyDlogEqRelation, bPointOther is: (%v,%v)\n", bPointOther.X, bPointOther.Y)

	// Compute z*G', where G' is the other base point
	gPrimeAddend02X, gPrimeAddend02Y := proof.Curve.ScalarMult(bPointOtherX, bPointOtherY, proof.Result.Bytes())
	//fmt.Printf("In VerifyDlogEqRelation, z*G' is: (%v,%v)\n", gPrimeAddend02.X, gPrimeAddend02.Y)

	// Compute chall*P' + z*G'
	// resultSecond := types.Point{}
	resultSecondX, resultSecondY := proof.Curve.Add(gPrimeAddend01X, gPrimeAddend01Y, gPrimeAddend02X, gPrimeAddend02Y)
	//fmt.Printf("In VerifyDlogEqRelation, chall*P' + z*G' is: (%v,%v)\n", resultSecond.X, resultSecond.Y)

	//Unmarshall the first message pair (first commitment message)

	cPointX, cPointY := elliptic.UnmarshalCompressed(proof.Curve, proof.CPoint)
	//fmt.Printf("In VerifyDlogEqRelation, cPoint is: (%v,%v)\n", cPoint.X, cPoint.Y)

	//Unmarshall the first message pair (second commitment message)
	// cPointOther := types.Point{}
	cPointOtherX, cPointOtherY := elliptic.UnmarshalCompressed(proof.Curve, proof.CPointOther)
	//fmt.Printf("In VerifyDlogEqRelation, cPointOther is: (%v,%v)\n", cPointOther.X, cPointOther.Y)

	//fmt.Printf("In VerifyDlogEqRelation %v, %v, %v, %v\n", cPoint.X.Cmp(resultFirst.X) == 0, cPoint.Y.Cmp(resultFirst.Y) == 0, cPointOther.X.Cmp(resultSecond.X) == 0, cPointOther.Y.Cmp(resultSecond.Y) == 0)

	return cPointX.Cmp(resultFirstX) == 0 && cPointY.Cmp(resultFirstY) == 0 && cPointOtherX.Cmp(resultSecondX) == 0 && cPointOtherY.Cmp(resultSecondY) == 0

}

/********************************************** End new additions *******************************************************************************/

func checkChallBytes(derived, actual []byte) bool {
	if len(derived) != len(actual) {
		return false
	}

	check := true
	for i := 0; i < len(derived); i++ {
		check = check && (derived[i] == actual[i])
	}
	return check

}

func checkChallBytesLists(derived, actual [][]byte) bool {
	if len(derived) != len(actual) {
		return false
	}

	check := true
	for i := 0; i < len(derived); i++ {
		check = check && checkChallBytes(derived[i], actual[i])
	}
	return check
}

//Helper functions for this class
/*********************************************************************/

func ElGamalEncryption(curve elliptic.Curve, pPoint *types.Point, rScalar *big.Int, msg *big.Int) *types.ElGamalCipherText {
	// msgPoint := types.Point{}
	// rpPoint := types.Point{}

	msgPointX, msgPointY := curve.ScalarBaseMult(msg.Bytes())
	rBytes := rScalar.Bytes()
	ct1X, ct1Y := curve.ScalarBaseMult(rBytes)
	ct1 := NewPoint(ct1X, ct1Y)

	rpPointX, rpPointY := curve.ScalarMult(&pPoint.X, &pPoint.Y, rBytes)

	// //fmt.Printf("ElGamalEncryption: rpPoint is: (%v,%v)\n", rpPoint.X, rpPoint.Y)

	ct2X, ct2Y := curve.Add(rpPointX, rpPointY, msgPointX, msgPointY)
	ct2 := NewPoint(ct2X, ct2Y)
	return &types.ElGamalCipherText{
		Ct1: ct1,
		Ct2: ct2,
	}
}

func ElGamalReEncryption(curve elliptic.Curve, pPoint *types.Point, rScalar *big.Int, cipherText *types.ElGamalCipherText) *types.ElGamalCipherText {
	rBytes := rScalar.Bytes()
	ct1X, ct1Y := curve.ScalarBaseMult(rBytes)

	ct1X, ct1Y = curve.Add(ct1X, ct1Y, &cipherText.Ct1.X, &cipherText.Ct1.Y)

	ct1 := NewPoint(ct1X, ct1Y)

	rpPointX, rpPointY := curve.ScalarMult(&pPoint.X, &pPoint.Y, rBytes)

	// //fmt.Printf("ElGamalReEncryption: rpPoint is: (%v,%v)\n", rpPoint.X, rpPoint.Y)

	ct2X, ct2Y := curve.Add(rpPointX, rpPointY, &cipherText.Ct2.X, &cipherText.Ct2.Y)
	ct2 := NewPoint(ct2X, ct2Y)
	return &types.ElGamalCipherText{
		Ct1: ct1,
		Ct2: ct2,
	}
}

func ElGamalVoteReEncryption(curve elliptic.Curve, pPoint *types.Point, rScalar *big.Int, vote types.VoteMessage) types.VoteMessage {

	ct := ElGamalReEncryption(curve, pPoint, rScalar, &vote.EncryptedVote)

	return types.VoteMessage{
		ElectionID:       vote.ElectionID,
		EncryptedVote:    *ct,
		CorrectVoteProof: vote.CorrectVoteProof,
		CorectEncProof:   vote.CorectEncProof,
	}
}
