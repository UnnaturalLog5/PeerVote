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
	"fmt"
	"math/big"

	"golang.org/x/xerrors"
)

const (
	DLOG_LABEL       = "dlog_LABEL"
	DLOG_EQ_LABEL    = "dlog_EQ_LABEL"
	DLOG_OR_LABEL    = "dlog_OR_LABEL"
	SHUFFLE_LABEL    = "shuffle_LABEL"
	SHUFFLE_01_LABEL = "shuffle_01_LABEL"
	SHUFFLE_02_LABEL = "shuffle_02_LABEL"
	SHUFFLE_03_LABEL = "shuffle_03_LABEL"
	SHUFFLE_04_LABEL = "shuffle_04_LABEL"

	SCALAR_SIZE = 32
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type Value []byte

type Proof struct {
	proofType        string
	curve            elliptic.Curve
	bPointOther      []byte //basePointOther (for equality proof)
	pPoint           []byte //publicPoint
	pPointOther      []byte //publicPointOther (for equality proof)
	cPoint           []byte //commitPoint
	cPointOther      []byte //commitPointOhter (for equality proof)
	verifierChall    []byte //verifier's public coins issued in the OR proof
	proverChall      []byte //prover's derived public coins for the first statement
	proverChallOther []byte //prover's derived public coins for the second statement
	result           big.Int
	resultOther      big.Int
}

type ShuffleInstance struct {
	Curve    elliptic.Curve
	pPoint   Point
	ctBefore []ElGamalCipherText
	ctAfter  []ElGamalCipherText
}

type ShuffleWitness struct {
	PermList       []uint32
	RandomizerList []*big.Int
}

type ShuffleProof struct {
	ProofType          string
	instance           *ShuffleInstance
	verifierChallList  [][]byte
	tPoint             []byte
	vPoint             []byte
	wPoint             []byte
	uPoint             []byte
	uPointListBytes    [][]byte
	gPrimePoint        []byte
	mPrimePoint        []byte
	tCapPointListBytes [][]byte
	vCapPointListBytes [][]byte
	vCapPoint          []byte
	wCapPointListBytes [][]byte
	wCapPoint          []byte
	sZeroScalar        *big.Int
	sList              []*big.Int
	dScalar            *big.Int
}

type ElGamalCipherText struct {
	ct1 Point
	ct2 Point
}

func (ct *ElGamalCipherText) GetCt1() Point {
	return ct.ct1
}

func (ct *ElGamalCipherText) GetCt2() Point {
	return ct.ct2
}

func NewPoint(px, py *big.Int) Point {
	return Point{
		X: px,
		Y: py,
	}
}

func NewProof(proofType string) Proof {
	return Proof{
		proofType: proofType,
	}
}

func NewProofExtended(proofType string, curve elliptic.Curve, pPoint, cPoint, challBytes []byte, result *big.Int) *Proof {
	return &Proof{
		proofType:     proofType,
		curve:         curve,
		pPoint:        pPoint,
		cPoint:        cPoint,
		verifierChall: challBytes,
		result:        *result,
	}
}

func NewShuffleInstance(curve elliptic.Curve, pPoint Point, ctBefore, ctAfter []ElGamalCipherText) *ShuffleInstance {
	return &ShuffleInstance{
		Curve:    curve,
		pPoint:   pPoint,
		ctBefore: ctBefore,
		ctAfter:  ctAfter,
	}
}

func NewShuffleWitness(permList []uint32, randomizerList []*big.Int) *ShuffleWitness {
	return &ShuffleWitness{
		PermList:       permList,
		RandomizerList: randomizerList,
	}
}

// The function computes the non-interactive proof of knowledge of the DLOG (a.k.a Schnorr's proof)
func ProveDlog(secret Value, pPoint Point, curve elliptic.Curve) (*Proof, error) {

	// Derive parameters of the elliptic curve
	curveParams := curve.Params()

	// Marshal the instance point in order to place it into the protocol transcript
	pPointCompressed := elliptic.MarshalCompressed(curve, pPoint.X, pPoint.Y)

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
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.proofType), secret)
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.proofType), commitRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {
		return nil, xerrors.Errorf("Error in ProveDlog: %v\n", err)
	}
	commitScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)
	fmt.Printf("In ProveDlog, commitScalarBytes length: %v\n", len(commitScalarBytes))

	cPoint := Point{}

	// Create commitment Point (cPoint=c*B, where B is the base point of the curve)
	cPoint.X, cPoint.Y = curve.ScalarBaseMult(commitScalarBytes)
	cPointCompressed := elliptic.MarshalCompressed(curve, cPoint.X, cPoint.Y)

	// Append derived cPoint to the protocol transcript
	transcript.AppendMessage(proofTypeBytes, cPointCompressed)

	// Derive public coins (challenge bytes) from the verifier based on the current
	// Trancript state
	challScalarBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)
	fmt.Printf("In VerifyDlog, challScalarBytes: %v\n", challScalarBytes)

	// Cast scalars as big.Ints
	secretScalar := new(big.Int).SetBytes(secret)
	challScalar := new(big.Int).SetBytes(challScalarBytes)
	commitScalar := new(big.Int).SetBytes(commitScalarBytes)

	// Computes chall*x (as scalars mod N, where N is the order of the base point)
	blindedScalar := new(big.Int).Mod(new(big.Int).Mul(secretScalar, challScalar), curveParams.N)

	// Computes z=chall*x+c (as scalars mod N, where N is the order of the base point)
	result := new(big.Int).Mod(new(big.Int).Add(commitScalar, blindedScalar), curveParams.N)

	// Store into the proof
	proof.curve = curve
	proof.pPoint = pPointCompressed
	proof.cPoint = cPointCompressed
	proof.result = *result

	fmt.Printf("In ProveDlog, pPoint: %v\n", proof.pPoint)
	fmt.Printf("In ProveDlog, cPoint: %v\n", proof.cPoint)
	fmt.Printf("In ProveDlog, result: %v\n", proof.result)
	return &proof, nil
}

// Verifies the Schnorr's non-interactive proof of the knowledge of DLOG
func VerifyDlog(proof *Proof) (bool, error) {
	// Recreate the state of the transcript to get challenge scalar
	transcript := NewTranscript(proof.proofType)
	proofTypeBytes := []byte(proof.proofType)

	// Appends information about the proof instance
	transcript.AppendMessage(proofTypeBytes, proof.pPoint)

	// Appends the commitment point (the first message of the protocol)
	transcript.AppendMessage(proofTypeBytes, proof.cPoint)

	// Derives verifier's challenge based on the current transcript state
	challBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)
	fmt.Printf("In VerifyDlog, challBytes: %v\n", challBytes)

	// Create placeholder for the l.h.s and the r.h.s of the final check
	point01 := Point{}
	point02 := Point{}

	// Create placeholder for the instance Pand the commitment Point in the proof
	pPoint := Point{}
	cPoint := Point{}

	// Computes z*G, where G is the base point, and z (a.k.a result) is z=chall*x+c
	// This is what is "received" by the verifier from the prover
	point01.X, point01.Y = proof.curve.ScalarBaseMult(proof.result.Bytes())

	// Unmarshalls both pPoint = x*G and cPoint = c*G
	pPoint.X, pPoint.Y = elliptic.UnmarshalCompressed(proof.curve, proof.pPoint)
	cPoint.X, cPoint.Y = elliptic.UnmarshalCompressed(proof.curve, proof.cPoint)

	// Computes chall*x*G
	point02.X, point02.Y = proof.curve.ScalarMult(pPoint.X, pPoint.Y, challBytes)

	// Computes c*G+(chall*x)*G
	point02.X, point02.Y = proof.curve.Add(point02.X, point02.Y, cPoint.X, cPoint.Y)

	// Finally compare if the claimed value (point01) is equal to the actual value (point02)
	return point01.X.Cmp(point02.X) == 0 && point01.Y.Cmp(point02.Y) == 0, nil
}

// Proves that the two values P = x*G and P' = x*G' have the same DLOG x (a.k.a the Chaum-Pedersen proof)
// Essentially, this corresponds to running two Schnorr proofs in parallel.
// For details, see e.x: https://crypto.stackexchange.com/questions/99262/chaum-pedersen-protocol
func ProveDlogEq(secret Value, pPoint Point, bPointOther Point, pPointOther Point, curve elliptic.Curve) (*Proof, error) {

	// Derive parameters of the elliptic curve
	curveParams := curve.Params()

	// Marshall proof instance to bytes
	pPointCompressed := elliptic.MarshalCompressed(curve, pPoint.X, pPoint.Y)
	bPointOtherCompressed := elliptic.MarshalCompressed(curve, bPointOther.X, bPointOther.Y)
	pPointOtherCompressed := elliptic.MarshalCompressed(curve, pPointOther.X, pPointOther.Y)

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
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.proofType), secret)
	trPRGbuilder.RekeyWitnessBytes([]byte(proof.proofType), commitRandSeed.Bytes())
	trPrg, err := trPRGbuilder.Finalize(proofTypeBytes)
	if err != nil {

	}

	commitScalarBytes := trPrg.GetRandomness(SCALAR_SIZE)

	// Create placeholders for the two commitment points
	cPoint := Point{}
	cPointOther := Point{}

	// Compute cPoint = c*G where G is the base point of the curve
	cPoint.X, cPoint.Y = curve.ScalarBaseMult(commitScalarBytes)
	cPointCompressed := elliptic.MarshalCompressed(curve, cPoint.X, cPoint.Y)

	// Compute cPoint = c*G' where G' is the base point of the curve (and G != G')
	cPointOther.X, cPointOther.Y = curve.ScalarMult(bPointOther.X, bPointOther.Y, commitScalarBytes)
	cPointOtherCompressed := elliptic.MarshalCompressed(curve, cPointOther.X, cPointOther.Y)

	// Append derived commitment points to the transcript
	transcript.AppendMessage(proofTypeBytes, cPointCompressed)
	transcript.AppendMessage(proofTypeBytes, cPointOtherCompressed)

	// Derive a public coin challenge based on the current state of the transcript
	challScalarBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	// Cast scalars as big.Ints
	secretScalar := new(big.Int).SetBytes(secret)
	commitScalar := new(big.Int).SetBytes(commitScalarBytes)
	challScalar := new(big.Int).SetBytes(challScalarBytes)

	// Computes chall*x (mod N, where N is the order of the base point)
	blindedScalar := new(big.Int).Mod(new(big.Int).Mul(secretScalar, challScalar), curveParams.N)

	// Computes z=c-chall*x (mod N, where N is the order of the base point)
	result := new(big.Int).Mod(new(big.Int).Sub(commitScalar, blindedScalar), curveParams.N)

	// Store the results into the proof structure
	proof.curve = curve
	proof.bPointOther = bPointOtherCompressed
	proof.pPoint = pPointCompressed
	proof.pPointOther = pPointOtherCompressed
	proof.cPoint = cPointCompressed
	proof.cPointOther = cPointOtherCompressed
	proof.result = *result

	return &proof, nil
}

// Verifies that the two values P = x*G and P' = x*G' have the same DLOG x (a.k.a the Chaum-Pedersen proof)
func VerifyDlogEq(proof *Proof) (bool, error) {

	// Recreate the state of the transcript to get challenge scalar
	transcript := NewTranscript(proof.proofType)
	proofTypeBytes := []byte(proof.proofType)

	// Appends information about the proof instance
	transcript.AppendMessage(proofTypeBytes, proof.bPointOther)
	transcript.AppendMessage(proofTypeBytes, proof.pPoint)
	transcript.AppendMessage(proofTypeBytes, proof.pPointOther)

	// Append commitment points (the first message pair of the protocol)
	transcript.AppendMessage(proofTypeBytes, proof.cPoint)
	transcript.AppendMessage(proofTypeBytes, proof.cPointOther)

	// Generate public challege from the current state of the transcript
	challBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)

	// Begin deriving components for checking if P = x*G

	// Derive P from the proof
	pPoint := Point{}
	pPoint.X, pPoint.Y = elliptic.UnmarshalCompressed(proof.curve, proof.pPoint)

	// Compute chall*P
	gAddend01 := Point{}
	gAddend01.X, gAddend01.Y = proof.curve.ScalarMult(pPoint.X, pPoint.Y, challBytes)

	// Compute z*G (where z=c-chall*x)
	gAddend02 := Point{}
	gAddend02.X, gAddend02.Y = proof.curve.ScalarBaseMult(proof.result.Bytes())

	// Compute chall*P + z*G
	resultFirst := Point{}
	resultFirst.X, resultFirst.Y = proof.curve.Add(gAddend01.X, gAddend01.Y, gAddend02.X, gAddend02.Y)

	// Begin deriving components for checking if P=x*G

	gPrimeAddend01 := Point{}
	pPointOther := Point{}
	pPointOther.X, pPointOther.Y = elliptic.UnmarshalCompressed(proof.curve, proof.pPointOther)
	gPrimeAddend01.X, gPrimeAddend01.Y = proof.curve.ScalarMult(pPointOther.X, pPointOther.Y, challBytes)

	// Checks for the other pair (corresponds to checks for G')
	bPointOther := Point{}
	gPrimeAddend02 := Point{}
	bPointOther.X, bPointOther.Y = elliptic.UnmarshalCompressed(proof.curve, proof.bPointOther)
	gPrimeAddend02.X, gPrimeAddend02.Y = proof.curve.ScalarMult(bPointOther.X, bPointOther.Y, proof.result.Bytes())

	resultSecond := Point{}
	resultSecond.X, resultSecond.Y = proof.curve.Add(gPrimeAddend01.X, gPrimeAddend01.Y, gPrimeAddend02.X, gPrimeAddend02.Y)

	cPoint := Point{}
	cPoint.X, cPoint.Y = elliptic.UnmarshalCompressed(proof.curve, proof.cPoint)

	cPointOther := Point{}
	cPointOther.X, cPointOther.Y = elliptic.UnmarshalCompressed(proof.curve, proof.cPointOther)
	return cPoint.X.Cmp(resultFirst.X) == 0 && cPoint.Y.Cmp(resultFirst.Y) == 0 &&
		cPointOther.X.Cmp(resultSecond.X) == 0 && cPointOther.Y.Cmp(resultSecond.Y) == 0, nil

}

// Computes the non-interactive zero-knowledge proof that secret x is the DLOG of either P or P'
// The proof generation can be parsed into the two cases:
// 1. For the true case: Run the regular Schnorr protocol
// 2. For the fake case: Use simulator to create an accepting transcript
func ProveDlogOr(secret Value, pPoint Point, secretOther Value, pPointOther Point, secretBit bool, curve elliptic.Curve) (*Proof, error) {

	curveParams := curve.Params()
	var trueSecret Value
	var truepPoint Point
	var fakepPoint Point
	if secretBit {
		trueSecret = secret
		truepPoint = pPoint
		fakepPoint = pPointOther
	} else {
		trueSecret = secretOther
		truepPoint = pPointOther
		fakepPoint = pPoint
	}

	// fmt.Printf("In ProveDlogOr, trueSecret is: %v \n ", trueSecret)
	// fmt.Printf("In ProveDlogOr, truepPoint is: (%v, %v) \n ", pPoint.X, pPoint.Y)
	// fmt.Printf("In ProveDlogOr, fakepPoint is: (%v, %v) \n ", pPointOther.X, pPointOther.Y)

	// Marshall the information about the proof instance
	pPointCompressed := elliptic.MarshalCompressed(curve, pPoint.X, pPoint.Y)
	pPointOtherCompressed := elliptic.MarshalCompressed(curve, pPointOther.X, pPointOther.Y)

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
	cPoint := Point{}
	cPoint.X, cPoint.Y = curve.ScalarBaseMult(commitScalarBytes)
	cPointCompressed := elliptic.MarshalCompressed(curve, cPoint.X, cPoint.Y)

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
	fmt.Printf("In ProveDlogOr, fakeChallBytes: %v\n", fakeChallBytes)

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
	fmt.Printf("In ProveDlogOr, trueChallBytes: %v\n", trueChallBytes)

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

	truepPointCompressed := elliptic.MarshalCompressed(curve, truepPoint.X, truepPoint.Y)
	fakepPointCompressed := elliptic.MarshalCompressed(curve, fakepPoint.X, fakepPoint.Y)

	if secretBit {
		proof.curve = curve
		proof.result = *trueResult
		proof.resultOther = *fakeResult
		proof.cPoint = cPointCompressed
		proof.cPointOther = fakeCPointCompressed
		proof.pPoint = truepPointCompressed
		proof.pPointOther = fakepPointCompressed
		proof.verifierChall = verifierChallBytes
		proof.proverChall = trueChallBytes
		proof.proverChallOther = fakeChallBytes

	} else {
		proof.curve = curve
		proof.result = *fakeResult
		proof.resultOther = *trueResult
		proof.cPoint = fakeCPointCompressed
		proof.cPointOther = cPointCompressed
		proof.pPoint = fakepPointCompressed
		proof.pPointOther = truepPointCompressed
		proof.verifierChall = verifierChallBytes
		proof.proverChall = fakeChallBytes
		proof.proverChallOther = trueChallBytes
	}

	return &proof, nil
}

// Verifies that one of the two proof instances satisfies the DLOG relation
// (a.k.a the OR-proof for the DLOG relation)
func VerifyDlogOr(proof *Proof) (bool, error) {

	proofTypeBytes := []byte(DLOG_OR_LABEL)

	// Initialize protocol transcript
	transcript := NewTranscript(DLOG_OR_LABEL)

	// Append public parameters corresponding to the
	transcript.AppendMessage(proofTypeBytes, proof.pPoint)
	transcript.AppendMessage(proofTypeBytes, proof.pPointOther)

	// Append the commitment points to the trasncript
	transcript.AppendMessage(proofTypeBytes, proof.cPoint)
	transcript.AppendMessage(proofTypeBytes, proof.cPointOther)

	fmt.Printf("In VerifyDlog, proverChall: %v\n", proof.proverChall)
	fmt.Printf("In VerifyDlog, proverChallOther: %v\n", proof.proverChallOther)
	fmt.Printf("In VerifyDlog, PROOF verifierChall: %v\n", proof.verifierChall)

	// Derive challenge bytes based on the state of the current transcript
	verifierChallBytes := transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE)
	fmt.Printf("In VerifyDlog, DERIVED verifierChall: %v\n", verifierChallBytes)

	// Begin checking if the verifier challenge is correctly derived
	checkBytesXor := true
	for i, val := range proof.verifierChall {
		// 1. Check if the xor of two byte streams corresponds to the byte stream from verifier
		checkBytesXor = checkBytesXor && (val == (proof.proverChall[i] ^ proof.proverChallOther[i]))

		// 2. Check if the derived verifier stream from the transcript and the actual stream are equal
		checkBytesXor = checkBytesXor && (val == verifierChallBytes[i])
	}

	// Create two proof instances which need to be checked

	proof01 := Proof{}
	proof01.curve = proof.curve
	proof01.pPoint = proof.pPoint
	proof01.cPoint = proof.cPoint
	proof01.verifierChall = proof.proverChall
	proof01.result = proof.result

	proof02 := Proof{}
	proof02.curve = proof.curve
	proof02.pPoint = proof.pPointOther
	proof02.cPoint = proof.cPointOther
	proof02.verifierChall = proof.proverChallOther
	proof02.result = proof.resultOther

	// Both proof instances need to satisfy the DLOG (Schnorr's proof check)
	res01 := VerifyDlogRelation(&proof01)
	res02 := VerifyDlogRelation(&proof02)

	fmt.Printf("In VerifyDlogOr, checkBytesXor result %v\n", checkBytesXor)
	fmt.Printf("In VerifyDlogOr, VerifyDlogRelation for proof01 result: %v\n", res01)
	fmt.Printf("In VerifyDlogOr, VerifyDlogRelation for proof02 result %v\n", res02)

	// Return the AND of all the checks as a result
	return checkBytesXor && res01 && res02, nil
}

// Based on the choise of the chall, derives the fake simulated (a.k.a) fake transcript for the Schnorr's proof
// Utilizes the c-simultability property of the Sigma protocols
func SimulatorDlog(challBytes []byte, trPRG *TranscriptRng, pPoint Point, curve elliptic.Curve) ([]byte, []byte, *big.Int) {

	curveParams := curve.Params()

	// Derive scalar z
	blindBytes := trPRG.GetRandomness(SCALAR_SIZE)
	blindScalar := new(big.Int).SetBytes(blindBytes)
	blindScalar = blindScalar.Mod(blindScalar, curveParams.N)

	// Compute z*G
	blindPoint := Point{}
	fmt.Printf("In SimulatorDlog, multiplying base point with value %v\n", blindScalar.Bytes())
	blindPoint.X, blindPoint.Y = curve.ScalarBaseMult(blindScalar.Bytes())

	// Compute -chall*P, where P is the point from the proof intance
	minusOneScalar := new(big.Int).Sub(curveParams.N, big.NewInt(1))
	challScalar := new(big.Int).SetBytes(challBytes)

	// Create placeholder for the -chall*P point
	challpPoint := Point{}

	// First compute -P given P
	challpPoint.X, challpPoint.Y = curve.ScalarMult(pPoint.X, pPoint.Y, minusOneScalar.Bytes())

	// Then computer chall*(-P)
	challpPoint.X, challpPoint.Y = curve.ScalarMult(challpPoint.X, challpPoint.Y, challScalar.Bytes())

	// Finally compute the the first message (in the original proof c*G)
	// As: c*G = z*G - chall*P
	cPoint := Point{}
	cPoint.X, cPoint.Y = curve.Add(blindPoint.X, blindPoint.Y, challpPoint.X, challpPoint.Y)
	cPointCompressed := elliptic.MarshalCompressed(curve, cPoint.X, cPoint.Y)

	fmt.Printf("In SimulatorDlog, BlindScalar value %v\n", blindScalar.Bytes())
	fmt.Printf("In SimulatorDlog, Is blindPoint on curve: %v\n", curve.IsOnCurve(blindPoint.X, blindPoint.Y))
	fmt.Printf("In SimulatorDlog, Is challpPoint on curve: %v\n", curve.IsOnCurve(challpPoint.X, challpPoint.Y))
	fmt.Printf("In SimulatorDlog, Is cPoint on curve: %v\n", curve.IsOnCurve(cPoint.X, cPoint.Y))

	fmt.Printf("In SimulatorDlog, blindPoint coordinates: (%v, %v) \n", blindPoint.X, blindPoint.Y)
	fmt.Printf("In SimulatorDlog, challpPoint coordinates: (%v, %v) \n", challpPoint.X, challpPoint.Y)
	fmt.Printf("In SimulatorDlog, cPoint coordinates: (%v, %v) \n", cPoint.X, cPoint.Y)

	fmt.Printf("In SimulatorDlog, cPointCompressed %v\n", cPointCompressed)
	fmt.Printf("In SimulatorDlog, challBytes %v\n", challBytes)
	fmt.Printf("In SimulatorDlog, blindScalar %v\n", blindScalar.Bytes())
	return cPointCompressed, challBytes, blindScalar
}

// Verifies that the values stored in the proof satisfies the DLOG (Schnorr's) relation
func VerifyDlogRelation(proof *Proof) bool {
	curve := proof.curve

	// Create the placeholder for the l.h.s and the r.h.s of the check
	pointlhs := Point{}
	pointrhs := Point{}

	// Create the placholders for the proof instance and commitment point
	pPoint := Point{}
	cPoint := Point{}

	fmt.Printf("In VerifyDlogRelation, cPointCompressed %v\n", proof.cPoint)
	fmt.Printf("In VerifyDlogRelation, challBytes %v\n", proof.verifierChall)
	fmt.Printf("In VerifyDlogRelation, blindScalar %v\n", proof.result.Bytes())

	fmt.Printf("In VerifyDlogRelation result scalar: %v\n", proof.result.Bytes())

	fmt.Printf("In VerifyDlogRelation, multiplying base point with value %v\n", proof.result.Bytes())

	// Computes z*G, which acts as the l.h.s of the check
	pointlhs.X, pointlhs.Y = curve.ScalarBaseMult(proof.result.Bytes())

	// Cast the proof instance and the commitment point as Point structs
	pPoint.X, pPoint.Y = elliptic.UnmarshalCompressed(curve, proof.pPoint)
	cPoint.X, cPoint.Y = elliptic.UnmarshalCompressed(curve, proof.cPoint)

	//Compute the r.h.s as a chall*P+cPoint
	pointrhs.X, pointrhs.Y = proof.curve.ScalarMult(pPoint.X, pPoint.Y, proof.verifierChall)
	pointrhs.X, pointrhs.Y = proof.curve.Add(pointrhs.X, pointrhs.Y, cPoint.X, cPoint.Y)

	fmt.Printf("In VerifyDlogRelation, Comparing X points %v\n", pointlhs.X.Cmp(pointrhs.X) == 0)
	fmt.Printf("In VerifyDlogRelation, Comparing Y points %v\n", pointlhs.Y.Cmp(pointrhs.Y) == 0)

	//Finally, check if the l.h.s and the r.h.s match
	return pointlhs.X.Cmp(pointrhs.X) == 0 && pointlhs.Y.Cmp(pointrhs.Y) == 0
}

func Verify(proof *Proof) (bool, error) {

	var result bool
	var err error
	switch proof.proofType {
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
func ProveShuffle(instance *ShuffleInstance, witness *ShuffleWitness) (*ShuffleProof, error) {
	curveParams := instance.Curve.Params()
	proofTypeBytes := []byte(SHUFFLE_LABEL)

	transcript := NewTranscript(SHUFFLE_LABEL)

	// Initialize transcript with the proof instance (which consists)
	pPointCompressed := elliptic.MarshalCompressed(instance.Curve, instance.pPoint.X, instance.pPoint.Y)

	// If a ciphertext consists of a pair ct=(ct_1, ct_2), then these are
	// The lists of ct_2,s for each ciphertext
	reEncBeforeList := MakeReencList(instance.ctBefore)
	reEncAfterList := MakeReencList(instance.ctAfter)

	// If a ciphertext consists of a pair ct=(ct_1, ct_2), then these are
	// The lists of ct_2,s for each ciphertext
	ctMsgBeforeList := MakeCtMsgList(instance.ctBefore)
	ctMsgAfterList := MakeCtMsgList(instance.ctAfter)

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

	byteRandList, err := MarshalBIntList(witness.RandomizerList)
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

	fmt.Printf("In ProveShuffle, public point is: (%v,%v)\n", instance.pPoint.X, instance.pPoint.Y)
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
	tPoint := Point{}
	vPoint := Point{}
	wPoint := Point{}
	uPoint := Point{}

	tPoint.X, tPoint.Y = instance.Curve.ScalarBaseMult(tauScalarBytes)
	vPoint.X, vPoint.Y = instance.Curve.ScalarBaseMult(thetaScalarBytes)
	wPoint.X, wPoint.Y = instance.Curve.ScalarBaseMult(sigmaScalarBytes)
	uPoint.X, uPoint.Y = instance.Curve.ScalarBaseMult(lambdaScalarBytes)

	fmt.Printf("In ProveShuffle, tauScalar is: %v\n", new(big.Int).SetBytes(tauScalarBytes))
	fmt.Printf("In ProveShuffle, thetaScalar is: %v\n", new(big.Int).SetBytes(thetaScalarBytes))
	fmt.Printf("In ProveShuffle, sigmaScalar is: %v\n", new(big.Int).SetBytes(sigmaScalarBytes))
	fmt.Printf("In ProveShuffle, lambdaScalar is: %v\n", new(big.Int).SetBytes(lambdaScalarBytes))

	fmt.Printf("In ProveShuffle, tPoint result is (%v,%v)\n", tPoint.X, tPoint.Y)
	fmt.Printf("In ProveShuffle, vPoint result is (%v,%v)\n", vPoint.X, vPoint.Y)
	fmt.Printf("In ProveShuffle, wPoint result is (%v,%v)\n", wPoint.X, wPoint.Y)
	fmt.Printf("In ProveShuffle, uPoint result is (%v,%v)\n", uPoint.X, uPoint.Y)

	// Prover STEP 01: Compute U_i = \lambda_i * G, where G is the base point
	uPointList := make([]Point, 0)
	for i := 0; i < len(witness.PermList); i++ {
		uP := Point{}
		fmt.Printf("In ProveShuffle, for index %d, lambdaScalar[i] is: %v\n", i, new(big.Int).SetBytes(lambdaList[i]))
		uP.X, uP.Y = instance.Curve.ScalarBaseMult(lambdaList[i])
		fmt.Printf("In ProveShuffle, for index %d uPoint result is (%v,%v)\n", i, uP.X, uP.Y)
		uPointList = append(uPointList, uP)
	}

	// Prover STEP 01: Compute G'=\phi*G + \sum_i \phi_i*ct_{i,1}

	//First compute the \phi*G
	gPrimePoint := Point{}
	gPrimePoint.X, gPrimePoint.Y = instance.Curve.ScalarBaseMult(phiScalarBytes)
	fmt.Printf("In ProveShuffle, PhiScalar is: %v\n", new(big.Int).SetBytes(phiScalarBytes))
	fmt.Printf("In ProveShuffle, gPrimePoint, initial result is (%v,%v)\n", gPrimePoint.X, gPrimePoint.Y)

	// Then compute the sum by calcluating addends and add them at each step to the running value of G'
	for i := 0; i < len(witness.PermList); i++ {
		addend := Point{}
		fmt.Printf("In ProveShuffle, for i: %d, PhiScalar[i] is: %v\n", i, new(big.Int).SetBytes(phiList[i]))
		fmt.Printf("In ProveShuffle, for i: %d, reEncBeforeList[i] is (%v,%v)\n", i, reEncBeforeList[i].X, reEncBeforeList[i].Y)

		addend.X, addend.Y = instance.Curve.ScalarMult(reEncBeforeList[i].X, reEncBeforeList[i].Y, phiList[i])

		fmt.Printf("In ProveShuffle, for i: %d, addend for gPrimePoint is (%v,%v)\n", i, addend.X, addend.Y)

		gPrimePoint.X, gPrimePoint.Y = instance.Curve.Add(gPrimePoint.X, gPrimePoint.Y, addend.X, addend.Y)

		fmt.Printf("In ProveShuffle, gPrimePoint, partial result is (%v,%v)\n", gPrimePoint.X, gPrimePoint.Y)
	}
	fmt.Printf("In ProveShuffle, gPrimePoint final result is (%v,%v)\n", gPrimePoint.X, gPrimePoint.Y)

	//Compute M'=\phi*P + \sum_i \phi_i*ct_{i,2}

	//First compute  \phi*P
	mPrimePoint := Point{}
	mPrimePoint.X, mPrimePoint.Y = instance.Curve.ScalarMult(instance.pPoint.X, instance.pPoint.Y, phiScalarBytes)
	fmt.Printf("In ProveShuffle, mPrimePoint initial result is (%v,%v)\n", mPrimePoint.X, mPrimePoint.Y)

	// Then compute the sum by calcluating addends and add them at each step to the running value of M'
	for i := 0; i < len(instance.ctBefore); i++ {
		// Computes addend = phi[i] * ct_{i,2}
		addend := Point{}
		addend.X, addend.Y = instance.Curve.ScalarMult(ctMsgBeforeList[i].X, ctMsgBeforeList[i].Y, phiList[i])
		fmt.Printf("In ProveShuffle, reEncBlindedPoint result is (%v,%v)\n", addend.X, addend.Y)
		mPrimePoint.X, mPrimePoint.Y = instance.Curve.Add(mPrimePoint.X, mPrimePoint.Y, addend.X, addend.Y)
		fmt.Printf("In ProveShuffle, mPrimePoint partial result is (%v,%v)\n", mPrimePoint.X, mPrimePoint.Y)
	}
	fmt.Printf("In ProveShuffle, mPrimePoint final result is (%v,%v)\n", mPrimePoint.X, mPrimePoint.Y)

	// Compute \cap{T_i}
	tauScalar := new(big.Int).SetBytes(tauScalarBytes)
	fmt.Printf("In ProveShuffle, tauScalar is: %v\n", tauScalar)

	tCapPointList := make([]Point, 0)
	for i := 0; i < len(witness.PermList); i++ {
		tCapBlindPoint := Point{}

		// Derive \lambda_i
		lambdaListScalar := new(big.Int).SetBytes(lambdaList[i])

		fmt.Printf("In ProveShuffle, for i: %d, lambdaList[i] is: %v\n", i, lambdaListScalar)
		// Compute product of tau*lambda_i
		tauLambdaScalar := new(big.Int).SetUint64(0)
		tauLambdaScalar.Mul(tauScalar, lambdaListScalar)
		tauLambdaScalar.Mod(tauLambdaScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, for i: %d, tauLambdaScalar is: %v\n", i, tauLambdaScalar)

		// Find the image of i under the secret permutation \pi
		permImg := witness.PermList[i]

		// Derive phi_{\pi(i)} as a scalar
		phiListScalar := new(big.Int).SetBytes(phiList[permImg])
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, chosen phiScalar is: %v\n", i, permImg, phiListScalar)

		//Compute resultScalar =  3*phi_{\pi(i)}
		threeScalar := new(big.Int).SetUint64(3)
		resultScalar := new(big.Int).SetUint64(0)
		resultScalar.Mul(threeScalar, phiListScalar)
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (after *3) is: %v\n", i, permImg, resultScalar)

		//Set resultScalar=resultScalar+tau*Lambda_i
		resultScalar.Add(resultScalar, tauLambdaScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (after adding tauLambda) final is: %v\n", i, permImg, resultScalar)

		//Compute result \cap{T_i} = result*G
		tCapBlindPoint.X, tCapBlindPoint.Y = instance.Curve.ScalarBaseMult(resultScalar.Bytes())
		fmt.Printf("In ProveShuffle, for i: %d, tCapBlindedPoint[i] is (%v,%v)\n", i, tCapBlindPoint.X, tCapBlindPoint.Y)
		tCapPointList = append(tCapPointList, tCapBlindPoint)
	}

	//Compute \cap{V_i}

	//First derive \theta as a scalar
	thetaScalar := new(big.Int).SetBytes(thetaScalarBytes)
	vCapPointList := make([]Point, 0)
	fmt.Printf("In ProveShuffle, thetaScalar is: %v\n", thetaScalar)

	for i := 0; i < len(witness.PermList); i++ {
		vCapBlindedPoint := Point{}
		// Set the placeholder for \theta * r_i
		thetaRScalar := new(big.Int).SetUint64(0)

		//Derive r_i as a scalar
		rScalar := witness.RandomizerList[i]

		fmt.Printf("In ProveShuffle, for i: %d, rScalar is: %v\n", i, rScalar)

		//Compute  \theta * r_i
		thetaRScalar = thetaRScalar.Mul(thetaScalar, rScalar)
		thetaRScalar = thetaRScalar.Mod(thetaRScalar, curveParams.N)

		fmt.Printf("In ProveShuffle, for i: %d, thetaRsalar is: %v\n", i, thetaRScalar)

		// Find the image of i under the secret permutation \pi
		permImg := witness.PermList[i]

		// Derive phi_{\pi(i)} as a scalar
		phiListScalar := new(big.Int).SetBytes(phiList[permImg])
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, chosen phiScalar is: %v\n", i, permImg, phiListScalar)

		// Set 3 as a scalar
		threeScalar := new(big.Int).SetUint64(3)

		// Compute the exponent of the vCapPointList
		resultScalar := new(big.Int).SetUint64(0)
		// Compute result = phi_{\pi(i)} * phi_{\pi(i)}
		resultScalar.Mul(phiListScalar, phiListScalar)
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (phi*phi) is: %v\n", i, permImg, resultScalar)

		// Compute result = 3 * phi_{\pi(i)} * phi_{\pi(i)}
		resultScalar.Mul(threeScalar, resultScalar)
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar (3*phi*phi) is: %v\n", i, permImg, resultScalar)

		// Compute result = result + (r_i * theta)
		resultScalar.Add(resultScalar, thetaRScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, for i: %d, chosen permImg %d, resultScalar *final(3*phi*phi+r_i * theta) is: %v\n", i, permImg, resultScalar)

		// Compute the point and add it to the vCapPointList
		vCapBlindedPoint.X, vCapBlindedPoint.Y = instance.Curve.ScalarBaseMult(resultScalar.Bytes())
		fmt.Printf("In ProveShuffle, for i: %d, vCapBlindedPoint[i] is (%v,%v)\n", i, vCapBlindedPoint.X, vCapBlindedPoint.Y)

		vCapPointList = append(vCapPointList, vCapBlindedPoint)
	}

	//Compute \cap{V}
	vCapPoint := Point{}

	// Compute the placeholders for \theta *\phi and \tau * \lambda
	thetaPhiScalar := new(big.Int).SetUint64(0)
	tauLambdaScalar := new(big.Int).SetUint64(0)

	// Set \lambda as a scalar
	lambdaScalar := new(big.Int).SetBytes(lambdaScalarBytes)

	fmt.Printf("In ProveShuffle, computing vCapPoint, lambdaScalar is: %v\n", lambdaScalar)

	// Compute the product \tau*\lambda
	tauLambdaScalar.Mul(tauScalar, lambdaScalar)
	tauLambdaScalar.Mod(tauLambdaScalar, curveParams.N)
	fmt.Printf("In ProveShuffle, computing vCapPoint, tauLambdaScalar is: %v\n", tauLambdaScalar)

	// Compute the product \theta *\phi
	thetaPhiScalar.Mul(thetaScalar, phiScalar)
	thetaPhiScalar.Mod(thetaPhiScalar, curveParams.N)
	fmt.Printf("In ProveShuffle, computing vCapPoint, thetaPhiScalar is: %v\n", thetaPhiScalar)

	// Initialize the result for the dlog of \cap{V}
	vCapScalarResult := new(big.Int).SetUint64(0)
	vCapScalarResult.Add(tauLambdaScalar, thetaPhiScalar)
	vCapScalarResult.Mod(vCapScalarResult, curveParams.N)
	fmt.Printf("In ProveShuffle, computing vCapPoint, vCapScalarResult initial (theta*phi + tau*lambda) is: %v\n", vCapScalarResult)

	for i := 0; i < len(witness.PermList); i++ {
		// Create the placeholders for \phi_i^2 and \phi_i^3
		phiSquared := new(big.Int).SetUint64(0)
		phiCubed := new(big.Int).SetUint64(0)

		phiListScalar := new(big.Int).SetBytes(phiList[i])
		fmt.Printf("In ProveShuffle, for index %d, computing vCapPoint, phiListScalar is: %v\n", i, phiListScalar)

		// Compute the \phi_i^2
		phiSquared.Mul(phiListScalar, phiListScalar)
		phiSquared.Mod(phiSquared, curveParams.N)

		// Compute the \phi_i^3 as \phi_i^2 * \phi_i
		phiCubed.Mul(phiSquared, phiListScalar)
		phiCubed.Mod(phiCubed, curveParams.N)
		fmt.Printf("In ProveShuffle, for index %d, computing vCapPoint, phiCubed is: %v\n", i, phiCubed)

		// Add the phi_i^3 to the running store for the exponent of \cap{V}
		vCapScalarResult.Add(phiCubed, vCapScalarResult)
		vCapScalarResult.Mod(vCapScalarResult, curveParams.N)
		fmt.Printf("In ProveShuffle, for index %d, computing vCapPoint, vCapScalarResult partial is: %v\n", i, phiCubed)
	}
	fmt.Printf("In ProveShuffle, computing vCapPoint, vCapScalarResult final is: %v\n", vCapScalarResult)

	// Compute the \cap{V} point based on the computed scalar as
	vCapPoint.X, vCapPoint.Y = instance.Curve.ScalarBaseMult(vCapScalarResult.Bytes())
	fmt.Printf("In ProveShuffle, vCapPoint final is (%v,%v)\n", vCapPoint.X, vCapPoint.Y)

	// Compute \cap{W_i}
	wCapPointList := make([]Point, 0)
	sigmaScalar := new(big.Int).SetBytes(sigmaScalarBytes)
	fmt.Printf("In ProveShuffle, computing wCapPointList, value of sigmaScalar is: %v\n", sigmaScalar)

	for i := 0; i < len(witness.PermList); i++ {

		// Choose r_i
		rScalar := witness.RandomizerList[i]
		fmt.Printf("In ProveShuffle, loop for ^w_i, index %d, witness.RandomizerList[i] is: %v\n", i, witness.RandomizerList[i])

		//Compute \sigma * r_i
		sigmarScalar := new(big.Int).Mul(sigmaScalar, rScalar)
		sigmarScalar.Mod(sigmarScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, loop for ^w_i, index %d, sigmarScalar is: %v\n", i, sigmarScalar)

		// Find the image of i under the secret permutation \pi
		ind := witness.PermList[i]
		fmt.Printf("In ProveShuffle, loop for ^w_i, index %d, witness.PermList is: %v\n", i, ind)

		// Derive phi_{\pi(i)}
		phiListScalar := new(big.Int).SetBytes(phiList[ind])
		fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, chosen phiListScalar is: %v\n", i, ind, phiListScalar)

		// Initialize 2 as a scalar
		twoScalar := new(big.Int).SetUint64(2)

		// Compute the product of 2*phi_{\pi(i)}
		resultScalar := new(big.Int).Mul(twoScalar, phiListScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, 2*phiListScalar is: %v\n", i, ind, resultScalar)

		// Compute the 2*phi_{\pi(i)} + \sigma * r_i
		resultScalar.Add(resultScalar, sigmarScalar)
		resultScalar.Mod(resultScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, resultScalar is: %v\n", i, ind, resultScalar)

		// Compute \cap{W_i} as result*G
		wCapBlindPoint := Point{}
		wCapBlindPoint.X, wCapBlindPoint.Y = instance.Curve.ScalarBaseMult(resultScalar.Bytes())
		fmt.Printf("In ProveShuffle, loop for wCapPoint[i], index %d, chosen perm index %d, wCapBlindPoint is (%v,%v)\n", i, ind, wCapBlindPoint.X, wCapBlindPoint.Y)
		wCapPointList = append(wCapPointList, wCapBlindPoint)
	}

	//Compute  \cap{W}
	wCapPoint := Point{}

	// \cap{W} =
	wCapScalar := new(big.Int).SetUint64(0)
	wCapScalar.Mul(phiScalar, sigmaScalar)
	wCapScalar.Mod(wCapScalar, curveParams.N)
	fmt.Printf("In ProveShuffle, loop for wCapPoint, inital result for exponent is %v\n", wCapScalar)

	for i := 0; i < len(witness.PermList); i++ {
		phiSquared := new(big.Int).SetUint64(0)
		phiListScalar := new(big.Int).SetBytes(phiList[i])
		fmt.Printf("In ProveShuffle, loop for wCapPoint, phiListScalar is %v\n", phiListScalar)

		phiSquared.Mul(phiListScalar, phiListScalar)
		phiSquared.Mod(phiSquared, curveParams.N)
		fmt.Printf("In ProveShuffle, loop for wCapPoint, phiListScalar is %v\n", phiSquared)

		wCapScalar.Add(wCapScalar, phiSquared)
		wCapScalar.Mod(wCapScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, loop for wCapPoint, partial result for exponent is %v\n", wCapScalar)

	}
	fmt.Printf("In ProveShuffle, loop for wCapPoint, final result for exponent is %v\n", wCapScalar)
	wCapScalar.Mod(wCapScalar, curveParams.N)
	wCapPoint.X, wCapPoint.Y = instance.Curve.ScalarBaseMult(wCapScalar.Bytes())
	fmt.Printf("In ProveShuffle, loop for wCapPoint, final result is (%v,%v)\n", wCapPoint.X, wCapPoint.Y)

	//Begin preparing derived points for appending to the transcript

	tPointCompressed := elliptic.MarshalCompressed(instance.Curve, tPoint.X, tPoint.Y)
	vPointCompressed := elliptic.MarshalCompressed(instance.Curve, vPoint.X, vPoint.Y)
	wPointCompressed := elliptic.MarshalCompressed(instance.Curve, wPoint.X, wPoint.Y)
	uPointCompressed := elliptic.MarshalCompressed(instance.Curve, uPoint.X, uPoint.Y)
	uPointListCompressed := MarshalPointList(uPointList, instance.Curve)
	//TODO: missing is ^g'-list and ^g' point

	gPrimePointCompressed := elliptic.MarshalCompressed(instance.Curve, gPrimePoint.X, gPrimePoint.Y)
	mPrimePointCompressed := elliptic.MarshalCompressed(instance.Curve, mPrimePoint.X, mPrimePoint.Y)
	tCapPointListCompressed := MarshalPointList(tCapPointList, instance.Curve)
	vCapPointListCompressed := MarshalPointList(vCapPointList, instance.Curve)
	vCapPointCompressed := elliptic.MarshalCompressed(instance.Curve, vCapPoint.X, vCapPoint.Y)
	wCapPointListCompressed := MarshalPointList(wCapPointList, instance.Curve)
	wCapPointCompressed := elliptic.MarshalCompressed(instance.Curve, wCapPoint.X, wCapPoint.Y)

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

	fmt.Printf("In ProveShuffle, challScalarList is %v\n", challScalarList)

	//Compute s_0 scalar
	sZeroScalar := new(big.Int).Set(phiScalar)
	fmt.Printf("In ProveShuffle, sZeroScalar initial: %v\n", sZeroScalar)

	for i := 0; i < len(witness.PermList); i++ {
		//Corresponds to \beta_j
		challScalar := new(big.Int).SetBytes(challScalarList[i])
		fmt.Printf("In ProveShuffle, challScalar is: %v\n", challScalar)
		//multiplied by r_j
		fmt.Printf("In ProveShuffle, loop for s_0, witness.RandomizerList[i] is: %v\n", witness.RandomizerList[i])
		rBeta := challScalar.Mul(challScalar, witness.RandomizerList[i])
		rBeta = rBeta.Mod(rBeta, curveParams.N)

		fmt.Printf("In ProveShuffle, for sZeroScalar addend is : %v\n", rBeta)

		//Add result to the sum
		sZeroScalar = sZeroScalar.Add(sZeroScalar, rBeta)
		sZeroScalar = sZeroScalar.Mod(sZeroScalar, curveParams.N)

		fmt.Printf("In ProveShuffle, sZeroScalar partial: %v\n", sZeroScalar)

	}
	fmt.Printf("In ProveShuffle, sZeroScalar final: %v\n", sZeroScalar)

	sList := make([]*big.Int, 0)
	fmt.Printf("In ProveShuffle, PermList is: %v\n", witness.PermList)
	permMatrix := MakePermutationMatrix(witness.PermList)
	fmt.Printf("In ProveShuffle, PermMatrix is:\n")
	printPermutationMatrix(permMatrix)

	// Compute s_i scalars
	for i := 0; i < len(witness.PermList); i++ {
		sScalar := new(big.Int).SetBytes(phiList[i])
		fmt.Printf("In ProveShuffle, for index %d, sScalar initial %v\n", i, sScalar)

		ind := findNonZeroIndex(permMatrix[i])
		fmt.Printf("In ProveShuffle, for index %d, chosen index in permutation matrix %d\n", i, ind)

		fmt.Printf("In ProveShuffle, Beta value chosen %v\n", challScalarList[ind])
		challScalar := new(big.Int).SetBytes(challScalarList[ind])
		fmt.Printf("In ProveShuffle, for index %d, challScalar is %v\n", i, challScalar)

		sScalar = sScalar.Add(sScalar, challScalar)
		sScalar = sScalar.Mod(sScalar, curveParams.N)
		fmt.Printf("In ProveShuffle, for index %d, sScalar final %v\n", i, sScalar)
		sList = append(sList, sScalar)
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
		fmt.Printf("In ProveShuffle, for dScalar, for index %d, partial value is %v\n", i, challSquared)

		//compute lambda_i*chall_i*chall_i
		prod := challSquared.Mul(challSquared, lambda)
		dScalar = dScalar.Add(dScalar, prod)
		dScalar = dScalar.Mod(dScalar, curveParams.N)

		fmt.Printf("In ProveShuffle, for dScalar,for index %d, dScalar partial %v\n", i, dScalar)

	}

	fmt.Printf("In ProveShuffle, dScalar final %v\n", dScalar)

	shuffleProof := ShuffleProof{
		ProofType:          SHUFFLE_LABEL,
		instance:           instance,
		verifierChallList:  challScalarList,
		tPoint:             tPointCompressed,
		vPoint:             vPointCompressed,
		wPoint:             wPointCompressed,
		uPoint:             uPointCompressed,
		uPointListBytes:    uPointListCompressed,
		gPrimePoint:        gPrimePointCompressed,
		mPrimePoint:        mPrimePointCompressed,
		tCapPointListBytes: tCapPointListCompressed,
		vCapPointListBytes: vCapPointListCompressed,
		vCapPoint:          vCapPointCompressed,
		wCapPointListBytes: wCapPointListCompressed,
		wCapPoint:          wCapPointCompressed,
		sZeroScalar:        sZeroScalar,
		sList:              sList,
		dScalar:            dScalar,
	}
	return &shuffleProof, nil
}

func VerifyShuffle(proof *ShuffleProof) bool {
	curve := proof.instance.Curve
	curveParams := proof.instance.Curve.Params()

	transcript := NewTranscript(proof.ProofType)
	proofTypeBytes := []byte(proof.ProofType)
	reEncBeforeList := MakeReencList(proof.instance.ctBefore)
	reEncAfterList := MakeReencList(proof.instance.ctAfter)
	ctMsgBeforeList := MakeCtMsgList(proof.instance.ctBefore)
	ctMsgAfterList := MakeCtMsgList(proof.instance.ctAfter)

	reEncBeforeByteList := MarshalPointList(reEncBeforeList, curve)
	reEncAfterByteList := MarshalPointList(reEncAfterList, curve)
	ctMsgBeforeByteList := MarshalPointList(ctMsgBeforeList, curve)
	ctMsgAfterByteList := MarshalPointList(ctMsgAfterList, curve)

	pPoint := Point{
		X: proof.instance.pPoint.X,
		Y: proof.instance.pPoint.Y,
	}

	pPointCompressed := elliptic.MarshalCompressed(curve, pPoint.X, pPoint.Y)

	//Putting public parameters into the transcript
	transcript.BatchAppendMessages(proofTypeBytes, reEncBeforeByteList)
	transcript.BatchAppendMessages(proofTypeBytes, reEncAfterByteList)
	transcript.BatchAppendMessages(proofTypeBytes, ctMsgBeforeByteList)
	transcript.BatchAppendMessages(proofTypeBytes, ctMsgAfterByteList)
	transcript.AppendMessage(proofTypeBytes, pPointCompressed)

	//Putting commitment messages into the transcript

	transcript.AppendMessage(proofTypeBytes, proof.tPoint)
	transcript.AppendMessage(proofTypeBytes, proof.vPoint)
	transcript.AppendMessage(proofTypeBytes, proof.wPoint)
	transcript.AppendMessage(proofTypeBytes, proof.uPoint)
	transcript.BatchAppendMessages(proofTypeBytes, proof.uPointListBytes)
	//TODO: extra missing ^g'_i, ^g' point

	transcript.AppendMessage(proofTypeBytes, proof.gPrimePoint)
	transcript.AppendMessage(proofTypeBytes, proof.mPrimePoint)
	transcript.BatchAppendMessages(proofTypeBytes, proof.tCapPointListBytes)
	transcript.BatchAppendMessages(proofTypeBytes, proof.vCapPointListBytes)
	transcript.AppendMessage(proofTypeBytes, proof.vCapPoint)
	transcript.BatchAppendMessages(proofTypeBytes, proof.wCapPointListBytes)
	transcript.AppendMessage(proofTypeBytes, proof.wCapPoint)

	//Verifier's step: derive public coins based on the
	challScalarList := make([][]byte, 0)
	for i := 0; i < len(proof.instance.ctBefore); i++ {
		challScalarList = append(challScalarList, transcript.GetChallengeBytes(proofTypeBytes, SCALAR_SIZE))
	}

	fmt.Printf("In VerifyShuffle, challScalarList is %v\n", challScalarList)

	//Parse all the points for the final verifier's check

	tPoint := Point{}
	wPoint := Point{}
	vPoint := Point{}
	uPoint := Point{}

	gPrimePoint := Point{}
	mPrimePoint := Point{}
	vCapPoint := Point{}
	wCapPoint := Point{}

	tPoint.X, tPoint.Y = elliptic.UnmarshalCompressed(curve, proof.tPoint)
	wPoint.X, wPoint.Y = elliptic.UnmarshalCompressed(curve, proof.wPoint)
	vPoint.X, vPoint.Y = elliptic.UnmarshalCompressed(curve, proof.vPoint)
	uPoint.X, uPoint.Y = elliptic.UnmarshalCompressed(curve, proof.uPoint)

	gPrimePoint.X, gPrimePoint.Y = elliptic.UnmarshalCompressed(curve, proof.gPrimePoint)
	mPrimePoint.X, mPrimePoint.Y = elliptic.UnmarshalCompressed(curve, proof.mPrimePoint)
	vCapPoint.X, vCapPoint.Y = elliptic.UnmarshalCompressed(curve, proof.vCapPoint)
	wCapPoint.X, wCapPoint.Y = elliptic.UnmarshalCompressed(curve, proof.wCapPoint)

	uPointList := UnmarshalPointList(proof.uPointListBytes, curve)
	vCapPointList := UnmarshalPointList(proof.vCapPointListBytes, curve)
	wCapPointList := UnmarshalPointList(proof.wCapPointListBytes, curve)
	tCapPointList := UnmarshalPointList(proof.tCapPointListBytes, curve)
	// fmt.Printf("wCapPointList, %v\n", wCapPointList)

	//Corresponds to check (5.20) in notes
	sGpoint := Point{}
	sGpoint.X, sGpoint.Y = curve.ScalarBaseMult(proof.sZeroScalar.Bytes())

	fmt.Printf("In VerifyShuffle, sZeroScalar is %v\n", proof.sZeroScalar)
	fmt.Printf("In VerifyShuffle, sGpoint, initial value is (%v,%v)\n", sGpoint.X, sGpoint.Y)

	for i, sScalar := range proof.sList {
		addend := Point{}
		fmt.Printf("In VerifyShuffle, reEncBeforeList[i] is (%v,%v)\n", reEncBeforeList[i].X, reEncBeforeList[i].Y)
		fmt.Printf("In VerifyShuffle, sScalar is %v\n", sScalar)

		addend.X, addend.Y = curve.ScalarMult(reEncBeforeList[i].X, reEncBeforeList[i].Y, sScalar.Bytes())
		sGpoint.X, sGpoint.Y = curve.Add(addend.X, addend.Y, sGpoint.X, sGpoint.Y)
		fmt.Printf("In VerifyShuffle, sGpoint, partial result is (%v,%v)\n", sGpoint.X, sGpoint.Y)

	}
	fmt.Printf("In VerifyShuffle, sGpoint,final is (%v,%v)\n", sGpoint.X, sGpoint.Y)

	betaGprimePoint := Point{
		X: new(big.Int).Set(gPrimePoint.X),
		Y: new(big.Int).Set(gPrimePoint.Y),
	}
	fmt.Printf("In VerifyShuffle, betaGprimePoint initial is (%v,%v)\n", betaGprimePoint.X, betaGprimePoint.Y)

	for i, challBytes := range challScalarList {
		addend := Point{}
		fmt.Printf("In VerifyShuffle, for index %d, reEncAfterList[i] is (%v,%v)\n", i, reEncAfterList[i].X, reEncAfterList[i].Y)
		addend.X, addend.Y = curve.ScalarMult(reEncAfterList[i].X, reEncAfterList[i].Y, challBytes)
		fmt.Printf("In VerifyShuffle, for index %d, addend is (%v,%v)\n", i, reEncAfterList[i].X, reEncAfterList[i].Y)
		betaGprimePoint.X, betaGprimePoint.Y = curve.Add(addend.X, addend.Y, betaGprimePoint.X, betaGprimePoint.Y)
		fmt.Printf("In VerifyShuffle, betaGprimePoint partial result is (%v,%v)\n", betaGprimePoint.X, betaGprimePoint.Y)

	}
	fmt.Printf("In VerifyShuffle, betaGprimePoint final is (%v,%v)\n", betaGprimePoint.X, betaGprimePoint.Y)

	checkO2 := sGpoint.X.Cmp(betaGprimePoint.X) == 0 && sGpoint.Y.Cmp(betaGprimePoint.Y) == 0

	//Corresponds to check (5.21) in notes

	sMpoint := Point{}
	sMpoint.X, sMpoint.Y = curve.ScalarMult(pPoint.X, pPoint.Y, proof.sZeroScalar.Bytes())
	fmt.Printf("In VerifyShuffle, sMpoint initial is (%v,%v)\n", sMpoint.X, sMpoint.Y)

	for i, s := range proof.sList {
		addend := Point{}
		fmt.Printf("In VerifyShuffle, for %d, ctMsgBefore[i] is (%v,%v)\n", i, ctMsgBeforeList[i].X, ctMsgBeforeList[i].Y)

		addend.X, addend.Y = curve.ScalarMult(ctMsgBeforeList[i].X, ctMsgBeforeList[i].Y, s.Bytes())
		fmt.Printf("In VerifyShuffle, sMpoint addend is (%v,%v)\n", addend.X, addend.Y)
		sMpoint.X, sMpoint.Y = curve.Add(addend.X, addend.Y, sMpoint.X, sMpoint.Y)
		fmt.Printf("In VerifyShuffle, sMpoint partial is (%v,%v)\n", sMpoint.X, sMpoint.Y)
	}
	fmt.Printf("In VerifyShuffle, sMpoint final is (%v,%v)\n", sMpoint.X, sMpoint.Y)

	challMprimePoint := Point{
		X: new(big.Int).Set(mPrimePoint.X),
		Y: new(big.Int).Set(mPrimePoint.Y),
	}

	fmt.Printf("In VerifyShuffle, challMprimePoint initial is (%v,%v)\n", challMprimePoint.X, challMprimePoint.Y)

	for i, challBytes := range challScalarList {
		addend := Point{}
		fmt.Printf("In VerifyShuffle, for index %d, ctMsgAfterList is (%v,%v)\n", i, ctMsgAfterList[i].X, ctMsgAfterList[i].Y)
		addend.X, addend.Y = curve.ScalarMult(ctMsgAfterList[i].X, ctMsgAfterList[i].Y, challBytes)
		fmt.Printf("In VerifyShuffle,for index %d, challMprimePoint addend is (%v,%v)\n", i, addend.X, addend.Y)

		challMprimePoint.X, challMprimePoint.Y = curve.Add(addend.X, addend.Y, challMprimePoint.X, challMprimePoint.Y)

		fmt.Printf("In VerifyShuffle,for index %d, challMprimePoint partial is (%v,%v)\n", i, challMprimePoint.X, challMprimePoint.Y)
	}
	fmt.Printf("In VerifyShuffle, challMprimePoint final is (%v,%v)\n", challMprimePoint.X, challMprimePoint.Y)

	checkO3 := sMpoint.X.Cmp(challMprimePoint.X) == 0 && sMpoint.Y.Cmp(challMprimePoint.Y) == 0

	//Corresponds to check (5.22) in notes
	sBetaSqWGPoint := Point{}

	//Initialize point to be s0*W
	sBetaSqWGPoint.X, sBetaSqWGPoint.Y = curve.ScalarMult(wPoint.X, wPoint.Y, proof.sZeroScalar.Bytes())

	fmt.Printf("In VerifyShuffle, challMprimePoint initial is (%v,%v)\n", sBetaSqWGPoint.X, sBetaSqWGPoint.Y)

	sqDiff := new(big.Int).SetUint64(0)
	for i := 0; i < len(challScalarList); i++ {
		//Compute s_i^2
		siSq := new(big.Int).Set(proof.sList[i])

		siSq = siSq.Mul(siSq, siSq)
		siSq = siSq.Mod(siSq, curveParams.N)

		fmt.Printf("In VerifyShuffle, for index %d, siSq is %v\n", i, siSq)

		//compute chall^2
		challScalar := new(big.Int).SetBytes(challScalarList[i])
		challSq := challScalar.Mul(challScalar, challScalar)
		challSq = challSq.Mod(challSq, curveParams.N)
		challSq = challSq.Neg(challSq)

		fmt.Printf("In VerifyShuffle, for index %d, challSq is %v\n", i, challSq)

		//Compute addend = s_i^2-chall^2
		addend := siSq.Add(siSq, challSq)
		addend = addend.Mod(addend, curveParams.N)

		fmt.Printf("In VerifyShuffle, for index %d, addend is %v\n", i, addend)

		//Add addend to the whole sum
		sqDiff = sqDiff.Add(sqDiff, addend)
		sqDiff = sqDiff.Mod(sqDiff, curveParams.N)

		fmt.Printf("In VerifyShuffle, for index %d, sqDiff partial is %v\n", i, sqDiff)
	}
	fmt.Printf("In VerifyShuffle, sqDiff final is %v\n", sqDiff)

	sqDiffGPoint := Point{}
	sqDiffGPoint.X, sqDiffGPoint.Y = curve.ScalarBaseMult(sqDiff.Bytes())
	fmt.Printf("In VerifyShuffle, sqDiffGPoint is (%v,%v)\n", sqDiffGPoint.X, sqDiffGPoint.Y)

	sBetaSqWGPoint.X, sBetaSqWGPoint.Y = curve.Add(sBetaSqWGPoint.X, sBetaSqWGPoint.Y, sqDiffGPoint.X, sqDiffGPoint.Y)
	fmt.Printf("In VerifyShuffle, sBetaSqWGPoint final is (%v,%v)\n", sBetaSqWGPoint.X, sBetaSqWGPoint.Y)

	betawCapPoint := Point{
		X: new(big.Int).Set(wCapPoint.X),
		Y: new(big.Int).Set(wCapPoint.Y),
	}
	fmt.Printf("In VerifyShuffle, betawCapPoint initial is (%v,%v)\n", betawCapPoint.X, betawCapPoint.Y)

	for i, challBytes := range challScalarList {
		addend := Point{}
		addend.X, addend.Y = curve.ScalarMult(wCapPointList[i].X, wCapPointList[i].Y, challBytes)
		fmt.Printf("In VerifyShuffle, addend for betawCapPoint is (%v,%v)\n", addend.X, addend.Y)

		betawCapPoint.X, betawCapPoint.Y = curve.Add(addend.X, addend.Y, betawCapPoint.X, betawCapPoint.Y)
		fmt.Printf("In VerifyShuffle,  betawCapPoint partial is (%v,%v)\n", betawCapPoint.X, betawCapPoint.Y)
	}
	fmt.Printf("In VerifyShuffle,  betawCapPoint final is (%v,%v)\n", betawCapPoint.X, betawCapPoint.Y)

	check04 := sBetaSqWGPoint.X.Cmp(betawCapPoint.X) == 0 && sBetaSqWGPoint.Y.Cmp(betawCapPoint.Y) == 0

	//Corresponds to check (5.23) in notes

	dGpoint := Point{}
	dGpoint.X, dGpoint.Y = curve.ScalarBaseMult(proof.dScalar.Bytes())

	fmt.Printf("In VerifyShuffle, dGPoint final is (%v,%v)\n", dGpoint.X, dGpoint.Y)

	challSqUPoint := Point{
		X: new(big.Int).Set(uPoint.X),
		Y: new(big.Int).Set(uPoint.Y),
	}

	fmt.Printf("In VerifyShuffle, challSqUPoint initial is (%v,%v)\n", challSqUPoint.X, challSqUPoint.Y)

	for i, challBytes := range challScalarList {
		addend := Point{}
		challScalar := new(big.Int).SetBytes(challBytes)
		challSqScalar := challScalar.Mod(challScalar.Mul(challScalar, challScalar), curveParams.N)
		fmt.Printf("In VerifyShuffle, for index %d challSq is %v\n", i, challSqScalar)

		addend.X, addend.Y = curve.ScalarMult(uPointList[i].X, uPointList[i].Y, challSqScalar.Bytes())
		fmt.Printf("In VerifyShuffle, for index %d addend is (%v,%v)\n", i, addend.X, addend.Y)

		challSqUPoint.X, challSqUPoint.Y = curve.Add(addend.X, addend.Y, challSqUPoint.X, challSqUPoint.Y)
		fmt.Printf("In VerifyShuffle, challSqUPoint partial is (%v,%v)\n", challSqUPoint.X, challSqUPoint.Y)
	}

	fmt.Printf("In VerifyShuffle, challSqUPoint final is (%v,%v)\n", challSqUPoint.X, challSqUPoint.Y)

	check05 := dGpoint.X.Cmp(challSqUPoint.X) == 0 && dGpoint.Y.Cmp(challSqUPoint.Y) == 0

	//Corresponds to check (5.24) in notes

	//Compute lhs of the (5.24) check
	dTPoint := Point{}
	dTPoint.X, dTPoint.Y = curve.ScalarMult(tPoint.X, tPoint.Y, proof.dScalar.Bytes())
	fmt.Printf("In VerifyShuffle, value of dTPoint is (%v,%v)\n", dTPoint.X, dTPoint.Y)

	sZeroVPoint := Point{}
	sZeroVPoint.X, sZeroVPoint.Y = curve.ScalarMult(vPoint.X, vPoint.Y, proof.sZeroScalar.Bytes())
	fmt.Printf("In VerifyShuffle, value of sZeroVPoint is (%v,%v)\n", sZeroVPoint.X, sZeroVPoint.Y)

	cubeDiff := new(big.Int).SetUint64(0)
	for i := 0; i < len(challScalarList); i++ {
		//Compute s_i^3
		siScalar := new(big.Int).Set(proof.sList[i])
		siCubed := new(big.Int).SetUint64(0)
		siCubed = siCubed.Mul(siScalar, siScalar)
		siCubed = siCubed.Mul(siCubed, siScalar)
		siCubed = siCubed.Mod(siCubed, curveParams.N)

		fmt.Printf("In VerifyShuffle, for index %d, siCubed is %v\n", i, siCubed)

		//compute -chall^3
		challSc := new(big.Int).SetBytes(challScalarList[i])

		challCubed := new(big.Int).SetUint64(0)
		challCubed = challCubed.Mul(challSc, challSc)
		challCubed = challCubed.Mul(challCubed, challSc)
		challCubed = challCubed.Mod(challCubed, curveParams.N)
		fmt.Printf("In VerifyShuffle, for index %d, challCubed is %v\n", i, challCubed)

		challCubed = challCubed.Neg(challCubed)

		fmt.Printf("In VerifyShuffle, for index %d, -challCubed is %v\n", i, challCubed)

		//Compute addend = s_i^3-chall^3
		addend := new(big.Int).SetUint64(0)
		addend = addend.Add(siCubed, challCubed)
		addend = addend.Mod(addend, curveParams.N)

		fmt.Printf("In VerifyShuffle, for index %d, value of addend (s_i^3 - chall^3) is %v\n", i, addend)

		// fmt.Printf("In VerifyShuffle, for index %d, addend is %v\n", i, addend)

		//Add addend to the whole sum
		cubeDiff = cubeDiff.Add(cubeDiff, addend)
		cubeDiff = cubeDiff.Mod(cubeDiff, curveParams.N)
		fmt.Printf("In VerifyShuffle, for index %d, cubeDiff partial is %v\n", i, cubeDiff)
	}
	fmt.Printf("In VerifyShuffle, cubeDiff final is %v\n", cubeDiff)

	cubeDiffGPoint := Point{}
	cubeDiffGPoint.X, cubeDiffGPoint.Y = curve.ScalarBaseMult(cubeDiff.Bytes())

	fmt.Printf("In VerifyShuffle, value of cubeDiffGPoint is (%v,%v)\n", cubeDiffGPoint.X, cubeDiffGPoint.Y)

	lhs := Point{}
	lhs.X, lhs.Y = curve.Add(dTPoint.X, dTPoint.Y, sZeroVPoint.X, sZeroVPoint.Y)
	fmt.Printf("In VerifyShuffle, value of sume dT + sZeroV is (%v,%v)\n", lhs.X, lhs.Y)

	lhs.X, lhs.Y = curve.Add(lhs.X, lhs.Y, cubeDiffGPoint.X, cubeDiffGPoint.Y)

	fmt.Printf("In VerifyShuffle, final value of lhs is (%v,%v)\n", lhs.X, lhs.Y)

	//Compute rhs of (5.24) check
	rhs := Point{
		X: new(big.Int).Set(vCapPoint.X),
		Y: new(big.Int).Set(vCapPoint.Y),
	}

	fmt.Printf("In VerifyShuffle, initial value of rhs is (%v,%v)\n", rhs.X, rhs.Y)

	for i := 0; i < len(challScalarList); i++ {
		challVcapPoint := Point{}
		challSqTCapPoint := Point{}

		chall := new(big.Int).SetBytes(challScalarList[i])

		fmt.Printf("In VerifyShuffle, for index %d, value of vCapPoint (%v,%v)\n", i, vCapPointList[i].X, vCapPointList[i].Y)

		challVcapPoint.X, challVcapPoint.Y = curve.ScalarMult(vCapPointList[i].X, vCapPointList[i].Y, challScalarList[i])
		fmt.Printf("In VerifyShuffle, for index %d, value of challVcapPoint (%v,%v)\n", i, challVcapPoint.X, challVcapPoint.Y)

		challSq := new(big.Int).SetUint64(0)
		challSq = challSq.Mul(chall, chall)
		challSq = challSq.Mod(challSq, curveParams.N)

		fmt.Printf("In VerifyShuffle, challSq final is %v\n", challSq)

		fmt.Printf("In VerifyShuffle, for index %d, value of tCapPoint (%v,%v)\n", i, tCapPointList[i].X, tCapPointList[i].Y)
		challSqTCapPoint.X, challSqTCapPoint.Y = curve.ScalarMult(tCapPointList[i].X, tCapPointList[i].Y, challSq.Bytes())
		fmt.Printf("In VerifyShuffle, for index %d, value of chall^2*tCapPoint (%v,%v)\n", i, challSqTCapPoint.X, challSqTCapPoint.Y)

		rhs.X, rhs.Y = curve.Add(rhs.X, rhs.Y, challVcapPoint.X, challVcapPoint.Y)
		rhs.X, rhs.Y = curve.Add(rhs.X, rhs.Y, challSqTCapPoint.X, challSqTCapPoint.Y)
	}

	check06 := lhs.X.Cmp(rhs.X) == 0 && lhs.Y.Cmp(rhs.Y) == 0

	fmt.Printf("Check02: %v, Check03: %v, Check04: %v, Check05: %v, Check06: %v\n", checkO2, checkO3, check04, check05, check06)

	return checkO2 && checkO3 && check04 && check05 && check06 //check04 && check05 //TODO: Missing checks for 5.22 (check04), 5.24 (check06)
}

//Helper functions for this class
/*********************************************************************/

func ElGamalEncryption(curve elliptic.Curve, pPoint *Point, rScalar *big.Int, msg *big.Int) *ElGamalCipherText {
	ct1 := Point{}
	ct2 := Point{}
	msgPoint := Point{}
	rpPoint := Point{}

	msgPoint.X, msgPoint.Y = curve.ScalarBaseMult(msg.Bytes())
	rBytes := rScalar.Bytes()
	ct1.X, ct1.Y = curve.ScalarBaseMult(rBytes)
	rpPoint.X, rpPoint.Y = curve.ScalarMult(pPoint.X, pPoint.Y, rBytes)

	// fmt.Printf("ElGamalEncryption: rpPoint is: (%v,%v)\n", rpPoint.X, rpPoint.Y)

	ct2.X, ct2.Y = curve.Add(rpPoint.X, rpPoint.Y, msgPoint.X, msgPoint.Y)
	return &ElGamalCipherText{
		ct1: ct1,
		ct2: ct2,
	}
}

func ElGamalReEncryption(curve elliptic.Curve, pPoint *Point, rScalar *big.Int, cipherText *ElGamalCipherText) *ElGamalCipherText {
	ct1 := Point{}
	ct2 := Point{}
	rpPoint := Point{}

	rBytes := rScalar.Bytes()
	ct1.X, ct1.Y = curve.ScalarBaseMult(rBytes)

	ct1.X, ct1.Y = curve.Add(ct1.X, ct1.Y, cipherText.ct1.X, cipherText.ct1.Y)

	rpPoint.X, rpPoint.Y = curve.ScalarMult(pPoint.X, pPoint.Y, rBytes)

	// fmt.Printf("ElGamalReEncryption: rpPoint is: (%v,%v)\n", rpPoint.X, rpPoint.Y)

	ct2.X, ct2.Y = curve.Add(rpPoint.X, rpPoint.Y, cipherText.ct2.X, cipherText.ct2.Y)
	return &ElGamalCipherText{
		ct1: ct1,
		ct2: ct2,
	}
}
