package impl

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"go.dedis.ch/cs438/types"
	"math/big"
)

func inList(element string, list []string) bool {
	for _, el := range list {
		if element == el {
			return true
		}
	}
	return false
}

func inMap(element string, recipients map[string]struct{}) bool {
	for k := range recipients {
		if k == element {
			return true
		}
	}
	return false
}

// Generates random permutation using the FIsher-Yates shuffling algorithm
func MakeRandomPermutation(size int) []uint32 {
	perm := make([]uint32, size)
	for i := 0; i < size; i++ {
		perm[i] = uint32(i)
	}

	for i := size - 1; i > 0; i-- {
		// rand.
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil
		}

		j := int(jBig.Int64())
		if j != i {
			perm[i], perm[j] = perm[j], perm[i]
		}
	}

	return perm
}

func MakePermutationMatrix(permList []uint32) [][]uint32 {
	// fmt.Printf("In makePermutationMatrix, PermList is: %v", permList)

	result := make([][]uint32, 0)
	for i := 0; i < len(permList); i++ {
		row := make([]uint32, len(permList))
		result = append(result, row)
	}

	for i, v := range permList {
		// fmt.Printf("In makePermutationMatrix, column: %v, row: %v", i, v)
		result[v][i] = 1
	}
	return result
}

func printPermutationMatrix(permMatrix [][]uint32) {
	for i := 0; i < len(permMatrix); i++ {
		fmt.Printf("[")
		for j := 0; j < len(permMatrix); j++ {
			fmt.Printf("%d,", permMatrix[i][j])

		}
		fmt.Printf("]\n")
	}
}

func findNonZeroIndex(list []uint32) int {
	for i, v := range list {
		if v != 0 {
			return i
		}

	}
	return -1
}

func MarshalPointList(pointList []types.Point, curve elliptic.Curve) [][]byte {
	bytePointList := make([][]byte, 0)
	for _, p := range pointList {
		pBytes := elliptic.MarshalCompressed(curve, p.X, p.Y)
		bytePointList = append(bytePointList, pBytes)

		// fmt.Printf("In MarshalPointList, Checking for entry %d, expected: %v\n", i, pBytes)
	}

	return bytePointList
}

func UnmarshalPointList(pointListBytes [][]byte, curve elliptic.Curve) []types.Point {
	pointList := make([]types.Point, 0)
	for _, p := range pointListBytes {
		point := types.Point{}
		point.X, point.Y = elliptic.UnmarshalCompressed(curve, p)
		pointList = append(pointList, point)
	}

	return pointList
}

func MarshalElGamalList(ctList []ElGamalCipherText, curve elliptic.Curve) [][]byte {
	bytePointList := make([][]byte, 0)
	for _, ct := range ctList {
		pBytes := elliptic.MarshalCompressed(curve, ct.ct1.X, ct.ct1.Y)
		bytePointList = append(bytePointList, pBytes)
		pBytesOther := elliptic.MarshalCompressed(curve, ct.ct2.X, ct.ct2.Y)
		bytePointList = append(bytePointList, pBytesOther)
	}

	return bytePointList
}

func MarshalBIntList(intList []big.Int) ([][]byte, error) {
	intByteList := make([][]byte, 0)
	for _, p := range intList {
		intBytes, err := p.MarshalJSON()
		if err != nil {
			return nil, err
		}
		intByteList = append(intByteList, intBytes)
	}

	return intByteList, nil
}

func MarshalUIntList(intList []uint32) [][]byte {
	intByteList := make([][]byte, len(intList))
	for _, p := range intList {
		bs := make([]byte, 4)
		binary.LittleEndian.PutUint32(bs, p)
		intByteList = append(intByteList, bs)
	}

	return intByteList
}

func MakeReencList(ctList []ElGamalCipherText) []types.Point {
	pointList := make([]types.Point, 0)
	for i := 0; i < len(ctList); i++ {
		//fmt.Printf("In ProveShuffle,  is %v\n", ctMsgAfterList)
		p := NewPoint(ctList[i].ct1.X, ctList[i].ct1.Y)
		pointList = append(pointList, p)
	}
	return pointList
}

func MakeCtMsgList(ctList []ElGamalCipherText) []types.Point {
	pointList := make([]types.Point, 0)
	for i := 0; i < len(ctList); i++ {
		p := NewPoint(ctList[i].ct2.X, ctList[i].ct2.Y)
		pointList = append(pointList, p)
	}
	return pointList
}
