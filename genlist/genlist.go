package main

import (
	"fmt"
	"math/big"
	"time"

	btcec "github.com/cuckoobtcec"
)

/*
func main() {
	c := btcec.S256()
	var i int64 = 67108866
	//var k int64 = 1
	x, y := c.ScalarBaseMult(big.NewInt(67108865).Bytes())
	sum := sha256.Sum256([]byte(x.String()))
	var sum64 [8]byte
	copy(sum64[:], sum[:8])
	fmt.Println(sum64)
	for ; i <= 268435456; i++ {
		//fmt.Printf("%d\n", i)
		x, y = c.Add(x, y, c.Gx, c.Gy)
		sum := sha256.Sum256([]byte(x.String()))
		var sum64 [8]byte
		copy(sum64[:], sum[:8])
		fmt.Println(sum64)
	}
}
*/
//var T1 = cuckoo.NewCuckoo(26)
var hashtime time.Duration = 0

func main() {
	c := btcec.S256()
	//var k int64 = 1
	for i := 1; i <= 268435456; i++ {
		//fmt.Println(i)
		x, _ := c.ScalarBaseMult(big.NewInt(int64(i)).Bytes())
		start1 := time.Now()
		x = new(big.Int).SetBytes(x.Bytes()[:8])
		fmt.Println(x)
		cost1 := time.Since(start1)
		hashtime = hashtime + cost1
	}
	//fmt.Printf("hash cost cost=[%s]\n", hashtime)
}
