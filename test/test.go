package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	btcec "github.com/cuckoobtcec"
)

var ecctimeall time.Duration = 0
var eccenall time.Duration = 0
var eccdeall time.Duration = 0
var ecchaddall time.Duration = 0
var ecchaddfieldall time.Duration = 0
var ecchmulall time.Duration = 0

var c = btcec.S256()

func testParbtcec(messages [1000]*big.Int) {
	privKey, _ := btcec.NewPrivateKey(c)
	pubKey := privKey.PubKey()
	for i := 0; i < 1000; i++ {
		fmt.Println("hecc Eecryption message : ", messages[i])
		start1 := time.Now()
		cipher := btcec.Encrypt(pubKey, messages[i])
		cost1 := time.Since(start1)
		fmt.Printf("btcecc encrypt cost=[%s]\n", cost1)
		start2 := time.Now()
		plaintext, _ := btcec.ParDecrypt(privKey, cipher)
		cost2 := time.Since(start2)
		fmt.Printf("btcecc decrypt cost=[%s]\n", cost2)
		fmt.Println("hecc Decryption Result : ", plaintext)
		cost3 := cost1 + cost2
		fmt.Printf("btcecc all cost=[%s]\n", cost3)
		cipher1 := btcec.Encrypt(pubKey, messages[999-i])
		start4 := time.Now()
		btcec.HomoAdd(cipher, cipher1)
		cost4 := time.Since(start4)
		start5 := time.Now()
		btcec.HomoAddField(cipher, cipher1)
		cost5 := time.Since(start5)
		start6 := time.Now()
		btcec.HomoMul(cipher, messages[999-i])
		cost6 := time.Since(start6)
		eccenall = eccenall + cost1
		eccdeall = eccdeall + cost2
		ecchaddall = ecchaddall + cost4
		ecchaddfieldall = ecchaddfieldall + cost5
		ecchmulall = ecchmulall + cost6
	}
}

func testNormalbtcec(messages [1000]*big.Int) {
	privKey, _ := btcec.NewPrivateKey(c)
	pubKey := privKey.PubKey()
	for i := 0; i < 1000; i++ {
		fmt.Println("hecc Eecryption message : ", messages[i])
		start1 := time.Now()
		cipher := btcec.NormalEnc(pubKey, messages[i])
		cost1 := time.Since(start1)
		fmt.Printf("btcecc encrypt cost=[%s]\n", cost1)
		start2 := time.Now()
		plaintext, _ := btcec.NormalDecrypt(privKey, cipher)
		cost2 := time.Since(start2)
		fmt.Printf("btcecc decrypt cost=[%s]\n", cost2)
		fmt.Println("hecc Decryption Result : ", plaintext)
		cost3 := cost1 + cost2
		fmt.Printf("btcecc all cost=[%s]\n", cost3)
		cipher1 := btcec.NormalEnc(pubKey, messages[999-i])
		start4 := time.Now()
		btcec.HomoAdd(cipher, cipher1)
		cost4 := time.Since(start4)
		start5 := time.Now()
		btcec.HomoAddField(cipher, cipher1)
		cost5 := time.Since(start5)
		start6 := time.Now()
		btcec.HomoMul(cipher, messages[999-i])
		cost6 := time.Since(start6)
		eccenall = eccenall + cost1
		eccdeall = eccdeall + cost2
		ecchaddall = ecchaddall + cost4
		ecchaddfieldall = ecchaddfieldall + cost5
		ecchmulall = ecchmulall + cost6
	}
}

func main() {
	var msgmax = big.NewInt(int64(btcec.Mmax))
	var messages [1000]*big.Int
	for i := 0; i < 1000; i++ {
		msg, _ := rand.Int(rand.Reader, msgmax)
		if i%2 == 0 {
			//messages[i] = msg.Neg(msg)
			messages[i] = msg
		} else {
			messages[i] = msg
		}
	}
	testParbtcec(messages)
	fmt.Printf("Exp-ElGamal left %dbits, %dbits\n", btcec.Ilen, btcec.Ilen+btcec.Jlen+1)
	fmt.Printf("Exp-ElGamal encrypto 1000 times average cost=[%s]\n", eccenall/1000)
	fmt.Printf("Exp-ElGamal decrypto 1000 times average cost=[%s]\n", eccdeall/1000)
	fmt.Printf("Exp-ElGamal h-add 1000 times average cost=[%s]\n", ecchaddall/1000)
	fmt.Printf("Exp-ElGamal h-fieldadd 1000 times average cost=[%s]\n", ecchaddfieldall/1000)
	fmt.Printf("Exp-ElGamal h-mul 1000 times average cost=[%s]\n", ecchmulall/1000)

}
