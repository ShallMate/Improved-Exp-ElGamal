// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"bufio"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/salviati/cuckoo"
)

var Ilen = 11
var Jlen = 28
var Threadnum = 8
var imax = 1 << Ilen
var jmax = 1 << Jlen
var Mmax = imax * jmax
var mflag = int64(Mmax + 1)
var c = S256()

var T1 = cuckoo.NewCuckoo(Jlen)

var T2x = make([]*FieldVal, imax)
var T2y = make([]*FieldVal, imax)
var ZTree = make([]*FieldVal, imax*2)
var ZinvTree = make([]*FieldVal, imax*2)

var zero = big.NewInt(0)

type Point struct {
	X *big.Int
	Y *big.Int
}

type Cipher struct {
	c1x *big.Int
	c1y *big.Int
	c2x *big.Int
	c2y *big.Int
}

type FieldCipher struct {
	c1x *FieldVal
	c1y *FieldVal
	c1z *FieldVal
	c2x *FieldVal
	c2y *FieldVal
	c2z *FieldVal
}

func BuildTree(zs []*FieldVal) (root *FieldVal) {
	for i := 0; i < imax; i++ {
		ZTree[i] = zs[i]
	}
	offset := imax
	treelen := imax*2 - 3
	treelen1 := treelen - 1
	for i := 0; i < treelen; i += 2 {
		z := new(FieldVal)
		zmult := z.Mul2(ZTree[i], ZTree[i+1])
		zmult.Normalize()
		ZTree[offset] = zmult
		offset = offset + 1
		if i == treelen1 {
			root = zmult
		}
	}
	return root
}

func min(x int, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
}

func GetTreeBranch(index int) []int {
	BranchIndex := make([]int, Ilen)
	j := 0
	k := 0
	zsize := 1024
	for ; zsize > 1; zsize = zsize / 2 {
		i := min(index^1, zsize-1) // nindex^1是异或操作，取邻节点
		BranchIndex[k] = j + i
		k = k + 1
		index = index >> 1 // 右移一位，除以二
		j = j + zsize      // 树的上一层级
	}
	return BranchIndex
}

func GetInvTree(rootinv *FieldVal) {
	treelen := imax*2 - 2
	prevfloorflag := treelen
	prevfloornum := 1
	thisfloorflag := treelen
	treeroot_inv := new(FieldVal)
	treeroot_inv.Set(rootinv)
	ZinvTree[prevfloorflag] = treeroot_inv
	for i := 0; i < Ilen; i++ {
		thisfloornum := prevfloornum * 2
		thisfloorflag = prevfloorflag - thisfloornum
		for f := 0; f < thisfloornum; f++ {
			thisindex := f + thisfloorflag
			ztreeindex := thisindex ^ 1
			thisindexvalue := new(FieldVal)
			thisindexvalue.Set(ZTree[ztreeindex])
			thisindexvalue.Mul2(thisindexvalue, ZinvTree[prevfloorflag+(f/2)])
			ZinvTree[thisindex] = thisindexvalue
		}
		prevfloorflag = thisfloorflag
		prevfloornum = prevfloornum * 2
	}
}

func GetTreeBranchMult(branchindex []int) *FieldVal {
	branchmult := new(FieldVal)
	branchmult.Set(ZTree[branchindex[0]])
	for i := 1; i < Ilen; i++ {
		branchmult.Mul2(branchmult, ZTree[branchindex[i]])
	}
	return branchmult
}

func Encrypt(pubkey *PublicKey, m *big.Int) *Cipher {
	r, _ := NewPrivateKey(c)
	rpkx, rpky := c.ScalarMult(pubkey.X, pubkey.Y, r.D.Bytes())
	mGx, mGy := c.ScalarBaseMult(m.Bytes())
	if m.Cmp(zero) == -1 {
		mGy = mGy.Sub(c.P, mGy)
	}
	c2x, c2y := c.Add(mGx, mGy, rpkx, rpky)
	return &Cipher{r.PublicKey.X, r.PublicKey.Y, c2x, c2y}
}

func NormalEnc(pubkey *PublicKey, m *big.Int) *Cipher {
	r, _ := NewPrivateKey(c)
	rpkx, rpky := c.ScalarMult(pubkey.X, pubkey.Y, r.D.Bytes())
	mGx, mGy := c.ScalarBaseMult(m.Bytes())
	c2x, c2y := c.Add(mGx, mGy, rpkx, rpky)
	return &Cipher{r.PublicKey.X, r.PublicKey.Y, c2x, c2y}
}

func EncryptJob(pubkey *PublicKey, m *big.Int) *FieldCipher {
	r, _ := NewPrivateKey(c)
	rpkx, rpky := c.ScalarMult(pubkey.X, pubkey.Y, r.D.Bytes())
	mGx, mGy := c.ScalarBaseMult(m.Bytes())
	if m.Cmp(zero) == -1 {
		mGy = mGy.Sub(c.P, mGy)
	}
	c2x, c2y, c2z := c.Add1(mGx, mGy, rpkx, rpky)
	c1x, c1y := c.bigAffineToField(r.PublicKey.X, r.PublicKey.Y)
	c1z := new(FieldVal).SetInt(1)
	return &FieldCipher{c1x, c1y, c1z, c2x, c2y, c2z}
}

var GetmG time.Duration = 0
var GetX21 time.Duration = 0
var GetTree1 time.Duration = 0
var GetInv time.Duration = 0
var GetTree2 time.Duration = 0
var BSGS time.Duration = 0
var Verify time.Duration = 0
var GetHash time.Duration = 0
var GetX3 time.Duration = 0
var GetSearch time.Duration = 0

func GetM(c *KoblitzCurve, mGx *big.Int, fmGx *FieldVal, fmGy *FieldVal, start int, end int, m *int64, overthreadnum chan int) {
	for j := start; j < end; j++ {
		if j == 0 {
			// hash time
			x64 := new(big.Int).SetBytes(mGx.Bytes()[:8]).Uint64()
			i, ok := T1.Search(cuckoo.Key(x64))
			if ok {
				*m = int64(i)
				break
			}
		}
		ft2x, ft2y := T2x[j], T2y[j]
		p := new(FieldVal).SetByteSlice(c.P.Bytes())
		leftx, invleftx := c.NewGetx3(fmGx, fmGy, ft2x, ft2y, ZinvTree[j], p)
		x64 := new(big.Int).SetBytes(leftx.Bytes()[:8]).Uint64()
		i, ok := T1.Search(cuckoo.Key(x64))
		if ok {
			*m = int64(j)*int64(jmax) + int64(i)
			break
		}
		x64 = new(big.Int).SetBytes(invleftx.Bytes()[:8]).Uint64()
		i, ok = T1.Search(cuckoo.Key(x64))
		if ok {
			*m = int64(-j)*int64(jmax) - int64(i)
			break
		}
	}
	overthreadnum <- 1
}

func ParDecrypt(priv *PrivateKey, cipher *Cipher) (*big.Int, string) {
	//start1 := time.Now()
	var m int64 = mflag
	skc1x, skc1y := c.ScalarMult(cipher.c1x, cipher.c1y, priv.D.Bytes())
	if skc1x.Cmp(cipher.c2x) == 0 {
		return zero, ""
	}
	inv_skc1y := new(big.Int)
	inv_skc1y.Add(c.P, inv_skc1y)
	inv_skc1y.Sub(inv_skc1y, skc1y)
	mGx, mGy := c.Add(cipher.c2x, cipher.c2y, skc1x, inv_skc1y)
	fmGx, fmGy := c.bigAffineToField(mGx, mGy)
	zs := make([]*FieldVal, imax)
	for i := 0; i < imax; i++ {
		ft2x := T2x[i]
		zs[i] = c.Getz3(fmGx, ft2x)
	}
	treeroot := BuildTree(zs)
	treeroot_inv := new(FieldVal).Set(treeroot).Inverse()
	GetInvTree(treeroot_inv)
	runtime.GOMAXPROCS(8)
	batch := imax / Threadnum
	overthreadnum := make(chan int, 8)
	for t := 0; t < Threadnum; t++ {
		go GetM(c, mGx, fmGx, fmGy, t*batch, (t+1)*batch, &m, overthreadnum)
	}
	for {
		//fmt.Println(overthreadnum)
		if m != mflag {
			TestmGx, _ := c.ScalarBaseMult(big.NewInt(m).Bytes())
			r1 := mGx.Cmp(TestmGx)
			if r1 == 0 {
				return big.NewInt(m), ""
			} else {
				return big.NewInt(0), "decrypt error"
			}
		} else if len(overthreadnum) == Threadnum {
			break
		}
	}
	return big.NewInt(0), "decrypt error"
}

var wg sync.WaitGroup

func GetZS(c *KoblitzCurve, zs []*FieldVal, fmGx *FieldVal, start int, end int) {
	for i := start; i < end; i++ {
		ft2x := T2x[i]
		zs[i] = c.Getz3(fmGx, ft2x)
	}
	wg.Done()
}

func NormalDecrypt(priv *PrivateKey, cipher *Cipher) (*big.Int, error) {
	c := S256()
	m := -1
	skc1x, skc1y := c.ScalarMult(cipher.c1x, cipher.c1y, priv.D.Bytes())
	inv_skc1y := new(big.Int)
	inv_skc1y.Add(c.P, inv_skc1y)
	inv_skc1y.Sub(inv_skc1y, skc1y)
	mGx, mGy := c.Add(cipher.c2x, cipher.c2y, skc1x, inv_skc1y)
	for j := 0; j < imax; j++ {
		if j == 0 {
			x64 := new(big.Int).SetBytes(mGx.Bytes()[:8]).Uint64()
			if i, ok := T1.Search(cuckoo.Key(x64)); ok {
				m = int(i)
				break
			}
		}
		z := new(FieldVal)
		z.SetInt(1)
		t2x, t2y := c.fieldJacobianToBigAffine(T2x[j], T2y[j], z)
		leftx, _ := c.Add(mGx, mGy, t2x, t2y)
		x64 := new(big.Int).SetBytes(leftx.Bytes()[:8]).Uint64()
		if i, ok := T1.Search(cuckoo.Key(x64)); ok {
			m = j*jmax + int(i)
			break
		}
	}
	return big.NewInt(int64(m)), nil
}

func HomoAddField(c1 *Cipher, c2 *Cipher) *FieldCipher {
	c1x, c1y, c1z := c.Add1(c1.c1x, c1.c1y, c2.c1x, c2.c1y)
	c2x, c2y, c2z := c.Add1(c1.c2x, c1.c2y, c2.c2x, c2.c2y)
	return &FieldCipher{c1x, c1y, c1z, c2x, c2y, c2z}
}

func HomoAddField1(c1 *FieldCipher, c2 *FieldCipher) *FieldCipher {
	c1x, c1y, c1z := new(FieldVal), new(FieldVal), new(FieldVal)
	c2x, c2y, c2z := new(FieldVal), new(FieldVal), new(FieldVal)
	c.AddGeneric(c1.c1x, c1.c1y, c1.c1z, c2.c1x, c2.c1y, c2.c1z, c1x, c1y, c1z)
	c.AddGeneric(c1.c2x, c1.c2y, c1.c2z, c2.c2x, c2.c2y, c2.c2z, c2x, c2y, c2z)
	return &FieldCipher{c1x, c1y, c1z, c2x, c2y, c2z}
}

func HomoAdd(c1 *Cipher, c2 *Cipher) *Cipher {
	c1x, c1y := c.Add(c1.c1x, c1.c1y, c2.c1x, c2.c1y)
	c2x, c2y := c.Add(c1.c2x, c1.c2y, c2.c2x, c2.c2y)
	return &Cipher{c1x, c1y, c2x, c2y}
}

func HomoAddPlainText(c1 *Cipher, c2 *big.Int) *Cipher {
	c2x, c2y := c.ScalarBaseMult(c2.Bytes())
	c2x, c2y = c.Add(c1.c2x, c1.c2y, c2x, c2y)
	return &Cipher{c1.c1x, c1.c1y, c2x, c2y}
}

func HomoMul(c1 *Cipher, k *big.Int) *Cipher {
	c1x, c1y := c.ScalarMult(c1.c1x, c1.c1y, k.Bytes())
	c2x, c2y := c.ScalarMult(c1.c2x, c1.c2y, k.Bytes())
	return &Cipher{c1x, c1y, c2x, c2y}
}

func HomoMulField(c1 *Cipher, k *big.Int) *FieldCipher {
	c1x, c1y, c1z := c.ScalarMultField(c1.c1x, c1.c1y, k.Bytes())
	c2x, c2y, c2z := c.ScalarMultField(c1.c2x, c1.c2y, k.Bytes())
	return &FieldCipher{c1x, c1y, c1z, c2x, c2y, c2z}
}

func ConvertCipher(fieldc *FieldCipher) *Cipher {
	c1x, c1y := c.fieldJacobianToBigAffine(fieldc.c1x, fieldc.c1y, fieldc.c1z)
	c2x, c2y := c.fieldJacobianToBigAffine(fieldc.c2x, fieldc.c2y, fieldc.c2z)
	return &Cipher{c1x, c1y, c2x, c2y}
}

func init() {
	var i int64 = 1
	filename := "/home/lgw/go/src/github.com/gerlist/Tx28.txt"
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	rd := bufio.NewReader(file)
	for {
		line, err := rd.ReadString('\n')
		if err != nil || io.EOF == err {
			break
		} else {
			line = strings.Replace(line, "\n", "", -1)
			x64, _ := strconv.ParseUint(line, 10, 64)
			T1.Insert(cuckoo.Key(x64), cuckoo.Value(i))
			//fmt.Println(i)
			if i == int64(jmax) {
				file.Close()
				break
			}
			i++
		}
	}
	var j int64 = 0
	t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(int64(jmax)).Bytes())
	for ; j < int64(imax); j++ {
		//fmt.Printf("%d\n", j)
		jbigint := big.NewInt(-j)
		t2x, t2y := c.ScalarMult(t1lastx, t1lasty, jbigint.Bytes())
		inv_t2y := new(big.Int)
		inv_t2y.Add(c.P, inv_t2y)
		inv_t2y.Sub(inv_t2y, t2y)
		ft2x, ft2y := c.bigAffineToField(t2x, inv_t2y)
		T2x[j] = ft2x
		T2y[j] = ft2y
	}
	fmt.Println("The table is built.")
}
