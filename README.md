# Improved-Exp-ElGamal
## Points to note before using this code are as follows (we believe this will be the fastest additive homomorphic encryption scheme you will ever use):
(1) The cuckoo hashing in the directory must be used because we have adjusted the parameters for it. If you use other cuckoo hashing, you may waste time modifying your code.
  
(2) We did not upload the precomputed table for running the BSGS because it is too large, you can generate one from the code in the genlist folder (`go run genlist.go > Tx28.txt`). At the same time you need to modify the path to this file in the init function in ciphering.go.  

(3) If you want to change the length of the plaintext (of course, this is the work after the code runs successfully), you can do it by changing the two variables Ilen and Jlen in ciphering.go, Ilen+Jlen is equal to the length of the plaintext, and it supports negative arithmetic.
