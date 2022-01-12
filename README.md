# Improved-Exp-ElGamal
## Points to note before using this code are as follows (we believe this will be the fastest additive homomorphic encryption scheme you will ever use.):
(1) The cuckoo hashing in the directory must be used because we have adjusted the parameters for it. If you use other cuckoo hashing, you may waste time modifying your code.
  
(2) We did not upload the precomputed table for running the BSGS because it is too large, you can generate one from the code in the genlist folder (`go run genlist.go > Tx28.txt`).

(3) 
