# Improved-Exp-ElGamal
## Points to note before using this code are as follows (we believe its efficiency will surprise you):
(1) The cuckoo hashing in the directory must be used because we have adjusted the parameters for it. If you use other cuckoo hashing, you may waste time modifying your code.
  
(2) We did not upload the precomputed table for running the BSGS because it is too large, you can generate one from the code in the genlist folder (`go run genlist.go > Tx28.txt`). At the same time you need to modify the path to this file in the init function in ciphering.go.  

(3) You can get a feel for the efficiency of the improved Exp-ElGamal by running test.go in the test folder. Since reading the precomputed table in step (2) takes some time (maybe a few minutes), you can set Jlen to be less than 24 so you don't wait too long.

(4) If you want to change the length of the plaintext (of course, this is the work after the code runs successfully), you can do it by changing the two variables Ilen and Jlen in ciphering.go, Ilen+Jlen is equal to the length of the plaintext, and our improved-Exp-ElGamal supports negative arithmetic.  

## If you don't want to spend time configuring the environment, get the code running. We also give an experimental result in our environment (clocked at 2.8GHZ):

![Image text](https://github.com/ShallMate/Improved-Exp-ElGamal/blob/main/res.png)
