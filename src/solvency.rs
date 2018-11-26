//Proof of Solvency

/*
A simple proof of solvency

Notation: 
This document uses additive notation for group operations. 
Capitalized letters denote group elements and lower case letters are scalars. 
Let 𝔾 be a group of prime order p in which the discrete logarithm holds. 
Concretely this can be the ristretto group (https://ristretto.group ). 
G,H G,H𝔾 are generators that generated as G=Hash(“EianG”) and H=Hash(“EianH”), 
G+H𝔾 denotes the group operation.

 Commit(x,r)=x*G+r*H is the peddersen commitment function

Input: 
Asset account commitments: CA,1,CA,2...CA,n such that CA,i=Commit(bA,i,rA,i)
Liability account commitments: CL,1,CL,2...CL,msuch that CL,i=Commit(bL,i,rL,i)
Proof:
Let CBalance=i=1nCA,i-i=1mCL,i. Let bBalance=i=1nbA,i-i=1mbL,iand rBalance=i=1nrA,i-i=1mrL,i. Note that CBalance=Commit(bBalance,rBalance). The solvency proof is a range proof that CBalanceis positive, i.e. is between [0,232-1] using bBalance,rBalanceas the witness. 
Proof((bA,1,rA,1)(bA,n,rA,n),(bL,1,bL,1),,(bL,m,bL,m)):
bBalance=i=1nbA,i-i=1mbL,i
rBalance=i=1nrA,i-i=1mrL,i
=RangeProof(bBalance,rBalance)
Output 
Verify(CA,1,,CA,n,CL,1,,CL,m,):
Compute CBalance=i=1nCA,i-i=1mCL,i and then verify using CBalance



*/