![alt text](https://github.com/eianio/zei/raw/master/zei_logo.png)

**Confidential Payments for Accounts**

Zei is a library to help manage an account system that hides transaction amounts.
It Implements Confidential Transactions that was first proposed by [Greg Maxwell](https://people.xiph.org/~greg/confidential_values.txt). It however utilizes [Bulletproofs by Benedikt et al.](https://eprint.iacr.org/2017/1066.pdf) for shorter Rangeproofs. Publickey encryption is utilized to reveal plaintext amounts & blinding factors to the reciever.
This implementation uses Pedersen Commitments and is vulnerable to account poisoning. 


# Benchmarks