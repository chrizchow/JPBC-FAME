# FAME: Fast Attribute-based Message Encryption Scheme in JPBC
This project is the CP-ABE variant of FAME encryption scheme. Implemented based on Java Pairing-Based Cryptography Library (JPBC).

## Description
Attribute-based Encryption (ABE) is a scheme of using attributes to encrypt the content. It makes sure that only users with the corresponding private keys of the attributes can decrypt the content. Generally, CP-ABE is the scheme that ciphertext is encrypted with an access structure (MSP), and each user is given a set of attributes. KP-ABE is the opposite: ciphertexts are "tagged" (encrypted) with a set of attributes, and each user is given an access structure. Both scheme can provide fine-grain user access control in different scenarios.

This project is based on Shashank Agrawal and Melissa Chase's paper [1], and it is the CP-ABE variant mentioned in their paper. The source code in this project also follows their corresponding Charm project [2]. However, the Monotone Span Program (MSP) part of this project can only support AND operations with up to 10 attributes, because I pre-computed the MSP part for simplicity. Also, the AES part has reused the code written by Junwei W.[3], which is originated from his BSW CP-ABE implementation.

This project only supports Type D (Asymmetric) elliptic curve. Although the project still runs if Type A elliptic curve is used, security will NOT be guaranteed as it has never been verified properly in the original paper.

## Known Issues
- Only support `and` operations with maximum 10 attributes. (TODO: implement full MSP)

## Reference
[1] S. Agrawal and M. Chase, “FAME: Fast attribute-based message encryption,” Proc. ACM Conf. Comput. Commun. Secur., pp. 665–682, 2017. [https://eprint.iacr.org/2017/807.pdf](https://eprint.iacr.org/2017/807.pdf)

[2] "Attribute-based Encryption". [https://github.com/sagrawal87/ABE](https://github.com/sagrawal87/ABE)

[3] Junwei Wang. Java Realization for Ciphertext-Policy Attribute-Based Encryption. [https://github.com/junwei-wang/cpabe/](https://github.com/junwei-wang/cpabe/), 2012

[4] A. De Caro and V. Iovino, “jPBC: Java pairing based cryptography,” in Proceedings of the 16th IEEE Symposium on Computers and Communications, ISCC 2011, 2011, pp. 850–855. [http://gas.dia.unisa.it/projects/jpbc/](http://gas.dia.unisa.it/projects/jpbc/)
