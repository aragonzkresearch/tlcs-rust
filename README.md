
# Time Lock Cryptographic Service (TLCS) based on League of Entropy (a.k.a. drand)

## Overview
The repository provides implementation of the efficient TLCS protocol (in `rust`), described in this [note](https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ) that builds on the LOE (a.k.a. [drand](https://github.com/drand/drand) ) service. In this implementation we used [`arkworks`](https://github.com/arkworks-rs) which is a `rust` ecosystem for zkSNARK programming.

**Important Note:**
1. This section is still a work in progress and has not reached its completion.
2. This portion of the code is experimental and not yet ready for usage in the main project.
3. Some of the components in this repo have not yet passed the required tests.
4. More information on the protocol and methods can be found here: [azkr-timelock-zone](https://github.com/aragonzkresearch/blog/blob/main/pdf/azkr-timelock-zone.pdf) and [How to Build a Time Lock Crypto Service based on League of Entropy.](https://hackmd.io/WYp7A-jPQvK8xSB1pyH7hQ)



## Goal:
The TLCS library allows to create public keys for any elliptic curve supported by `arkwork` and in addition the `G1` group of the `BLS12_381` curve and the babyjubjub curve.


---

Aragon ZK Research Team: https://research.aragon.org/
