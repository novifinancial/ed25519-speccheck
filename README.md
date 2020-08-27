# ed25519-speccheck

This repository generates and uses test vectors for EdDSA to check edge cases
in the implementation of the algorithm. Namely, we test bounds checks on points
and scalars involved in a signature, along with cofactored vs. cofactorless verification.

We hope this helps outline the measures needed to implement the FIPS 186-5 and
RFC 8022 rigorously.

## Condition table

Those are a few of the cases we would like to cover:

```
| | parameters              | cofactored        | cofactorless                     | comment                               |
|-+-------------------------+-------------------+----------------------------------+---------------------------------------|
|1| S = 0, R small, A small | always passes     | R = -k×A                         | see ed25519's verify_strict           |
|2| S > 0, R small, A small | always fails      | always fails                     | no large order component on the right |
|3| S = 0, R mixed, A small | always fails      | always fails                     | no large order component on the left  |
|4| S > 0, R mixed, A small | 8×S×B = 8×R       | 8×S×B = 8×R ∧ L×R = -L×k×A       | [*]                                   |
|5| S = 0, R small, A mixed | always fails      | always fails                     | no large order component on the left  |
|6| S > 0, R small, A mixed | 8×S×B = 8×k×A     | 8×S×B = 8×k×A ∧ L×R = -L×k×A     | symmetric of [*]                      |
|7| S = 0, R mixed, A mixed | 8×R = -8×k×A      | R = -k×A                         | hard to test (req. hash inversion)    |
|8| S > 0, R mixed, A mixed | 8×S×B = 8×R+8×k×A | 8×S×B = 8×R+8×k×A ∧ L×R = -L×k×A |                                       |
```

Here "mixed" means with a strictly positive torsion component but not small,
i.e. "mixed" and "small" are mutually exclusive. Out of the eight test cases
above, only 4 are concretely testable:

-  the 7th test vector would require a hash inversion to generate.
- The 2nd, 3d and 5th compinations of cases cannot produce a valid signature.

We test each vector in [1, 4, 6, 8] for each cofactored or cofactorless case.

Besides that, we also test:

- a large S > L (prepared to pass cofactorless and cofactored).
- "pre-reduced" scalar, namely if the verification equation is
  `[8] R + [8 k] A = [8 s] B` rather than the recommended `[8] (R + k A) = [8] sB`.
  (which passes cofactored, without pre-reduction)

For a total of 10 test vectors.

## Verified libraries

- [Dalek](https://github.com/dalek-cryptography/ed25519-dalek) : in unit tests
- [Zebra](https://github.com/ZcashFoundation/ed25519-zebra) : in unit tests
- BoringSSL, through [Ring](https://github.com/briansmith/ring) : in unit tests
- [Go-ed25519](https://golang.org/pkg/crypto/ed25519/) : in scripts/ed25519_test.go
- [ed25519-java](https://github.com/str4d/ed25519-java) : in scripts/ed25519-java
- [bouncycastle](https://www.bouncycastle.org/) : in scripts/ed25519-java
- LibSodium, through [pynacl](https://github.com/pyca/pynacl) : in scripts/pynacl_test.py
- [npm's ed25519](https://www.npmjs.com/package/ed25519) : in scripts/eddsa_test
- [Pyca](https://cryptography.io/en/latest/) using OpenSSL 1.1.1g as default backend : in scripts/pyca-openssl
- [OpenSSL](https://github.com/openssl/openssl) : in scripts openssl_3/test_script.sh
- [tweetnacl](https://www.npmjs.com/package/tweetnacl) version 1.0.3 : in scripts/tweetnacl
- [ref10 from SUPERCOP through Python bindings](https://github.com/warner/python-ed25519) : in scripts/python-ed25519.py
- [ed25519-donna from Signal](https://github.com/signalapp/libsignal-protocol-c.git): in scripts/ed25519-signal-donna
- ed25519 on nCipher, by Rob Starkey

## Claimed (but feel free to steal)
