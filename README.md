# ed25519-speccheck


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
i.e. "mixed" and "small" are mutually exclusive. Besides that, we also test:

- a large S > L.
- "pre-reduced" scalar, namely if the verification equation is
  `[8] R + [8 k] A = [8 s] B` rather than the recommended `[8] (R + k A) = [8] sB`.

## Randomized batching

TODO


## Verified libraries

- [Dalek](https://github.com/dalek-cryptography/ed25519-dalek) : in unit tests,
- [Zebra](https://github.com/ZcashFoundation/ed25519-zebra) : in unit tests,
- BoringSSL, through [Ring](https://github.com/briansmith/ring): in unit tests,
- [Go-ed25519](https://golang.org/pkg/crypto/ed25519/), in scripts/ed25519_test.go
- [ed25519-java](https://github.com/str4d/ed25519-java), in scripts/ed25519-java
- [bouncycastle](https://www.bouncycastle.org/), in scripts/ed25519-java
- LibSodium, through [pynacl](https://github.com/pyca/pynacl), in scripts/pynacl_test.py
- [npm's ed25519](https://www.npmjs.com/package/ed25519) in scripts/eddsa_test
- [Pyca](https://cryptography.io/en/latest/)
- [OpenSSL](https://github.com/openssl/openssl) in scripts openssl_3/test_script.sh

## Claimed (but feel free to steal)

- ed25519-donna, by @kevinlewi
