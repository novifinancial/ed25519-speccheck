# ed25519-speccheck

This repository generates and uses test vectors for EdDSA to check edge cases
in the implementation of the algorithm. Namely, we test bounds checks on points
and scalars involved in a signature, along with cofactored vs. cofactorless verification.

We hope this helps outline the measures needed to implement the FIPS 186-5 and
RFC 8032 rigorously.

You can run this utility with `RUST_LOG=debug cargo run` to get a list of the
test vectors and their inteded test conditions.

# Usage

To run the scripts on the connected libraries, execute the `./run.sh` script at
the root of the project.

To print out the test cases, use `RUST_LOG=debug cargo run`.

## Condition table

Those are the cases we considered, with the index of the test vectors when applicable:

```
| n   | parameters              | cofactored        | cofactorless                     | comment                               |
|-----+-------------------------+-------------------+----------------------------------+---------------------------------------|
|0-1  | S = 0, R small, A small | always passes     | R = -k×A                         | see ed25519's verify_strict           |
|     | S > 0, R small, A small | always fails      | always fails                     | no large order component on the right |
|     | S = 0, R mixed, A small | always fails      | always fails                     | no large order component on the left  |
|2-3  | S > 0, R mixed, A small | 8×S×B = 8×R       | 8×S×B = 8×R ∧ L×R = -L×k×A       | [*]                                   |
|     | S = 0, R small, A mixed | always fails      | always fails                     | no large order component on the left  |
|4-5  | S > 0, R small, A mixed | 8×S×B = 8×k×A     | 8×S×B = 8×k×A ∧ L×R = -L×k×A     | symmetric of [*]                      |
|     | S = 0, R mixed, A mixed | 8×R = -8×k×A      | R = -k×A                         | hard to test (req. hash inversion)    |
|6-7  | S > 0, R mixed, A mixed | 8×S×B = 8×R+8×k×A | 8×S×B = 8×R+8×k×A ∧ L×R = -L×k×A |                                       |
|9-10 | S > L                   | always passes     | always passes                    |                                       |
|10-11| R non-canonical, small  | always passes     | always passes                    | depends on reduction bef. hashing     |
|12-13| A non-canonical, small  | always passes     | always passes                    | depends on reduction bef. hashing     |
```

Here "mixed" means with a strictly positive torsion component but not small,
i.e. "mixed" and "small" are mutually exclusive. Out of the eight test cases
above, only some are concretely testable:

-  the 7th line would require a hash inversion to generate.
- The 2nd, 3d and 5th lines cannot produce a valid signature.

We test each vector at lines [1, 4, 6, 8, 9, 10, 11] for cofactored or cofactorless case.

Besides small components, we also test:

- a large S > L (prepared to pass cofactorless and cofactored) (vectors 9, 10,
  where vector 10 contains a S so large it can't have a canonical serialization
  with a null high bit).
- a "pre-reduced" scalar (vector 8), namely one that fails if the verification equation is
  `[8] R + [8 k] A = [8 s] B` rather than the recommended `[8] (R + k A) = [8] sB`.
  (which passes cofactored, without pre-reduction).
- a negative zero point in A (vectors 12 & 13).

For a total of 15 test vectors.

## Verified libraries

- [Apple CryptoKit](https://developer.apple.com/documentation/cryptokit) : in `scripts/ed25519-ios`
- BoringSSL, through [Ring](https://github.com/briansmith/ring) : in unit tests
- [Bouncy Castle (Java)](https://www.bouncycastle.org/java.html) version 1.66 : in `scripts/ed25519-java`
- [Dalek](https://github.com/dalek-cryptography/ed25519-dalek) : in unit tests
- [ed25519-donna from Signal](https://github.com/signalapp/libsignal-protocol-c.git): in `scripts/ed25519-signal-donna`
- [ed25519-java](https://github.com/str4d/ed25519-java) version 0.3.0 : in `scripts/ed25519-java`
- [Go-ed25519](https://golang.org/pkg/crypto/ed25519/) : in `scripts/ed25519_test.go`
- [libra-crypto](https://github.com/libra/libra/tree/master/crypto/crypto) : in unit tests
- LibSodium, through [pynacl](https://github.com/pyca/pynacl) : in `scripts/pynacl_test.py`
- nCipher's ed25519, by Rob Starkey
- [npm's ed25519](https://www.npmjs.com/package/ed25519) : in `scripts/eddsa_test`
- [OpenSSL](https://github.com/openssl/openssl) : in `scripts openssl_3/test_script.sh`
- [Pyca](https://cryptography.io/en/latest/) using OpenSSL 1.1.1g as default backend : in `scripts/pyca-openssl`
- [python-ed25519](https://github.com/warner/python-ed25519)) : in `scripts/python-ed25519`
- [ref10 from SUPERCOP through Python bindings](https://github.com/warner/python-ed25519) : in `scripts/python-ed25519.py`
- [tweetnacl](https://www.npmjs.com/package/tweetnacl) version 1.0.3 : in `scripts/tweetnacl`
- [Zebra](https://github.com/ZcashFoundation/ed25519-zebra) : in unit tests

## Results

```
┌---------------------------------------------------------------------------┐
|Library        | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10| 11| 12| 13| 14|
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|Apple CryptoKit| X | V | X | V | X | V | V | X | X | X | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|BoringSSL      | X | V | X | V | X | V | V | X | X | X | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|Bouncy Castle  | X | V | X | V | X | V | V | X | X | X | X | X | X | X | X |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|Dalek          | X | V | X | V | X | V | V | X | X | X | V | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|ed25519-donna  | X | V | X | V | X | V | V | X | X | V | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|ed25519-java   | X | V | X | V | X | V | V | X | X | V | V | X | X | V | X |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|Go             | X | V | X | V | X | V | V | X | X | X | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|libra-crypto   | X | X | X | X | X | X | V | X | X | X | X | X | X | X | X |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|LibSodium      | X | X | X | X | X | X | V | X | X | X | X | X | X | X | X |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|nCipher        | X | X | X | X | X | V | X | X | X | X | X | ? | ? | ? | ? |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|npm            | X | V | X | V | X | V | V | X | X | X | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|OpenSSL-3.0    | X | V | X | V | X | V | V | X | X | X | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|PyCA           | X | V | X | V | X | V | V | X | X | X | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|python-ed25519 | X | V | X | V | X | V | V | X | X | V | V | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|ref10          | X | V | X | V | X | V | V | X | X | V | X | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|TweetNaCl-js   | X | V | X | V | X | V | V | X | X | V | V | X | X | X | V |
|---------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---|
|Zebra          | V | V | V | V | V | V | V | V | V | X | X | X | V | V | V |
└---------------------------------------------------------------------------┘

```
