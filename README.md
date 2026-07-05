# Scaling ML-KEM to (much) higher security levels

Kaiburr is a research-oriented fork of the [reference implementation of
**Kyber / ML-KEM**](https://github.com/pq-crystals/kyber). It targets higher
security levels and differs from Kyber in three specific ways.

## How Kaiburr differs from Kyber

| Aspect | Kyber / ML-KEM (`ref`) | Kaiburr |
| --- | --- | --- |
| Secret/error noise | Centered Binomial Distribution (CBD) with parameters η₁, η₂ | **`f(n)`** over `{−2,−1,0,1,2}` (see [fn.c](fn.c)) |
| Ciphertext compression | `b` and `v` are compressed (`d_u`, `d_v` bits/coeff) | **No compression** |
| Module rank `KYBER_K` | 2 / 3 / 4 (Kyber512 / 768 / 1024) | **7 / 18 / 24** |

### Noise distribution `f(n)`

Kyber samples secret and error coefficients from a centered binomial distribution. Kaiburr
replaces this with the distribution `f(n)`, implemented in [fn.c](fn.c). Each coefficient
consumes `n` uniformly random bits $a_1, \dots, a_n$ and is computed as:

$$c = (2a_n - 1)\left(1 - a_1 + 2\prod_{i=1}^{n-1} a_i\right)$$

which yields:

| value | probability |
| --- | --- |
| $0$ | $\tfrac{1}{2} - \left(\tfrac{1}{2}\right)^{n-1}$ |
| $\pm 1$ | $\tfrac{1}{4}$ each |
| $\pm 2$ | $\left(\tfrac{1}{2}\right)^{n}$ each |

The parameter `n` is `KYBER_FN ∈ {4, 6, 8}` and selects the variant. The sampler reads
`KYBER_NOISE_BYTES = n·256/8` bytes of PRF output per polynomial.

## Parameter sets

| Variant | `KYBER_K` | `f(n)` = `KYBER_FN` | Public key | Secret key | Ciphertext | Shared secret |
| --- | --- | --- | --- | --- | --- | --- |
| kaiburr4 | 7  | 4 | 2720 | 5472  | 3072 | 32 |
| kaiburr6 | 18 | 6 | 6944 | 13920 | 7296 | 32 |
| kaiburr8 | 24 | 8 | 9248 | 18528 | 9600 | 32 |

## Repository layout

```
fn.c / fn.h            f(n) noise sampler (replaces cbd.c/cbd.h)
params.h               parameters; maps KYBER_K → variant, KYBER_FN, sizes
indcpa.c / indcpa.h    IND-CPA PKE (keygen / enc / dec), ciphertext (de)serialization
kem.c / kem.h          IND-CCA2 KEM (FO transform) — the public API
poly.*, polyvec.*      polynomial / vector arithmetic and serialization
ntt.c, reduce.c        number-theoretic transform and modular reduction
fips202.c, symmetric-shake.c, symmetric.h   SHAKE/SHA3 primitives
verify.c, randombytes.c                     constant-time compare, RNG
api.h                  per-variant sizes and namespaced function prototypes
test/                  round-trip, known-answer, and speed tests
Makefile               build targets
```

## Building and running the tests

Requires a C compiler and `make`. The variant is selected at compile time via `-DKYBER_K`.

### Build

```bash
make test     # functional tests: test_kaiburr{4,6,8} + test_vectors{4,6,8}
make speed    # benchmarks:       test_speed{4,6,8}
make shared   # shared libraries under lib/
```

### Run the round-trip / functional tests

Each binary runs many keygen → encapsulate → decapsulate cycles and checks that both sides
derive the same shared secret.

```bash
./test/test_kaiburr4
./test/test_kaiburr6
./test/test_kaiburr8
```

Verify success explicitly with the exit code:

```bash
./test/test_kaiburr6 && echo "PASS ($?)"
```

### Run the deterministic test vectors

```bash
./test/test_vectors6
```

### Benchmarks (optional)

```bash
make speed
./test/test_speed6
```

### Clean

```bash
make clean
```