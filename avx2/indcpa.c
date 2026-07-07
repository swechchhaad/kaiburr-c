#include <stddef.h>
#include <stdint.h>
#include <immintrin.h>
#include <string.h>
#include "align.h"
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "ntt.h"
#include "cbd.h"
#include "rejsample.h"
#include "symmetric.h"
#include "randombytes.h"

/*************************************************
* Name:        pack_pk
*
* Description: Serialize the public key as concatenation of the
*              serialized vector of polynomials pk and the
*              public seed used to generate the matrix A.
*              The polynomial coefficients in pk are assumed to
*              lie in the invertal [0,q], i.e. pk must be reduced
*              by polyvec_reduce().
*
* Arguments:   uint8_t *r: pointer to the output serialized public key
*              polyvec *pk: pointer to the input public-key polyvec
*              const uint8_t *seed: pointer to the input public seed
**************************************************/
static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  polyvec_tobytes(r, pk);
  memcpy(r+KYBER_POLYVECBYTES, seed, KYBER_SYMBYTES);
}

/*************************************************
* Name:        unpack_pk
*
* Description: De-serialize public key from a byte array;
*              approximate inverse of pack_pk
*
* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
*              - uint8_t *seed: pointer to output seed to generate matrix A
*              - const uint8_t *packedpk: pointer to input serialized public key
**************************************************/
static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  polyvec_frombytes(pk, packedpk);
  memcpy(seed, packedpk+KYBER_POLYVECBYTES, KYBER_SYMBYTES);
}

/*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key.
*              The polynomial coefficients in sk are assumed to
*              lie in the invertal [0,q], i.e. sk must be reduced
*              by polyvec_reduce().
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

/*************************************************
* Name:        unpack_sk
*
* Description: De-serialize the secret key; inverse of pack_sk
*
* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
*              - const uint8_t *packedsk: pointer to input serialized secret key
**************************************************/
static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

/*************************************************
* Name:        pack_ciphertext
*
* Description: Serialize the ciphertext as concatenation of the
*              serialized vector of polynomials b
*              and the serialized polynomial v.
*              The polynomial coefficients in b and v are assumed to
*              lie in the invertal [0,q], i.e. b and v must be reduced
*              by polyvec_reduce() and poly_reduce(), respectively.
*
* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
*              poly *pk: pointer to the input vector of polynomials b
*              poly *v: pointer to the input polynomial v
**************************************************/
static void pack_ciphertext(uint8_t r[KYBER_INDCPA_BYTES], polyvec *b, poly *v)
{
  polyvec_tobytes(r, b);
  poly_tobytes(r+KYBER_POLYVECBYTES, v);
}

/*************************************************
* Name:        unpack_ciphertext
*
* Description: De-serialize ciphertext from a byte array;
*              approximate inverse of pack_ciphertext
*
* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
*              - poly *v: pointer to the output polynomial v
*              - const uint8_t *c: pointer to the input serialized ciphertext
**************************************************/
static void unpack_ciphertext(polyvec *b, poly *v, const uint8_t c[KYBER_INDCPA_BYTES])
{
  polyvec_frombytes(b, c);
  poly_frombytes(v, c+KYBER_POLYVECBYTES);
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output array
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos <= buflen - 3) {  // buflen is always at least 3
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)

/*************************************************
* Name:        gen_matrix_x4
*
* Description: Sample four matrix entries at once, leveraging the 4-way
*              batched Keccak. Mirrors mlkem-native's mlk_poly_rej_uniform_x4.
*
* Arguments:   - poly *r0,r1,r2,r3: pointers to the four output polynomials
*              - const uint8_t *seed: pointer to the 32-byte public seed
*              - const uint8_t *nonces: eight nonce bytes (x0,y0,...,x3,y3),
*                                       one (x,y) pair per output polynomial
**************************************************/
static void gen_matrix_x4(poly *r0, poly *r1, poly *r2, poly *r3,
                          const uint8_t seed[32], const uint8_t nonces[8])
{
  unsigned int ctr0, ctr1, ctr2, ctr3;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf[4];
  __m256i f;
  keccakx4_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf[0].vec, f);
  _mm256_store_si256(buf[1].vec, f);
  _mm256_store_si256(buf[2].vec, f);
  _mm256_store_si256(buf[3].vec, f);

  buf[0].coeffs[32] = nonces[0]; buf[0].coeffs[33] = nonces[1];
  buf[1].coeffs[32] = nonces[2]; buf[1].coeffs[33] = nonces[3];
  buf[2].coeffs[32] = nonces[4]; buf[2].coeffs[33] = nonces[5];
  buf[3].coeffs[32] = nonces[6]; buf[3].coeffs[33] = nonces[7];

  shake128x4_absorb_once(&state, buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 34);
  shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr0 = rej_uniform_avx(r0->coeffs, buf[0].coeffs);
  ctr1 = rej_uniform_avx(r1->coeffs, buf[1].coeffs);
  ctr2 = rej_uniform_avx(r2->coeffs, buf[2].coeffs);
  ctr3 = rej_uniform_avx(r3->coeffs, buf[3].coeffs);

  while(ctr0 < KYBER_N || ctr1 < KYBER_N || ctr2 < KYBER_N || ctr3 < KYBER_N) {
    shake128x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs, buf[2].coeffs, buf[3].coeffs, 1, &state);

    ctr0 += rej_uniform(r0->coeffs + ctr0, KYBER_N - ctr0, buf[0].coeffs, SHAKE128_RATE);
    ctr1 += rej_uniform(r1->coeffs + ctr1, KYBER_N - ctr1, buf[1].coeffs, SHAKE128_RATE);
    ctr2 += rej_uniform(r2->coeffs + ctr2, KYBER_N - ctr2, buf[2].coeffs, SHAKE128_RATE);
    ctr3 += rej_uniform(r3->coeffs + ctr3, KYBER_N - ctr3, buf[3].coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(r0);
  poly_nttunpack(r1);
  poly_nttunpack(r2);
  poly_nttunpack(r3);
}

/*************************************************
* Name:        gen_matrix_x1
*
* Description: Sample a single matrix entry using the 1-way Keccak. Used for
*              the leftover entries when KYBER_K*KYBER_K is not a multiple of 4.
*
* Arguments:   - poly *r: pointer to the output polynomial
*              - const uint8_t *seed: pointer to the 32-byte public seed
*              - uint8_t x, y: the two nonce bytes for this entry
**************************************************/
static void gen_matrix_x1(poly *r, const uint8_t seed[32], uint8_t x, uint8_t y)
{
  unsigned int ctr;
  ALIGNED_UINT8(REJ_UNIFORM_AVX_NBLOCKS*SHAKE128_RATE) buf;
  __m256i f;
  keccak_state state;

  f = _mm256_loadu_si256((__m256i *)seed);
  _mm256_store_si256(buf.vec, f);
  buf.coeffs[32] = x;
  buf.coeffs[33] = y;

  shake128_absorb_once(&state, buf.coeffs, 34);
  shake128_squeezeblocks(buf.coeffs, REJ_UNIFORM_AVX_NBLOCKS, &state);

  ctr = rej_uniform_avx(r->coeffs, buf.coeffs);
  while(ctr < KYBER_N) {
    shake128_squeezeblocks(buf.coeffs, 1, &state);
    ctr += rej_uniform(r->coeffs + ctr, KYBER_N - ctr, buf.coeffs, SHAKE128_RATE);
  }

  poly_nttunpack(r);
}

/*************************************************
* Name:        gen_matrix
*
* Description: Deterministically generate matrix A (or the transpose of A)
*              from a seed. Entries of the matrix are polynomials that look
*              uniformly random. Performs rejection sampling on output of
*              a XOF.
*
*              Entries are sampled four at a time through the batched Keccak,
*              iterating over all KYBER_K*KYBER_K entries in row-major order.
*              This mirrors the reference gen_matrix loop (and mlkem-native's
*              mlk_gen_matrix).
*
* Arguments:   - polyvec *a: pointer to ouptput matrix A
*              - const uint8_t *seed: pointer to input seed
*              - int transposed: boolean deciding whether A or A^T is generated
**************************************************/
void gen_matrix(polyvec *a, const uint8_t seed[32], int transposed)
{
  unsigned int i, j;
  uint8_t nonces[8];

  /* four matrix entries at a time via the batched Keccak */
  for(i = 0; i + 4 <= KYBER_K*KYBER_K; i += 4) {
    for(j = 0; j < 4; j++) {
      uint8_t x = (uint8_t)((i+j)/KYBER_K);   /* row */
      uint8_t y = (uint8_t)((i+j)%KYBER_K);   /* col */
      if(transposed) {
        nonces[2*j+0] = x;
        nonces[2*j+1] = y;
      } else {
        nonces[2*j+0] = y;
        nonces[2*j+1] = x;
      }
    }
    gen_matrix_x4(&a[ i   /KYBER_K].vec[ i   %KYBER_K],
                  &a[(i+1)/KYBER_K].vec[(i+1)%KYBER_K],
                  &a[(i+2)/KYBER_K].vec[(i+2)%KYBER_K],
                  &a[(i+3)/KYBER_K].vec[(i+3)%KYBER_K],
                  seed, nonces);
  }

  /* leftover entries (KYBER_K*KYBER_K mod 4) one at a time */
  for(; i < KYBER_K*KYBER_K; i++) {
    uint8_t x = (uint8_t)(i/KYBER_K);   /* row */
    uint8_t y = (uint8_t)(i%KYBER_K);   /* col */
    if(transposed)
      gen_matrix_x1(&a[i/KYBER_K].vec[i%KYBER_K], seed, x, y);
    else
      gen_matrix_x1(&a[i/KYBER_K].vec[i%KYBER_K], seed, y, x);
  }
}

/*************************************************
* Name:        indcpa_keypair_derand
*
* Description: Generates public and private key for the CPA-secure
*              public-key encryption scheme underlying Kyber
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
*              - uint8_t *sk: pointer to output private key
*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
*              - const uint8_t *coins: pointer to input randomness
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
void indcpa_keypair_derand(uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                           uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES],
                           const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t buf[2*KYBER_SYMBYTES];
  const uint8_t *publicseed = buf;
  const uint8_t *noiseseed = buf + KYBER_SYMBYTES;
  polyvec a[KYBER_K], e, pkpv, skpv;

  memcpy(buf, coins, KYBER_SYMBYTES);
  buf[KYBER_SYMBYTES] = KYBER_K;
  hash_g(buf, buf, KYBER_SYMBYTES+1);

  gen_a(a, publicseed);

#if KYBER_K == 2
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, e.vec+0, e.vec+1, noiseseed, 0, 1, 2, 3);
#elif KYBER_K == 3
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, skpv.vec+2, e.vec+0, noiseseed, 0, 1, 2, 3);
  poly_getnoise_eta1_4x(e.vec+1, e.vec+2, pkpv.vec+0, pkpv.vec+1, noiseseed, 4, 5, 6, 7);
#elif KYBER_K == 4
  poly_getnoise_eta1_4x(skpv.vec+0, skpv.vec+1, skpv.vec+2, skpv.vec+3, noiseseed,  0, 1, 2, 3);
  poly_getnoise_eta1_4x(e.vec+0, e.vec+1, e.vec+2, e.vec+3, noiseseed, 4, 5, 6, 7);
#endif

  polyvec_ntt(&skpv);
  polyvec_reduce(&skpv);
  polyvec_ntt(&e);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++) {
    polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
    poly_tomont(&pkpv.vec[i]);
  }

  polyvec_add(&pkpv, &pkpv, &e);
  polyvec_reduce(&pkpv);

  pack_sk(sk, &skpv);
  pack_pk(pk, &pkpv, publicseed);
}

/*************************************************
* Name:        indcpa_enc
*
* Description: Encryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *c: pointer to output ciphertext
*                            (of length KYBER_INDCPA_BYTES bytes)
*              - const uint8_t *m: pointer to input message
*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
*              - const uint8_t *pk: pointer to input public key
*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
*              - const uint8_t *coins: pointer to input random coins used as seed
*                                      (of length KYBER_SYMBYTES) to deterministically
*                                      generate all randomness
**************************************************/
void indcpa_enc(uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[KYBER_SYMBYTES])
{
  unsigned int i;
  uint8_t seed[KYBER_SYMBYTES];
  polyvec sp, pkpv, ep, at[KYBER_K], b;
  poly v, k, epp;

  unpack_pk(&pkpv, seed, pk);
  poly_frommsg(&k, m);
  gen_at(at, seed);

#if KYBER_K == 2
  poly_getnoise_eta1122_4x(sp.vec+0, sp.vec+1, ep.vec+0, ep.vec+1, coins, 0, 1, 2, 3);
  poly_getnoise_eta2(&epp, coins, 4);
#elif KYBER_K == 3
  poly_getnoise_eta1_4x(sp.vec+0, sp.vec+1, sp.vec+2, ep.vec+0, coins, 0, 1, 2 ,3);
  poly_getnoise_eta1_4x(ep.vec+1, ep.vec+2, &epp, b.vec+0, coins,  4, 5, 6, 7);
#elif KYBER_K == 4
  poly_getnoise_eta1_4x(sp.vec+0, sp.vec+1, sp.vec+2, sp.vec+3, coins, 0, 1, 2, 3);
  poly_getnoise_eta1_4x(ep.vec+0, ep.vec+1, ep.vec+2, ep.vec+3, coins, 4, 5, 6, 7);
  poly_getnoise_eta2(&epp, coins, 8);
#endif

  polyvec_ntt(&sp);

  // matrix-vector multiplication
  for(i=0;i<KYBER_K;i++)
    polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);
  polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

  polyvec_invntt_tomont(&b);
  poly_invntt_tomont(&v);

  polyvec_add(&b, &b, &ep);
  poly_add(&v, &v, &epp);
  poly_add(&v, &v, &k);
  polyvec_reduce(&b);
  poly_reduce(&v);

  pack_ciphertext(c, &b, &v);
}

/*************************************************
* Name:        indcpa_dec
*
* Description: Decryption function of the CPA-secure
*              public-key encryption scheme underlying Kyber.
*
* Arguments:   - uint8_t *m: pointer to output decrypted message
*                            (of length KYBER_INDCPA_MSGBYTES)
*              - const uint8_t *c: pointer to input ciphertext
*                                  (of length KYBER_INDCPA_BYTES)
*              - const uint8_t *sk: pointer to input secret key
*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
**************************************************/
void indcpa_dec(uint8_t m[KYBER_INDCPA_MSGBYTES],
                const uint8_t c[KYBER_INDCPA_BYTES],
                const uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec b, skpv;
  poly v, mp;

  unpack_ciphertext(&b, &v, c);
  unpack_sk(&skpv, sk);

  polyvec_ntt(&b);
  polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
  poly_invntt_tomont(&mp);

  poly_sub(&mp, &v, &mp);
  poly_reduce(&mp);

  poly_tomsg(m, &mp);
}
