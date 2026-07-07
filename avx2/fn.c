#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "fn.h"

#if KYBER_FN == 4
/*************************************************
* Name:        fn4
*
* Description: Sample a polynomial with coefficients distributed according to
*              f(4). Two coefficients per input byte (4 bits each).
* Arguments:   - poly *r: pointer to output polynomial
*              - const __m256i *buf: pointer to aligned input byte array
**************************************************/
static void fn4(poly * restrict r, const __m256i buf[KYBER_NOISE_BYTES/32])
{
  unsigned int i;
  __m256i v, x, f0, f1, f2, f3, a1, an, s, pmask, m, twoprod;
  const __m256i mask01 = _mm256_set1_epi8(1);
  const __m256i mask0F = _mm256_set1_epi8(0x0F);
  const __m256i maskF8 = _mm256_set1_epi8((char)0xF8);  /* bits 3..7: isolate low 3 bits */
  const __m256i maskFF = _mm256_set1_epi8((char)0xFF);
  const __m256i two    = _mm256_set1_epi8(2);

  for(i = 0; i < KYBER_N/64; i++) {
    v = _mm256_load_si256(&buf[i]);

    /* low nibble -> even-index coefficients */
    x  = _mm256_and_si256(v, mask0F);
    a1 = _mm256_and_si256(x, mask01);
    an = _mm256_and_si256(_mm256_srli_epi16(x, 3), mask01);      /* bit 3 */
    s  = _mm256_sub_epi8(_mm256_add_epi8(an, an), mask01);       /* 2*a_n - 1 */
    pmask   = _mm256_cmpeq_epi8(_mm256_or_si256(x, maskF8), maskFF);
    twoprod = _mm256_and_si256(pmask, two);                      /* 2*prod */
    m  = _mm256_add_epi8(_mm256_sub_epi8(mask01, a1), twoprod);  /* 1 - a1 + 2*prod */
    f0 = _mm256_sign_epi8(m, s);

    /* high nibble -> odd-index coefficients */
    x  = _mm256_and_si256(_mm256_srli_epi16(v, 4), mask0F);
    a1 = _mm256_and_si256(x, mask01);
    an = _mm256_and_si256(_mm256_srli_epi16(x, 3), mask01);
    s  = _mm256_sub_epi8(_mm256_add_epi8(an, an), mask01);
    pmask   = _mm256_cmpeq_epi8(_mm256_or_si256(x, maskF8), maskFF);
    twoprod = _mm256_and_si256(pmask, two);
    m  = _mm256_add_epi8(_mm256_sub_epi8(mask01, a1), twoprod);
    f1 = _mm256_sign_epi8(m, s);

    /* interleave even/odd coefficients and sign-extend to 16-bit */
    f2 = _mm256_unpacklo_epi8(f0, f1);
    f3 = _mm256_unpackhi_epi8(f0, f1);

    f0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
    f1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2,1));
    f2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
    f3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3,1));

    _mm256_store_si256(&r->vec[4*i+0], f0);
    _mm256_store_si256(&r->vec[4*i+1], f2);
    _mm256_store_si256(&r->vec[4*i+2], f1);
    _mm256_store_si256(&r->vec[4*i+3], f3);
  }
}
#endif

#if KYBER_FN == 6
/*************************************************
* Name:        fn6
*
* Description: Sample a polynomial with coefficients distributed according to
*              f(6). Coefficients span 6 bits and do not align to byte
*              boundaries, so we reuse cbd3's gather (24 bytes -> eight 32-bit
*              lanes, each holding four 6-bit fields at offsets 0,6,12,18) and
*              its final reorder, applying the f(6) arithmetic in between.
*              Uses over-reading loads (needs 32 bytes of trailing slack).
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const __m256i *buf: pointer to aligned input byte array
**************************************************/
static void fn6(poly * restrict r, const __m256i buf[KYBER_NOISE_BYTES/32+1])
{
  unsigned int i;
  __m256i f0, g0, g1, g2, g3, fLo, fHi, t2, t3, a1, an, s, pm, m;
  const uint8_t *p = (const uint8_t *)buf;
  const __m256i mask3F = _mm256_set1_epi32(0x3F);
  const __m256i mask1F = _mm256_set1_epi32(0x1F);
  const __m256i one    = _mm256_set1_epi32(1);
  const __m256i two    = _mm256_set1_epi32(2);
  const __m256i lo16   = _mm256_set1_epi32(0xFFFF);
  const __m256i shufbidx = _mm256_set_epi8(-1,15,14,13,-1,12,11,10,-1, 9, 8, 7,-1, 6, 5, 4,
                                           -1,11,10, 9,-1, 8, 7, 6,-1, 5, 4, 3,-1, 2, 1, 0);

  for(i = 0; i < KYBER_N/32; i++) {
    /* gather: 24 bytes -> each 32-bit lane holds 4 six-bit fields */
    f0 = _mm256_loadu_si256((const __m256i *)&p[24*i]);
    f0 = _mm256_permute4x64_epi64(f0, 0x94);
    f0 = _mm256_shuffle_epi8(f0, shufbidx);

    /* isolate the four 6-bit fields (coeffs 4L+0..4L+3 of lane L) */
    g0 = _mm256_and_si256(f0, mask3F);
    g1 = _mm256_and_si256(_mm256_srli_epi32(f0, 6), mask3F);
    g2 = _mm256_and_si256(_mm256_srli_epi32(f0,12), mask3F);
    g3 = _mm256_and_si256(_mm256_srli_epi32(f0,18), mask3F);

    /* f(6) per field: coeff = (2*a_6 - 1) * (1 - a_1 + 2*prod), prod=a_1..a_5 */
#define FN6(g)                                                              \
    (a1 = _mm256_and_si256(g, one),                                         \
     an = _mm256_and_si256(_mm256_srli_epi32(g, 5), one),                   \
     s  = _mm256_sub_epi32(_mm256_add_epi32(an, an), one),                  \
     pm = _mm256_cmpeq_epi32(_mm256_and_si256(g, mask1F), mask1F),          \
     m  = _mm256_add_epi32(_mm256_sub_epi32(one, a1),                       \
                           _mm256_and_si256(pm, two)),                      \
     _mm256_sign_epi32(m, s))
    g0 = FN6(g0);
    g1 = FN6(g1);
    g2 = FN6(g2);
    g3 = FN6(g3);
#undef FN6

    /* pack two 16-bit coefficients per 32-bit lane, then reorder as in cbd3 */
    fLo = _mm256_or_si256(_mm256_and_si256(g0, lo16), _mm256_slli_epi32(g1, 16));
    fHi = _mm256_or_si256(_mm256_and_si256(g2, lo16), _mm256_slli_epi32(g3, 16));

    t2 = _mm256_unpacklo_epi32(fLo, fHi);
    t3 = _mm256_unpackhi_epi32(fLo, fHi);
    fLo = _mm256_permute2x128_si256(t2, t3, 0x20);
    fHi = _mm256_permute2x128_si256(t2, t3, 0x31);

    _mm256_store_si256(&r->vec[2*i+0], fLo);
    _mm256_store_si256(&r->vec[2*i+1], fHi);
  }
}
#endif

#if KYBER_FN == 8
/*************************************************
* Name:        fn8
*
* Description: Sample a polynomial with coefficients distributed according to
*              f(8). Exactly one coefficient per input byte.
*
* Arguments:   - poly *r: pointer to output polynomial
*              - const __m256i *buf: pointer to aligned input byte array
**************************************************/
static void fn8(poly * restrict r, const __m256i buf[KYBER_NOISE_BYTES/32])
{
  unsigned int i;
  __m256i v, a1, an, s, pmask, m, twoprod, c;
  const __m256i mask01 = _mm256_set1_epi8(1);
  const __m256i mask80 = _mm256_set1_epi8((char)0x80);  /* bit 7: isolate low 7 bits */
  const __m256i maskFF = _mm256_set1_epi8((char)0xFF);
  const __m256i two    = _mm256_set1_epi8(2);

  for(i = 0; i < KYBER_N/32; i++) {
    v  = _mm256_load_si256(&buf[i]);
    a1 = _mm256_and_si256(v, mask01);
    an = _mm256_and_si256(_mm256_srli_epi16(v, 7), mask01);      /* bit 7 */
    s  = _mm256_sub_epi8(_mm256_add_epi8(an, an), mask01);       /* 2*a_n - 1 */
    pmask   = _mm256_cmpeq_epi8(_mm256_or_si256(v, mask80), maskFF);
    twoprod = _mm256_and_si256(pmask, two);                      /* 2*prod */
    m  = _mm256_add_epi8(_mm256_sub_epi8(mask01, a1), twoprod);  /* 1 - a1 + 2*prod */
    c  = _mm256_sign_epi8(m, s);

    _mm256_store_si256(&r->vec[2*i+0], _mm256_cvtepi8_epi16(_mm256_castsi256_si128(c)));
    _mm256_store_si256(&r->vec[2*i+1], _mm256_cvtepi8_epi16(_mm256_extracti128_si256(c,1)));
  }
}
#endif

void poly_fn(poly *r, const __m256i buf[KYBER_NOISE_BYTES/32+1])
{
#if   KYBER_FN == 4
  fn4(r, buf);
#elif KYBER_FN == 6
  fn6(r, buf);
#elif KYBER_FN == 8
  fn8(r, buf);
#else
#error "This implementation requires KYBER_FN in {4,6,8}"
#endif
}
