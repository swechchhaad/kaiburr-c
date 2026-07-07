#include <stdint.h>
#include "params.h"
#include "fn.h"

/* read bit index i from buf, LSB-first */
#define BIT(buf, i) (((buf)[(i)>>3] >> ((i)&7)) & 1)

/*************************************************
* Name:        fn4 / fn6 / fn8
*
* Description: Given a buffer of uniformly random bytes, sample a polynomial
*              whose coefficients follow the distribution f(n):
*                Pr[ 0]  = 1/2 - (1/2)^(n-1)
*                Pr[+-1] = 1/4
*                Pr[+-2] = (1/2)^n
*              Each coefficient consumes n uniformly random bits a_1..a_n
*              and is
*                (2*a_n - 1) * (1 - a_1 + 2 * prod_{i=1}^{n-1} a_i).
* Arguments:   - poly *r: pointer to output polynomial
*              - const uint8_t *buf: input byte array (KYBER_NOISE_BYTES bytes)
**************************************************/
#if KYBER_FN == 4
static void fn4(poly *r, const uint8_t buf[KYBER_NOISE_BYTES])
{
  unsigned int i, b;
  int a1, prod, an;
  for(i = 0; i < KYBER_N; i++) {
    b    = 4*i;                                   /* bit index of a_1 */
    a1   = BIT(buf, b);
    prod = a1 & BIT(buf, b+1) & BIT(buf, b+2);    /* a_1 & a_2 & a_3 */
    an   = BIT(buf, b+3);                          /* a_4 */
    r->coeffs[i] = (int16_t)((2*an - 1) * (1 - a1 + 2*prod));
  }
}
#endif

#if KYBER_FN == 6
static void fn6(poly *r, const uint8_t buf[KYBER_NOISE_BYTES])
{
  unsigned int i, b;
  int a1, prod, an;
  for(i = 0; i < KYBER_N; i++) {
    b    = 6*i;
    a1   = BIT(buf, b);
    prod = a1 & BIT(buf, b+1) & BIT(buf, b+2) & BIT(buf, b+3) & BIT(buf, b+4);
    an   = BIT(buf, b+5);                          /* a_6 */
    r->coeffs[i] = (int16_t)((2*an - 1) * (1 - a1 + 2*prod));
  }
}
#endif

#if KYBER_FN == 8
static void fn8(poly *r, const uint8_t buf[KYBER_NOISE_BYTES])
{
  unsigned int i, b;
  int a1, prod, an;
  for(i = 0; i < KYBER_N; i++) {
    b    = 8*i;                                   /* one byte per coefficient */
    a1   = BIT(buf, b);
    prod = a1 & BIT(buf, b+1) & BIT(buf, b+2) & BIT(buf, b+3)
              & BIT(buf, b+4) & BIT(buf, b+5) & BIT(buf, b+6);
    an   = BIT(buf, b+7);                          /* a_8 */
    r->coeffs[i] = (int16_t)((2*an - 1) * (1 - a1 + 2*prod));
  }
}
#endif

void poly_fn(poly *r, const uint8_t buf[KYBER_NOISE_BYTES])
{
#if   KYBER_FN == 4
  fn4(r, buf);
#elif KYBER_FN == 6
  fn6(r, buf);
#elif KYBER_FN == 8
  fn8(r, buf);
#else
#error "KYBER_FN must be in {4,6,8}"
#endif
}

#undef BIT
