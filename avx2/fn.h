#ifndef FN_H
#define FN_H

#include <stdint.h>
#include <immintrin.h>
#include "params.h"
#include "poly.h"

#define poly_fn KYBER_NAMESPACE(poly_fn)
void poly_fn(poly *r, const __m256i buf[KYBER_NOISE_BYTES/32+1]);

#endif