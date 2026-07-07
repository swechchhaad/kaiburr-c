#ifndef FN_H
#define FN_H

#include <stdint.h>
#include "params.h"
#include "poly.h"

#define poly_fn KYBER_NAMESPACE(poly_fn)
void poly_fn(poly *r, const uint8_t buf[KYBER_NOISE_BYTES]);

#endif
