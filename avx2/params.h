#ifndef PARAMS_H
#define PARAMS_H

#ifndef KYBER_K
#define KYBER_K 18
#endif

/* Don't change parameters below this line */
#if   (KYBER_K == 7)
#define KYBER_NAMESPACE(s) kaiburr4_avx2_##s
#elif (KYBER_K == 18)
#define KYBER_NAMESPACE(s) kaiburr6_avx2_##s
#elif (KYBER_K == 24)
#define KYBER_NAMESPACE(s) kaiburr8_avx2_##s
#else
#error "KYBER_K must be in {7,18,24}"
#endif

#define KYBER_N 256
#define KYBER_Q 3329

#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */

#define KYBER_POLYBYTES		384
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)

#if   (KYBER_K == 7)      /* kaiburr4 */
#define KYBER_FN 4
#elif (KYBER_K == 18)     /* kaiburr6 */
#define KYBER_FN 6
#elif (KYBER_K == 24)     /* kaiburr8 */
#define KYBER_FN 8
#endif

#define KYBER_NOISE_BYTES (KYBER_FN*KYBER_N/8)   /* n uniform bits per coefficient */

#define KYBER_INDCPA_MSGBYTES       (KYBER_SYMBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECBYTES + KYBER_POLYBYTES)

#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

#endif
