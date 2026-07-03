#ifndef API_H
#define API_H

#include <stdint.h>

/* kaiburr4, k=7 */
#define kaiburr4_SECRETKEYBYTES   5472
#define kaiburr4_PUBLICKEYBYTES   2720
#define kaiburr4_CIPHERTEXTBYTES  3072
#define kaiburr4_KEYPAIRCOINBYTES   64
#define kaiburr4_ENCCOINBYTES       32
#define kaiburr4_BYTES              32

#define kaiburr4_ref_SECRETKEYBYTES  kaiburr4_SECRETKEYBYTES
#define kaiburr4_ref_PUBLICKEYBYTES  kaiburr4_PUBLICKEYBYTES
#define kaiburr4_ref_CIPHERTEXTBYTES kaiburr4_CIPHERTEXTBYTES
#define kaiburr4_ref_KEYPAIRCOINBYTES kaiburr4_KEYPAIRCOINBYTES
#define kaiburr4_ref_ENCCOINBYTES    kaiburr4_ENCCOINBYTES
#define kaiburr4_ref_BYTES           kaiburr4_BYTES

int kaiburr4_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int kaiburr4_ref_keypair(uint8_t *pk, uint8_t *sk);
int kaiburr4_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int kaiburr4_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kaiburr4_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* kaiburr6, k=18 */
#define kaiburr6_SECRETKEYBYTES  13920
#define kaiburr6_PUBLICKEYBYTES   6944
#define kaiburr6_CIPHERTEXTBYTES  7296
#define kaiburr6_KEYPAIRCOINBYTES   64
#define kaiburr6_ENCCOINBYTES       32
#define kaiburr6_BYTES              32

#define kaiburr6_ref_SECRETKEYBYTES  kaiburr6_SECRETKEYBYTES
#define kaiburr6_ref_PUBLICKEYBYTES  kaiburr6_PUBLICKEYBYTES
#define kaiburr6_ref_CIPHERTEXTBYTES kaiburr6_CIPHERTEXTBYTES
#define kaiburr6_ref_KEYPAIRCOINBYTES kaiburr6_KEYPAIRCOINBYTES
#define kaiburr6_ref_ENCCOINBYTES    kaiburr6_ENCCOINBYTES
#define kaiburr6_ref_BYTES           kaiburr6_BYTES

int kaiburr6_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int kaiburr6_ref_keypair(uint8_t *pk, uint8_t *sk);
int kaiburr6_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int kaiburr6_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kaiburr6_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* kaiburr8, k=24 */
#define kaiburr8_SECRETKEYBYTES  18528
#define kaiburr8_PUBLICKEYBYTES   9248
#define kaiburr8_CIPHERTEXTBYTES  9600
#define kaiburr8_KEYPAIRCOINBYTES   64
#define kaiburr8_ENCCOINBYTES       32
#define kaiburr8_BYTES              32

#define kaiburr8_ref_SECRETKEYBYTES  kaiburr8_SECRETKEYBYTES
#define kaiburr8_ref_PUBLICKEYBYTES  kaiburr8_PUBLICKEYBYTES
#define kaiburr8_ref_CIPHERTEXTBYTES kaiburr8_CIPHERTEXTBYTES
#define kaiburr8_ref_KEYPAIRCOINBYTES kaiburr8_KEYPAIRCOINBYTES
#define kaiburr8_ref_ENCCOINBYTES    kaiburr8_ENCCOINBYTES
#define kaiburr8_ref_BYTES           kaiburr8_BYTES

int kaiburr8_ref_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
int kaiburr8_ref_keypair(uint8_t *pk, uint8_t *sk);
int kaiburr8_ref_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
int kaiburr8_ref_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int kaiburr8_ref_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#endif
