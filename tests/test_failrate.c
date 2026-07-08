#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "kem.h"
#include "fips202.h"

#ifndef NRUNS
#define NRUNS 10000000LL      /* 10^7 */
#endif
#ifndef PROGRESS
#define PROGRESS 100000LL
#endif

static void iter_coins(uint8_t out[96], unsigned long long iter)
{
  static const uint8_t base[32] = {
    0xA5,0x5A,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,
    0xEE,0xFF,0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0x10,0x32,0x54,0x76,0x98,0xBA};
  uint8_t in[40];
  unsigned j;
  memcpy(in, base, 32);
  for(j=0;j<8;j++) in[32+j] = (uint8_t)(iter >> (8*j));
  shake256(out, 96, in, 40);
}

int main(int argc, char **argv)
{
  uint8_t pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ka[CRYPTO_BYTES], kb[CRYPTO_BYTES];
  uint8_t coins[96];
  long long i, fails = 0;
  long long N = (argc > 1) ? atoll(argv[1]) : NRUNS;
  time_t t0 = time(NULL);

  setvbuf(stdout, NULL, _IOLBF, 0);
  printf("failrate %s  N=%lld  (deterministic; failures reproducible by iter index)\n",
         CRYPTO_ALGNAME, N);

  for(i = 1; i <= N; i++) {
    iter_coins(coins, (unsigned long long)i);
    crypto_kem_keypair_derand(pk, sk, coins);
    crypto_kem_enc_derand(ct, kb, pk, coins + 64);
    crypto_kem_dec(ka, ct, sk);
    if(memcmp(ka, kb, CRYPTO_BYTES) != 0) {
      fails++;
      printf("!! DECAP FAILURE  %s  iter=%lld  (reproduce with base_seed||%lld)\n",
             CRYPTO_ALGNAME, i, i);
    }
    if(i % PROGRESS == 0) {
      double el = difftime(time(NULL), t0);
      double rate = el > 0 ? i / el : 0;
      double eta  = rate > 0 ? (N - i) / rate : 0;
      printf("%-9s %10lld/%-10lld fails=%lld  elapsed=%.0fs  %.0f/s  ETA=%.0fs\n",
             CRYPTO_ALGNAME, i, N, fails, el, rate, eta);
    }
  }
  printf("%-9s DONE  N=%lld  failures=%lld\n", CRYPTO_ALGNAME, N, fails);
  return fails ? 1 : 0;
}
