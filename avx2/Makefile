CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -mavx2 -mbmi2 -mpopcnt \
  -march=native -mtune=native -O3 -fomit-frame-pointer -z noexecstack
NISTFLAGS += -Wno-unused-result -mavx2 -mbmi2 -mpopcnt \
  -march=native -mtune=native -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c fq.S shuffle.S ntt.S invntt.S \
  basemul.S consts.c rejsample.c fn.c verify.c
SOURCESKECCAK   = $(SOURCES) fips202.c fips202x4.c symmetric-shake.c \
  keccak4x/KeccakP-1600-times4-SIMD256.o
HEADERS = params.h align.h kem.h indcpa.h polyvec.h poly.h reduce.h fq.inc shuffle.inc \
  ntt.h consts.h rejsample.h fn.h verify.h symmetric.h randombytes.h
HEADERSKECCAK   = $(HEADERS) fips202.h fips202x4.h

.PHONY: all shared clean

all: \
  test/test_kaiburr4 \
  test/test_kaiburr6 \
  test/test_kaiburr8 \
  test/test_vectors4 \
  test/test_vectors6 \
  test/test_vectors8 \
  speed

speed: \
  test/test_speed4 \
  test/test_speed6 \
  test/test_speed8 \

shared: \
  libpqcrystals_kaiburr4_avx2.so \
  libpqcrystals_kaiburr6_avx2.so \
  libpqcrystals_kaiburr8_avx2.so \
  libpqcrystals_fips202_ref.so \
  libpqcrystals_fips202x4_avx2.so \

keccak4x/KeccakP-1600-times4-SIMD256.o: \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/KeccakP-SIMD256-config.h \
  keccak4x/KeccakP-align.h \
  keccak4x/KeccakP-brg_endian.h
	$(CC) $(CFLAGS) -c $< -o $@

libpqcrystals_fips202_ref.so: fips202.c fips202.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

libpqcrystals_fips202x4_avx2.so: fips202x4.c fips202x4.h \
  keccak4x/KeccakP-1600-times4-SIMD256.c \
  keccak4x/KeccakP-1600-times4-SnP.h \
  keccak4x/KeccakP-1600-unrolling.macros \
  keccak4x/KeccakP-SIMD256-config.h \
  keccak4x/KeccakP-align.h \
  keccak4x/KeccakP-brg_endian.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $< keccak4x/KeccakP-1600-times4-SIMD256.c

libpqcrystals_kaiburr4_avx2.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fpic $(CFLAGS) -DKYBER_K=7 $(SOURCES) \
	  symmetric-shake.c -o libpqcrystals_kaiburr4_avx2.so

libpqcrystals_kaiburr6_avx2.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fpic $(CFLAGS) -DKYBER_K=18 $(SOURCES) \
	  symmetric-shake.c -o libpqcrystals_kaiburr6_avx2.so

libpqcrystals_kaiburr8_avx2.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fpic $(CFLAGS) -DKYBER_K=24 $(SOURCES) \
	  symmetric-shake.c -o libpqcrystals_kaiburr8_avx2.so

test/test_kaiburr4: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=7 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o $@

test/test_kaiburr6: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=18 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o $@

test/test_kaiburr8: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_kyber.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=24 $(SOURCESKECCAK) randombytes.c test/test_kyber.c -o $@

test/test_vectors4: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_vectors.c
	$(CC) $(CFLAGS) -DKYBER_K=7 $(SOURCESKECCAK) test/test_vectors.c -o $@

test/test_vectors6: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_vectors.c
	$(CC) $(CFLAGS) -DKYBER_K=18 $(SOURCESKECCAK) test/test_vectors.c -o $@

test/test_vectors8: $(SOURCESKECCAK) $(HEADERSKECCAK) test/test_vectors.c
	$(CC) $(CFLAGS) -DKYBER_K=24 $(SOURCESKECCAK) test/test_vectors.c -o $@

test/test_speed4: $(SOURCESKECCAK) $(HEADERSKECCAK) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=7 $(SOURCESKECCAK) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

test/test_speed6: $(SOURCESKECCAK) $(HEADERSKECCAK) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=18 $(SOURCESKECCAK) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

test/test_speed8: $(SOURCESKECCAK) $(HEADERSKECCAK) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=24 $(SOURCESKECCAK) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@


clean:
	-$(RM) -rf *.o *.a *.so
	-$(RM) -rf test/test_kaiburr4
	-$(RM) -rf test/test_kaiburr6
	-$(RM) -rf test/test_kaiburr8
	-$(RM) -rf test/test_vectors4
	-$(RM) -rf test/test_vectors6
	-$(RM) -rf test/test_vectors8
	-$(RM) -rf test/test_speed4
	-$(RM) -rf test/test_speed6
	-$(RM) -rf test/test_speed8
	-$(RM) -rf keccak4x/KeccakP-1600-times4-SIMD256.o
