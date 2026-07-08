CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -z noexecstack
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c ntt.c fn.c reduce.c verify.c
SOURCESKECCAK = $(SOURCES) fips202.c symmetric-shake.c
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h fn.h reduce.h verify.h symmetric.h
HEADERSKECCAK = $(HEADERS) fips202.h

.PHONY: all speed shared clean

all: test speed shared

test: \
  test/test_kaiburr4 \
  test/test_kaiburr6 \
  test/test_kaiburr8 \
  test/test_vectors4 \
  test/test_vectors6 \
  test/test_vectors8 \

speed: \
  test/test_speed4 \
  test/test_speed6 \
  test/test_speed8 \

shared: \
  lib/libpqcrystals_kaiburr4_ref.so \
  lib/libpqcrystals_kaiburr6_ref.so \
  lib/libpqcrystals_kaiburr8_ref.so \
  lib/libpqcrystals_fips202_ref.so \


lib/libpqcrystals_fips202_ref.so: fips202.c fips202.h
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) fips202.c -o $@

lib/libpqcrystals_kaiburr4_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=7 $(SOURCES) symmetric-shake.c -o $@

lib/libpqcrystals_kaiburr6_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=18 $(SOURCES) symmetric-shake.c -o $@

lib/libpqcrystals_kaiburr8_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=24 $(SOURCES) symmetric-shake.c -o $@

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
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test/test_kaiburr4
	-$(RM) -f test/test_kaiburr6
	-$(RM) -f test/test_kaiburr8
	-$(RM) -f test/test_vectors4
	-$(RM) -f test/test_vectors6
	-$(RM) -f test/test_vectors8
	-$(RM) -f test/test_speed4
	-$(RM) -f test/test_speed6
	-$(RM) -f test/test_speed8
	-$(RM) -rf lib/
