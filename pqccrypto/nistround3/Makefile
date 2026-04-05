CC ?= /usr/bin/cc
AR = ar
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wvla -Wpointer-arith -O3 -march=native -mtune=native
NISTFLAGS += -Wno-unused-result -O3
SOURCES = sign.c packing.c polyvec.c poly.c ntt.c reduce.c rounding.c
SRCDIR = ./dilithium/core

HEAD1 = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h  fips202.h

HEAD2 = $(wildcard $(SRCDIR)*.h)
HEAD3 = ../randombytes/randombytes.h  multi.h

SOURCE1 = ./build3/*.o
SOURCE2 = ./build5/*.o
SOURCE3 = ./build512/*.o 
SOURCE4 = ./build1024/*.o

HEADERS = config.h params.h api.h sign.h packing.h polyvec.h poly.h ntt.h \
  reduce.h rounding.h symmetric.h ../../../randombytes/randombytes.h 
KECCAK_SOURCES = $(SOURCES) fips202.c symmetric-shake.c
KECCAK_HEADERS = $(HEADERS) fips202.h
AES_SOURCES = $(SOURCES) fips202.c aes256ctr.c symmetric-aes.c
AES_HEADERS = $(HEADERS) fips202.h aes256ctr.h

OBJ2 =  build2/sign.o build2/packing.o build2/polyvec.o build2/poly.o build2/ntt.o \
	build2/reduce.o  build2/rounding.o build2/randombytes.o build2/symmetric-shake.o build2/fips202.o

OBJ3 = build3/dilithium3.o build3/sign.o build3/packing.o build3/polyvec.o build3/poly.o build3/ntt.o \
	build3/reduce.o  build3/rounding.o build3/randombytes.o build3/symmetric-shake.o build3/fips202.o

OBJ5 = build5/dilithium5.o build5/sign.o build5/packing.o build5/polyvec.o build5/poly.o build5/ntt.o \
	build5/reduce.o  build5/rounding.o build5/randombytes.o build5/symmetric-shake.o build5/fips202.o


.PHONY:  all speed shared  clean


all: PQCgenKAT_sign

speed: \
  test/test_mul \
  test/test_speed2 \
  test/test_speed3 \
  test/test_speed5 \
  test/test_speed2aes \
  test/test_speed3aes \
  test/test_speed5aes

shared: \
  build/libpqcrystals_dilithium2_ref.so \
  build/libpqcrystals_dilithium3_ref.so \
  build/libpqcrystals_dilithium5_ref.so \
  build/libpqcrystals_fips202_ref.so \
  #libpqcrystals_dilithium2aes_ref.so \
  #libpqcrystals_dilithium3aes_ref.so \
  #libpqcrystals_dilithium5aes_ref.so \

  #libpqcrystals_aes256ctr_ref.so

static: \
  build2/libpqcrystals_dilithium2_ref.a \
  build3/libpqcrystals_dilithium3_ref.a \
  build5/libpqcrystals_dilithium5_ref.a \

build/libpqcrystals_fips202_ref.so: fips202.c fips202.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

libpqcrystals_aes256ctr_ref.so: aes256ctr.c aes256ctr.h
	$(CC) -shared -fPIC $(CFLAGS) -o $@ $<

build/libpqcrystals_dilithium2_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $(SOURCES) symmetric-shake.c ../../../randombytes/randombytes.c

build/libpqcrystals_dilithium3_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $(SOURCES) symmetric-shake.c ../../../randombytes/randombytes.c

build/libpqcrystals_dilithium5_ref.so: $(SOURCES) $(HEADERS) symmetric-shake.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $(SOURCES) symmetric-shake.c ../../../randombytes/randombytes.c

libpqcrystals_dilithium2aes_ref.so: $(SOURCES) $(HEADERS) symmetric-aes.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES) symmetric-aes.c

libpqcrystals_dilithium3aes_ref.so: $(SOURCES) $(HEADERS) symmetric-aes.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES) symmetric-aes.c

libpqcrystals_dilithium5aes_ref.so: $(SOURCES) $(HEADERS) symmetric-aes.c
	$(CC) -shared -fPIC $(CFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	   -o $@ $(SOURCES) symmetric-aes.c

build2/libpqcrystals_dilithium2_ref.a: $(OBJ2) $(HEADERS) 
	$(AR) rcs -o $@ $(OBJ2) 

build3/libpqcrystals_dilithium3_ref.a: $(OBJ3) $(HEAD2) $(HEAD3) 
	$(AR) rcs -o $@ $(OBJ3) 

build5/libpqcrystals_dilithium5_ref.a:  $(OBJ5) $(HEAD3) $(HEAD2)
	$(AR) rcs -o $@ $(OBJ5) 

#-----------------------DDILITHIUM_MODE=2------------------------|
build2/sign.o: sign.c $(SRCDIR)/$(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ sign.c

build2/packing.o: $(SRCDIR)/packing.c $(SRCDIR)/$(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 $< -o $@ 

build2/polyvec.o: $(SRCDIR)/polyvec.c $(SRCDIR)/$(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ polyvec.c

build2/poly.o: $(SRCDIR)/poly.c $(SRCDIR)/$(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ poly.c

build2/ntt.o: $(SRCDIR)/ntt.c $(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ ntt.c

build2/reduce.o: $(SRCDIR)/reduce.c $(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ reduce.c

build2/rounding.o: rounding.c $(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ rounding.c

build2/fips202.o: fips202.c $(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ fips202.c

build2/symmetric-shake.o: symmetric-shake.c $(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ symmetric-shake.c

build2/randombytes.o: ../../../randombytes/randombytes.c $(HEAD1)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=2 -DDILITHIUM_PREFIX=pqcrystals_dilithium2 -o $@ ../../../randombytes/randombytes.c

#-----------------------DDILITHIUM_MODE=3------------------------|
build3/dilithium3.o: dilithium3.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/sign.o: $(SRCDIR)/sign.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/packing.o: $(SRCDIR)/packing.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/polyvec.o: $(SRCDIR)/polyvec.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/poly.o: $(SRCDIR)/poly.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/ntt.o: $(SRCDIR)/ntt.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/reduce.o: $(SRCDIR)/reduce.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/rounding.o: $(SRCDIR)/rounding.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/fips202.o: $(SRCDIR)/fips202.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/symmetric-shake.o: $(SRCDIR)/symmetric-shake.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 

build3/randombytes.o: ../randombytes/randombytes.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=3 -DDILITHIUM_PREFIX=pqcrystals_dilithium3 $< -o $@ 
#-----------------------DDILITHIUM_MODE=5------------------------|
build5/dilithium5.o: dilithium5.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/sign.o: $(SRCDIR)/sign.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/packing.o: $(SRCDIR)/packing.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/polyvec.o: $(SRCDIR)/polyvec.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/poly.o: $(SRCDIR)/poly.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/ntt.o: $(SRCDIR)/ntt.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/reduce.o: $(SRCDIR)/reduce.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/rounding.o: $(SRCDIR)/rounding.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/fips202.o: $(SRCDIR)/fips202.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/symmetric-shake.o: $(SRCDIR)/symmetric-shake.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 

build5/randombytes.o: ../randombytes/randombytes.c $(HEAD3) $(HEAD2)
	$(CC) $(CFLAGS) -c -DDILITHIUM_MODE=5 -DDILITHIUM_PREFIX=pqcrystals_dilithium5 $< -o $@ 
	
test/test_dilithium2: test/test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< randombytes.c $(KECCAK_SOURCES)

test/test_dilithium3: test/test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< randombytes.c $(KECCAK_SOURCES)

test/test_dilithium5: test/test_dilithium.c randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< randombytes.c $(KECCAK_SOURCES)

test/test_dilithium2aes: test/test_dilithium.c randombytes.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< randombytes.c $(AES_SOURCES)

test/test_dilithium3aes: test/test_dilithium.c randombytes.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< randombytes.c $(AES_SOURCES)

test/test_dilithium5aes: test/test_dilithium.c randombytes.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< randombytes.c $(AES_SOURCES)

test/test_vectors2: test/test_vectors.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< $(KECCAK_SOURCES)

test/test_vectors3: test/test_vectors.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< $(KECCAK_SOURCES)

test/test_vectors5: test/test_vectors.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< $(KECCAK_SOURCES)

test/test_vectors2aes: test/test_vectors.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< $(AES_SOURCES)

test/test_vectors3aes: test/test_vectors.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< $(AES_SOURCES)

test/test_vectors5aes: test/test_vectors.c $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< $(AES_SOURCES)

test/test_speed2: test/test_speed.c test/speed_print.c test/speed_print.h \
  test/cpucycles.c test/cpucycles.h randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< test/speed_print.c test/cpucycles.c randombytes.c \
	  $(KECCAK_SOURCES)

test/test_speed3: test/test_speed.c test/speed_print.c test/speed_print.h \
  test/cpucycles.c test/cpucycles.h randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< test/speed_print.c test/cpucycles.c randombytes.c \
	  $(KECCAK_SOURCES)

test/test_speed5: test/test_speed.c test/speed_print.c test/speed_print.h \
  test/cpucycles.c test/cpucycles.h randombytes.c $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< test/speed_print.c test/cpucycles.c randombytes.c \
	  $(KECCAK_SOURCES)

test/test_speed2aes: test/test_speed.c test/speed_print.c test/speed_print.h \
  test/cpucycles.c test/cpucycles.h randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< test/speed_print.c test/cpucycles.c randombytes.c \
	  $(AES_SOURCES)

test/test_speed3aes: test/test_speed.c test/speed_print.c test/speed_print.h \
  test/cpucycles.c test/cpucycles.h randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< test/speed_print.c test/cpucycles.c randombytes.c \
	  $(AES_SOURCES)

test/test_speed5aes: test/test_speed.c test/speed_print.c test/speed_print.h \
  test/cpucycles.c test/cpucycles.h randombytes.c $(AES_SOURCES) $(AES_HEADERS)
	$(CC) $(CFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< test/speed_print.c test/cpucycles.c randombytes.c \
	  $(AES_SOURCES)

test/test_mul: test/test_mul.c randombytes.c $(KECCAK_SOURCES) $(KECCAK_HEADERS)
	$(CC) $(CFLAGS) -UDBENCH -o $@ $< randombytes.c $(KECCAK_SOURCES)

PQCgenKAT_sign: PQCgenKAT_sign.c rng.c rng.h $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(NISTFLAGS) -o $@ $< rng.c $(KECCAK_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign2: PQCgenKAT_sign.c rng.c rng.h $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=2 \
	  -o $@ $< rng.c $(KECCAK_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign3: PQCgenKAT_sign.c rng.c rng.h $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=3 \
	  -o $@ $< rng.c $(KECCAK_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign5: PQCgenKAT_sign.c rng.c rng.h $(KECCAK_SOURCES) \
  $(KECCAK_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=5 \
	  -o $@ $< rng.c $(KECCAK_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign2aes: PQCgenKAT_sign.c rng.c rng.h $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=2 -DDILITHIUM_USE_AES \
	  -o $@ $< rng.c $(AES_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign3aes: PQCgenKAT_sign.c rng.c rng.h $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=3 -DDILITHIUM_USE_AES \
	  -o $@ $< rng.c $(AES_SOURCES) $(LDFLAGS) -lcrypto

PQCgenKAT_sign5aes: PQCgenKAT_sign.c rng.c rng.h $(AES_SOURCES) \
  $(AES_HEADERS)
	$(CC) $(NISTFLAGS) -DDILITHIUM_MODE=5 -DDILITHIUM_USE_AES \
	  -o $@ $< rng.c $(AES_SOURCES) $(LDFLAGS) -lcrypto

cleandili:
	# rm -f *~ test/*~ *.gcno *.gcda *.lcov
	# rm -f libpqcrystals_dilithium2_ref.so
	# rm -f libpqcrystals_dilithium3_ref.so
	# rm -f libpqcrystals_dilithium5_ref.so
	# rm -f libpqcrystals_dilithium2aes_ref.so
	# rm -f libpqcrystals_dilithium3aes_ref.so
	# rm -f libpqcrystals_dilithium5aes_ref.so
	# rm -f libpqcrystals_fips202_ref.so
	# rm -f libpqcrystals_aes256ctr_ref.so
	# rm -f test/test_dilithium2
	# rm -f test/test_dilithium3
	# rm -f test/test_dilithium5
	# rm -f test/test_dilithium2aes
	# rm -f test/test_dilithium3aes
	# rm -f test/test_dilithium5aes
	# rm -f test/test_vectors2
	# rm -f test/test_vectors3
	# rm -f test/test_vectors5
	# rm -f test/test_vectors2aes
	# rm -f test/test_vectors3aes
	# rm -f test/test_vectors5aes
	# rm -f test/test_speed2
	# rm -f test/test_speed3
	# rm -f test/test_speed5
	# rm -f test/test_speed2aes
	# rm -f test/test_speed3aes
	# rm -f test/test_speed5aes
	# rm -f test/test_mul
	# rm -f PQCgenKAT_sign2
	# rm -f PQCgenKAT_sign3
	# rm -f PQCgenKAT_sign5
	# rm -f PQCgenKAT_sign2aes
	# rm -f PQCgenKAT_sign3aes
	# rm -f PQCgenKAT_sign5aes
	rm -f build2/libpqcrystals_dilithium2_ref.a
	rm -f build2/*.o
	rm -f build3/libpqcrystals_dilithium3_ref.a
	rm -f build3/*.o
	rm -f build5/libpqcrystals_dilithium5_ref.a
	rm -f build5/*.o

#--------------------------------------falcon512------------------------------
FLCON_CC = c99
FALCON_CFLAGS = -W -Wall -O2
LD = c99
# AR = ar
ARFLAGS = rcs

FALCON512_HEAD1 = multi.h ./falcon/falcon512/falconCore/api.h ./falcon/falcon512/falconCore/fpr.h ./falcon/falcon512/falconCore/inner.h ../randombytes/randombytes.h
# FALCON512_HEAD2 = ./falcon/falcon512/falconCore/api.h ../KAT/generator/katrng.h

FALCON512_OBJ1 = build512/falcon512.o build512/api.o build512/codec.o build512/common.o build512/fft.o build512/fpr.o build512/keygen.o  build512/rng.o build512/shake.o build512/sign.o build512/vrfy.o build512/randombytes.o

build512/kat512int.a: $(FALCON512_OBJ1) 
	$(AR) $(ARFLAGS) build512/librstflc512int.a $(FALCON512_OBJ1) 

build512/falcon512.o: falcon512.c $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/falcon512.o falcon512.c

build512/api.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/api.o ./falcon/falcon512/falconCore/api.c

build512/codec.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/codec.o ./falcon/falcon512/falconCore/codec.c

build512/common.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/common.o ./falcon/falcon512/falconCore/common.c

build512/fft.o:  $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/fft.o ./falcon/falcon512/falconCore/fft.c

build512/fpr.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/fpr.o ./falcon/falcon512/falconCore/fpr.c

build512/keygen.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/keygen.o ./falcon/falcon512/falconCore/keygen.c

build512/rng.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/rng.o ./falcon/falcon512/falconCore/rng.c

build512/shake.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/shake.o ./falcon/falcon512/falconCore/shake.c

build512/sign.o: $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/sign.o ./falcon/falcon512/falconCore/sign.c

build512/vrfy.o:  $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner512 -o build512/vrfy.o ./falcon/falcon512/falconCore/vrfy.c

build512/randombytes.o:  ../randombytes/randombytes.c $(FALCON512_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -o build512/randombytes.o ../randombytes/randombytes.c

clean512:
	rm -f build512/*.o
	rm -f build512/*.a

#-----------------------------------------------------falcon1024-----------------------------------------#

FALCON1024_HEAD1 = multi.h ./falcon/falcon1024/falconCore/api.h ./falcon/falcon1024/falconCore/fpr.h ./falcon/falcon1024/falconCore/inner.h ../randombytes/randombytes.h
# FALCON512_HEAD2 = ./falcon/falcon1024/falconCore/api.h ../KAT/generator/katrng.h

FALCON1024_OBJ1 = build1024/falcon1024.o build1024/api.o build1024/codec.o build1024/common.o build1024/fft.o build1024/fpr.o build1024/keygen.o  build1024/rng.o build1024/shake.o build1024/sign.o build1024/vrfy.o build1024/randombytes.o

build1024/kat1024int.a: $(FALCON1024_OBJ1) 
	$(AR) $(ARFLAGS) build1024/librstflc1024int.a $(FALCON1024_OBJ1) 

build1024/falcon1024.o: falcon1024.c $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/falcon1024.o falcon1024.c

build1024/api.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/api.o ./falcon/falcon1024/falconCore/api.c

build1024/codec.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/codec.o ./falcon/falcon1024/falconCore/codec.c

build1024/common.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/common.o ./falcon/falcon1024/falconCore/common.c

build1024/fft.o:  $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/fft.o ./falcon/falcon1024/falconCore/fft.c

build1024/fpr.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/fpr.o ./falcon/falcon1024/falconCore/fpr.c

build1024/keygen.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/keygen.o ./falcon/falcon1024/falconCore/keygen.c

build1024/rng.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/rng.o ./falcon/falcon1024/falconCore/rng.c

build1024/shake.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/shake.o ./falcon/falcon1024/falconCore/shake.c

build1024/sign.o: $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/sign.o ./falcon/falcon1024/falconCore/sign.c

build1024/vrfy.o:  $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -DFALCON_PREFIX=falcon_inner1024 -o build1024/vrfy.o ./falcon/falcon1024/falconCore/vrfy.c

build1024/randombytes.o:  ../randombytes/randombytes.c $(FALCON1024_HEAD1)
	$(FLCON_CC) $(FALCON_CFLAGS) -c -o build1024/randombytes.o ../randombytes/randombytes.c

clean1024:
	rm -f build1024/*.o
	rm -f build1024/*.a


build/libmultipqcsig.a:$(FALCON512_OBJ1) $(FALCON1024_OBJ1) $(OBJ3) $(OBJ5) $(SOURCE1) $(SOURCE2) $(SOURCE3) $(SOURCE4) 
	$(AR) rcs -o $@ $(SOURCE1) $(SOURCE2) $(SOURCE3) $(SOURCE4) 