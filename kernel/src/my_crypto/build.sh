#!/usr/bin/env bash

#SSEFLAGS="-mno-sse -mno-sse2 -mno-avx -fno-tree-vectorize"
SSEFLAGS="-march=native -O3"

gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -fPIC -mrdrnd \
	 -c my_crypto.c  
gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Curve25519_51.c
gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Hash_SHA3.c

gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_NaCl.c
gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Salsa20.c
gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_MAC_Poly1305.c

# for report signing
gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Ed25519.c
gcc $SSEFLAGS -nostdlib -Ihacl/karamel/ -Ihacl/karamel/krmllib/dist/minimal -Ihacl/karamel/include/ -Ihacl/include -fPIC \
	-c hacl/Hacl_Hash_SHA2.c # required by Hacl_Ed25519.c

ar rcs libmy_crypto.a Hacl_Curve25519_51.o Hacl_NaCl.o Hacl_Hash_SHA3.o Hacl_Salsa20.o Hacl_MAC_Poly1305.o Hacl_Ed25519.o Hacl_Hash_SHA2.o my_crypto.o
mkdir -p ../../../libmy_crypto/
cp libmy_crypto.a ../../../libmy_crypto/libmy_crypto.a 
cp my_crypto.h ../../../../module/include/
cp libmy_crypto.a ../../../../module/include/
