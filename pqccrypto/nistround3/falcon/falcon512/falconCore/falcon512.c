#include "api.h"

int falcon512_genkey(unsigned char *pk, unsigned char *sk, 
	unsigned char *seed){
        return falcon_genkey(pk,sk,seed);
    }
    
int falcon512_sign(unsigned char *sm,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk) {
        return falcon_sign(sm,m,mlen,sk);
}

int falcon512_verify(const unsigned char *m, unsigned long long mlen,
	const unsigned char *sm, const unsigned char *pk) {
        return verify_sign(m,mlen,sm,pk);
}