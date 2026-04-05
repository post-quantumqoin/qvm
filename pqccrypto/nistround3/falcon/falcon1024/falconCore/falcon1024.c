#include "api.h"

int falcon1024_sign(unsigned char *sm,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk) {
    return falcon_sign(sm,m,mlen,sk);
    
}

int falcon1024_verify(const unsigned char *m, unsigned long long mlen,
	const unsigned char *sm, const unsigned char *pk) {
    return verify_sign(m,mlen,sm,pk);
    
}