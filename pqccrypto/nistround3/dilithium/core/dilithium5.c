#include "api.h"
/// @brief 
/// @param m 
/// @param sm 
/// @param smlen 
/// @param pk 
/// @return 
int dilithium5_crypto_sign_verify(unsigned char *m, const unsigned char *sm, 
        unsigned long long smlen, const unsigned char *pk){
        return crypto_sign_verify(m,sm,smlen,pk);
    }

/// @brief 
/// @param sm 
/// @param msg 
/// @param len 
/// @param sk 
/// @param random 
/// @return 
int dilithium5_crypto_sign_signature(unsigned char *sm, const unsigned char *msg, 
        unsigned long long len, const unsigned char *sk,
        unsigned char random){
        return    crypto_sign_signature(sm,msg, len, sk,random);

    }