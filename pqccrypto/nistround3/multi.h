
#ifndef MULTI_H_
#define MULTI_H_
int falcon512_genkey(unsigned char *pk, unsigned char *sk, 
	unsigned char *seed);

int falcon512_sign(unsigned char *sm,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);

int falcon512_verify(const unsigned char *m, unsigned long long mlen,
	const unsigned char *sm, const unsigned char *pk);


int falcon1024_sign(unsigned char *sm,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *sk);

int falcon1024_verify(const unsigned char *m, unsigned long long mlen,
	const unsigned char *sm, const unsigned char *pk);

/// @brief 
/// @param m 
/// @param sm 
/// @param smlen 
/// @param pk 
/// @return 
int dilithium3_crypto_sign_verify(unsigned char *m, const unsigned char *sm, 
                       unsigned long long smlen, const unsigned char *pk);

/// @brief 
/// @param sm 
/// @param msg 
/// @param len 
/// @param sk 
/// @param random 
/// @return 
int dilithium3_crypto_sign_signature(unsigned char *sm, const unsigned char *msg, 
    unsigned long long len, const unsigned char *sk,
    unsigned char random);


/// @brief 
/// @param m 
/// @param sm 
/// @param smlen 
/// @param pk 
/// @return 
int dilithium5_crypto_sign_verify(unsigned char *m, const unsigned char *sm, 
                       unsigned long long smlen, const unsigned char *pk);

/// @brief 
/// @param sm 
/// @param msg 
/// @param len 
/// @param sk 
/// @param random 
/// @return 
int dilithium5_crypto_sign_signature(unsigned char *sm, const unsigned char *msg, 
    unsigned long long len, const unsigned char *sk,
    unsigned char random);

#endif