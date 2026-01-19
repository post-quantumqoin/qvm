extern "C" {
    pub fn falcon512_verify(
        m: *const u8,  
        mlen: i32, 
        sm: *const u8, 
        pk: *const u8
    )-> i32;

    pub fn falcon1024_verify(
        m: *const u8,  
        mlen: i32, 
        sm: *const u8, 
        pk: *const u8
    )-> i32;

    pub fn dilithium3_crypto_sign_verify(
        m: *const u8, 
        sm: *const u8, 
        mlen: i32,  
        pk: *const u8
    )-> i32;

    pub fn dilithium5_crypto_sign_verify(
        m: *const u8, 
        sm: *const u8, 
        mlen: i32,  
        pk: *const u8
    )-> i32;
}