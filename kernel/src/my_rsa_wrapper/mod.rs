extern "C" {
    /************************************************
     * Return number of bytes for RSA key
     * or 0 if the RSA keys have not been initialized 
     * *********************************************/
    pub fn get_RSA_size() -> u32;
    pub fn gen_RSA_keys(n: u32) -> u32;    
    pub fn RSA_encrypt(flen: u32, from: *mut u8, to: *mut u8) -> u32;
    pub fn RSA_decrypt(flen: u32, from: *mut u8, to: *mut u8) -> u32;
}
