#ifndef aes_h
#define aes_h
#include <stdlib.h>
#include <string>
#include <string.h>
#include <iostream>
//#include<cstring>
#include<vector>
//#include <unistd.h>
#include <openssl/aes.h>
// g++ aes.cpp -o aes -lssl -lcrypto
void my_AES_cbc_encrypt(unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void my_AES_cbc_decrypt(unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
unsigned long long AesEnc(unsigned int a, unsigned int b);
void AesDec(unsigned long long esk);
#endif