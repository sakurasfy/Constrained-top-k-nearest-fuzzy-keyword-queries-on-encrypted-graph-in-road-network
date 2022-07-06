#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <iostream>
//#include<cstring>
#include<vector>
//#include <unistd.h>
#include <openssl/aes.h>
//4039 88234

using namespace std;

// g++ aes.cpp -o aes -lssl -lcrypto
void my_AES_cbc_encrypt(unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
void my_AES_cbc_decrypt(unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec);
unsigned long long AesEnc(unsigned int a, unsigned int b);
void AesDec(unsigned long long esk);
void AesDec(unsigned long long esk){
    //printf("Start AesDec...\n");
    AES_KEY de_key;

    char str_w[20];
    char str_d[20];
    char str[20];

    // pair_wd tmp_wd;
    
    // strncpy(str_w, (char *)encrypt_result, 8);

    unsigned int ret_w;
    unsigned int ret_d;

    sprintf(str, "%.16llx", esk);

    size_t len = (size_t) strlen(str);
    printf("esk strlen: %d\n", (int)len);

    size_t length = ((len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组
    printf("esk length: %d\n", (int)length);

    unsigned char userkey[AES_BLOCK_SIZE+1]="H=bsJS+nda5d9kJD";
    unsigned char *iv1 = (unsigned char *)malloc(AES_BLOCK_SIZE);

    unsigned char *decrypt_result = (unsigned char *)malloc(length);

    //memset((unsigned char*)userkey,'k',AES_BLOCK_SIZE);
    memset((unsigned char*)iv1,'m',AES_BLOCK_SIZE);
    memset((unsigned char*)decrypt_result, 0, length);

    AES_set_decrypt_key((const unsigned char *)userkey, AES_BLOCK_SIZE*8, &de_key);

    my_AES_cbc_decrypt((unsigned char*)str, decrypt_result, len, &de_key, iv1);

    strncpy(str_w, (char *)decrypt_result, 8);
    strncpy(str_d, (char *)decrypt_result+8, 8);
    str_w[8] = '\0';
    str_d[8] = '\0';

    sscanf(str_w, "%x", &ret_w);
    sscanf(str_d, "%x", &ret_d);

    // tmp_wd.w.push_back(ret_w);
    // tmp_wd.d.push_back(ret_d);
    printf("aesDEc: w:%.8x, d:%.8x\n", ret_w, ret_d);
    //printf("AesDec done!...\n");

    // return tmp_wd;
}

unsigned long long AesEnc(unsigned int a, unsigned int b){
    AES_KEY en_key;
    AES_KEY de_key;

    char str_a[20];
    char str_b[20];
    char str[20];

    unsigned int ret_a;
    unsigned int ret_b;

    unsigned long long ret;

    sprintf(str_a, "%.8x", a);
    //-----
    printf("str a:%s\n", str_a);

    sprintf(str_b, "%.8x", b);
    //-----
    printf("str b:%s\n", str_b);

    // strcat
    strcpy(str, str_a);
    strcat(str, str_b);
    //-----
    printf("原始数据 AesEnc：%s\n", str);

    size_t len = (size_t) strlen(str);
    //-----
    printf("明文长度 AesEnc：%d\n",(int)len);
    size_t length = ((len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;    //对齐分组

    unsigned char userkey[AES_BLOCK_SIZE+1]="H=bsJS+nda5d9kJD";
    unsigned char *iv1 = (unsigned char *)malloc(AES_BLOCK_SIZE);
    unsigned char *iv2 = (unsigned char *)malloc(AES_BLOCK_SIZE);

    unsigned char *encrypt_result = (unsigned char *)malloc(length);
    unsigned char *decrypt_result = (unsigned char *)malloc(length);

    

    //memset((unsigned char*)userkey,'k',AES_BLOCK_SIZE);
    memset((unsigned char*)iv1,'m',AES_BLOCK_SIZE);
    memset((unsigned char*)iv2,'m',AES_BLOCK_SIZE);
    memset((unsigned char*)encrypt_result, 0, length);
    memset((unsigned char*)decrypt_result, 0, length);

    AES_set_encrypt_key((const unsigned char *)userkey, AES_BLOCK_SIZE*8, &en_key);
    //-----
    printf("加密密钥 AesEnc：%s\n", userkey);

    my_AES_cbc_encrypt((unsigned char*)str, encrypt_result, len, &en_key, iv1);


    //-----
    printf("加密结果 AesEnc:%s\n", encrypt_result);
    for(int i=0; i<length; i++){
        printf("%.2x ",encrypt_result[i]);
    }
    putchar('\n');

    strncpy(str_a, (char *)encrypt_result, 8);
    strncpy(str_b, (char *)encrypt_result+8, 8);
    str_a[8] = '\0';
    str_b[8] = '\0';

    // printf("strlen a :%d\n", strlen(tmp_a));
    // printf("strlen b :%d\n", strlen(tmp_b));

    //-----
    printf("AesEnc...tmp_a str: %s...\n", str_a);
    printf("AesEnc...tmp_b str: %s...\n", str_b);

    sscanf(str_a, "%x", &ret_a);
    sscanf(str_b, "%x", &ret_b);

    //-----
    printf("AesEnc ret_a hex: %x\n", ret_a);
    printf("AesEnc ret_b hex: %x\n", ret_b);

    ret = ret_a;
    ret <<= 32;
    ret += ret_b;
    printf("AesEnc ret hex     : %llx\n", ret);

    return ret;
}


void my_AES_cbc_encrypt(unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec)
{
    size_t n;
    const unsigned char *iv = ivec;

    if (len == 0){
      return;
    }
    while (len) {
        for (n = 0; n < 16 && n < len; ++n)
            out[n] = in[n] ^ iv[n];
        for (; n < 16; ++n)// 填充
            out[n] = iv[n];// 解密时与本身异或，全为0
        AES_encrypt(out, out, key);
        iv = out;
        if (len <= 16)
            break;
        len -= 16;
        in += 16;
        out += 16;
    }
}

void my_AES_cbc_decrypt(unsigned char *in, unsigned char *out,
                           size_t len, const AES_KEY *key,
                           unsigned char *ivec)
{
    size_t n;
    unsigned char tmp[16];

    if (len == 0){
      return;
    }
    while (len) {
        unsigned char c;
        AES_decrypt(in, tmp, key);
        for (n = 0; n < 16 && n < len; ++n) {
            c = in[n];
            out[n] = tmp[n] ^ ivec[n];
            ivec[n] = c;
        }
        if (len <= 16) {
            for (; n < 16; ++n)
                ivec[n] = in[n];
            break;
        }
        len -= 16;
        in += 16;
        out += 16;
    }
}
