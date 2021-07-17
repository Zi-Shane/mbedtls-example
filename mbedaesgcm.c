#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/gcm.h"

unsigned char* hexstr_to_char(const char* hexstr, size_t* olen)
{
    size_t len = strlen(hexstr);
    if (len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
    *olen = final_len;
    unsigned char* chrs = (unsigned char*)malloc((final_len+1) * sizeof(*chrs));
    for (size_t i=0, j=0; j<final_len; i+=2, j++)
        chrs[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    chrs[final_len] = '\0';
    return chrs;
}

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    printf( "%s", title );
    for( i = 0; i < len; i++ )
        printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    printf( "\n" );
}

int aesgcm(int encrypt_mode, unsigned char* input, size_t input_len, unsigned char* output) {
    int ret = 1;

    size_t key_len;
    unsigned char* key = hexstr_to_char("4141414141414141414141", &key_len);
    size_t iv_len;
    unsigned char* iv = hexstr_to_char("41414141414141414141", &iv_len);
    size_t aad_len;
    unsigned char* aad = hexstr_to_char("41414141414141414141", &aad_len);
    

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init( &aes_ctx );

    mbedtls_gcm_setkey( &aes_ctx, MBEDTLS_CIPHER_ID_AES , key, key_len * 8 );

    switch ( encrypt_mode )
    {
    case MBEDTLS_GCM_ENCRYPT:
        mbedtls_gcm_starts( &aes_ctx, MBEDTLS_GCM_ENCRYPT, iv, iv_len, aad, aad_len );

        break;

    case MBEDTLS_GCM_DECRYPT:
        mbedtls_gcm_starts( &aes_ctx, MBEDTLS_GCM_DECRYPT, iv, iv_len, aad, aad_len );

        break;
    
    default:
        break;
    }

    mbedtls_gcm_update( &aes_ctx, input_len, input, output);

    mbedtls_gcm_free( &aes_ctx );

    return ret;
}

int aesgcm_encrypt_with_auth() {
    int ret = 1;

    size_t key_len;
    unsigned char* key = hexstr_to_char("000102030405060708090A0B0C0D0E0F", &key_len);
    size_t iv_len;
    unsigned char* iv = hexstr_to_char("4D4D4D0000BC614E01234567", &iv_len);
    size_t aad_len;
    unsigned char* aad = hexstr_to_char("30D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF", &aad_len);
    size_t input_len;
    unsigned char* input = hexstr_to_char("01011000112233445566778899AABBCCDDEEFF0000065F1F0400007E1F04B0", &input_len);
    unsigned char output[input_len];
    size_t tag_len = 12;
    unsigned char tag[tag_len];

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init( &aes_ctx );

    if( ( ret = mbedtls_gcm_setkey( &aes_ctx, MBEDTLS_CIPHER_ID_AES , key, key_len * 8 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_gcm_setkey returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    if( ( ret = mbedtls_gcm_crypt_and_tag( &aes_ctx, 
                                            MBEDTLS_GCM_ENCRYPT, 
                                            input_len, 
                                            iv, 
                                            iv_len, 
                                            aad, 
                                            aad_len, 
                                            input, 
                                            output, 
                                            tag_len, 
                                            tag ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_gcm_crypt_and_tag returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    

    dump_buf("  + output: ", output, input_len);
    dump_buf("  + tag: ", tag, tag_len);

    mbedtls_gcm_free( &aes_ctx );
    return ret;
}

int aesgcm_decrypt_with_auth() {
    int ret = 1;

    size_t key_len;
    unsigned char* key = hexstr_to_char("000102030405060708090A0B0C0D0E0F", &key_len);
    size_t iv_len;
    unsigned char* iv = hexstr_to_char("4D4D4D0000BC614E01234567", &iv_len);
    size_t aad_len;
    unsigned char* aad = hexstr_to_char("30D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF", &aad_len);
    size_t input_len;
    unsigned char* input = hexstr_to_char("801302ff8a7874133d414ced25b42534d28db0047720606b175bd52211be68", &input_len);
    size_t tag_len;
    unsigned char* tag = hexstr_to_char("41DB204D39EE6FDB8E356855", &tag_len);
    unsigned char output[input_len];

    mbedtls_gcm_context aes_ctx;
    mbedtls_gcm_init( &aes_ctx );

    if( ( ret = mbedtls_gcm_setkey( &aes_ctx, MBEDTLS_CIPHER_ID_AES , key, key_len * 8 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_gcm_setkey returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    if( ( ret = mbedtls_gcm_auth_decrypt( &aes_ctx, 
                                            input_len, 
                                            iv, 
                                            iv_len, 
                                            aad, 
                                            aad_len, 
                                            tag, 
                                            tag_len, 
                                            input, 
                                            output ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_gcm_auth_decrypt returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    dump_buf("  + output: ", output, input_len );

    mbedtls_gcm_free( &aes_ctx );

    return ret;
}

int main() {
    // size_t len;
    // unsigned char* plain_text = hexstr_to_char("41414141414141414141", &len);
    // unsigned char ciphered_text[len];
    // printf("  . Start  Only GCM - Encrypt mode\n");
    // aesgcm(MBEDTLS_GCM_ENCRYPT, plain_text, len, ciphered_text);
    // dump_buf("  + Input: ", plain_text, len);
    // dump_buf("  + Output: ", ciphered_text, len);
    // printf("  . OK\n\n");

    // aesgcm(MBEDTLS_GCM_DECRYPT, ciphered_text, len, plain_text);
    // printf("  . Start  Only GCM - Decrypt mode\n");
    // dump_buf("  + Input: ", ciphered_text, len);
    // dump_buf("  + Output: ", plain_text, len);
    // printf("  . OK\n\n");

    size_t key_len;
    unsigned char* key = hexstr_to_char("000102030405060708090A0B0C0D0E0F", &key_len);
    size_t iv_len;
    unsigned char* iv = hexstr_to_char("4D4D4D0000BC614E01234567", &iv_len);
    size_t aad_len;
    unsigned char* aad = hexstr_to_char("30D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF", &aad_len);
    size_t input_len;
    unsigned char* input = hexstr_to_char("801302ff8a7874133d414ced25b42534d28db0047720606b175bd52211be68", &input_len);
    unsigned char output[input_len];
    size_t tag_len;
    unsigned char* tag = hexstr_to_char("41DB204D39EE6FDB8E356855", &tag_len);

    printf("  . Start  Encrypt with Tag\n");
    aesgcm_encrypt_with_auth();
    printf("  . OK\n\n");

    printf("  . Start  Decrypt with Tag\n");
    if (aesgcm_decrypt_with_auth() != 0)
    {
        printf("  fail\n\n");
    }
    else
    {
        printf("  . OK\n\n");
    }

}
