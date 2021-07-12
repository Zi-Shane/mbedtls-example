#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"

unsigned char* hexstr_to_char(const char* hexstr)
{
    size_t len = strlen(hexstr);
    if (len % 2 != 0)
        return NULL;
    size_t final_len = len / 2;
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

static void dump_pubkey( const char *title, mbedtls_ecdsa_context *key )
{
    unsigned char buf[300];
    size_t len;

    if( mbedtls_ecp_point_write_binary( &key->grp, &key->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &len, buf, sizeof buf ) != 0 )
    {
        printf("internal error\n");
        return;
    }

    dump_buf( title, buf, len );
}

int sign() {
    int ret = 1;
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    const char *pers = "ecdsa";
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
    }

    mbedtls_ecdsa_context ecdsaprikey;
    mbedtls_ecdsa_init(&ecdsaprikey);

    mbedtls_mpi_read_string(&ecdsaprikey.d, 16, "CE69EFE1E68415AD5B9F4C8B2F3025CB1332DDBD881073309A53A526FD3D7DBD");
    if( ( ret = mbedtls_ecp_group_load( &ecdsaprikey.grp, MBEDTLS_ECP_DP_SECP256R1 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecp_group_load returned -0x%04x\n", (unsigned int) -ret );
    }

    char text[] = "43545430303030304142434445464748073B0F45272556735A0A6663635F6853C7EDE9CA4154E6DEA172512FC1CCC8BAC0B883067C45160DAA12BF78DACD1838016F888F798BDD0D7826D0";
    unsigned char hashbyte[32];
    unsigned char *textbyte = hexstr_to_char(text);

    if( ( ret = mbedtls_sha256_ret( (unsigned char *) textbyte, 75, hashbyte , 0) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_sha256_ret returned -0x%04x\n", (unsigned int) -ret );
    }

    dump_buf( "  + Hash: ", hashbyte, sizeof(hashbyte) );

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    /*
     * Computes the ECDSA signature
     * Deterministic version
     */
    // if( ( ret = mbedtls_ecdsa_sign_det( &ecdsaprikey.grp, &r, &s, &ecdsaprikey.d, hashbyte, sizeof(hashbyte), MBEDTLS_MD_SHA256 ) ) != 0 )
    // {
    //     printf( " failed\n  ! mbedtls_ecdsa_sign_det returned -0x%04x\n", (unsigned int) -ret );
    // }

    /*
     * Computes the ECDSA signature
     * with Random Number Generator version
     */
    if( ( ret = mbedtls_ecdsa_sign( &ecdsaprikey.grp, &r, &s, &ecdsaprikey.d, hashbyte, sizeof(hashbyte), mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecdsa_sign returned -0x%04x\n", (unsigned int) -ret );
    }

    // char tmp[1000];
    // size_t olen;
    // mbedtls_mpi_write_string(&r, 16, tmp, sizeof(tmp), &olen);
    // printf("  + R: %s\n", tmp);
    // mbedtls_mpi_write_string(&s, 16, tmp, sizeof(tmp), &olen);
    // printf("  + S: %s\n", tmp);

    unsigned char signature_byte_r[32];
    unsigned char signature_byte_s[32];
    if (mbedtls_mpi_write_binary(&r, signature_byte_r, 32) != 0)
    {
        printf( " failed\n  ! mbedtls_mpi_write_binary returned -0x%04x\n", (unsigned int) -ret );
    }
    if (mbedtls_mpi_write_binary(&s, signature_byte_s, 32) != 0)
    {
        printf( " failed\n  ! mbedtls_mpi_write_binary returned -0x%04x\n", (unsigned int) -ret );
    }
    
    dump_buf("  + R: ", signature_byte_r, 32);
    dump_buf("  + S: ", signature_byte_s, 32);

    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_ecdsa_free( &ecdsaprikey );
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

int verify() {
    int ret = 1;

    mbedtls_ecdsa_context ecdsapubkey;
    mbedtls_ecdsa_init(&ecdsapubkey);

    if( ( ret = mbedtls_ecp_point_read_string( &ecdsapubkey.Q, 16, "bc316842562ab04ca987f39fbc5368899a0f2d6059e1247b68d3dc4f26c75669", "f808c6bb115b3b43e7f3a23d3e5f4bb3628183615a5604e1e603c9563bb24942" ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecp_point_read_string returned -0x%04x\n", (unsigned int) -ret );
    }

    if( ( ret = mbedtls_ecp_group_load( &ecdsapubkey.grp, MBEDTLS_ECP_DP_SECP256R1 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecp_group_load returned -0x%04x\n", (unsigned int) -ret );
    }

    dump_pubkey("  + Public key: ", &ecdsapubkey);

    char text[] = "43545430303030304142434445464748073B0F45272556735A0A6663635F6853C7EDE9CA4154E6DEA172512FC1CCC8BAC0B883067C45160DAA12BF78DACD1838016F888F798BDD0D7826D0";
    unsigned char hashbyte[32];

    unsigned char *textbyte = hexstr_to_char(text);


    if( ( ret = mbedtls_sha256_ret( (unsigned char *) textbyte, 75, hashbyte , 0) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_sha256_ret returned -0x%04x\n", (unsigned int) -ret );
    }

    dump_buf( "  + Hash: ", hashbyte, sizeof( hashbyte ) );

    char r_string[] = "DECE52910E62F5696082481FC22F60E29DD4E09B28CCF8D8FFCCAFE6C7699231";
    char s_string[] = "893946FD46D67053DEB4EB046DE3EE8A5308D9C3CDEA89B49406FE8B14F51D2F";
    unsigned char *r_byte = hexstr_to_char(r_string);
    unsigned char *s_byte = hexstr_to_char(s_string);
    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    // mbedtls_mpi_read_string(&r, 16, "DECE52910E62F5696082481FC22F60E29DD4E09B28CCF8D8FFCCAFE6C7699231");
    mbedtls_mpi_read_binary(&r, r_byte, 32);
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    // mbedtls_mpi_read_string(&s, 16, "893946FD46D67053DEB4EB046DE3EE8A5308D9C3CDEA89B49406FE8B14F51D2F");
    mbedtls_mpi_read_binary(&s, s_byte, 32);
    if( ( ret = mbedtls_ecdsa_verify(&ecdsapubkey.grp, hashbyte, 32, &ecdsapubkey.Q, &r, &s) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecdsa_read_signature returned -0x%04x\n", (unsigned int) -ret );
    }

    if (!ret)
        printf( "\n  . OK (the signature is valid)\n\n" );

    mbedtls_ecdsa_free(&ecdsapubkey);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

int main() {
    sign();
    verify();
}
