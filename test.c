#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
//     mbedtls_pk_context pk;
//     mbedtls_pk_init( &pk );
//     const unsigned char* mykey = "-----BEGIN PRIVATE KEY-----\n"\
// "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgzmnv4eaEFa1bn0yLLzAlyxMy3b2IEHMwmlOlJv09fb2hRANCAAS8MWhCViqwTKmH85+8U2iJmg8tYFnhJHto09xPJsdWafgIxrsRWztD5/OiPT5fS7NigYNhWlYE4eYDyVY7sklC\n"\
// "-----END PRIVATE KEY-----";

//     if( ( ret = mbedtls_pk_parse_key( &pk, mykey, strlen(mykey)+1, NULL, 0 ) ) != 0 )
//     {
//         printf( " failed\n  ! mbedtls_pk_parse_key returned -0x%04x\n", (unsigned int) -ret );
//     }

    mbedtls_ecdsa_context ecdsaprikey;
    mbedtls_ecdsa_init(&ecdsaprikey);
    // const mbedtls_ecp_keypair *pk_ecp = mbedtls_pk_ec(pk);
    // mbedtls_ecdsa_from_keypair(&ecdsaprikey, pk_ecp);

    mbedtls_mpi_read_string(&ecdsaprikey.d, 16, "CE69EFE1E68415AD5B9F4C8B2F3025CB1332DDBD881073309A53A526FD3D7DBD");
    if( ( ret = mbedtls_ecp_group_load( &ecdsaprikey.grp, MBEDTLS_ECP_DP_SECP256R1 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecp_group_load returned -0x%04x\n", (unsigned int) -ret );
    }

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    char text[] = "43545430303030304142434445464748073B0F45272556735A0A6663635F6853C7EDE9CA4154E6DEA172512FC1CCC8BAC0B883067C45160DAA12BF78DACD1838016F888F798BDD0D7826D0";
    unsigned char hashbyte[32];
    unsigned char *textbyte = hexstr_to_char(text);

    if( ( ret = mbedtls_sha256_ret( (unsigned char *) textbyte, 75, hashbyte , 0) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_sha256_ret returned -0x%04x\n", (unsigned int) -ret );
    }

    dump_buf( "  + Hash: ", hashbyte, sizeof(hashbyte) );

    if( ( ret = mbedtls_ecdsa_sign_det( &ecdsaprikey.grp, &r, &s, &ecdsaprikey.d, hashbyte, sizeof(hashbyte), MBEDTLS_MD_SHA256 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecdsa_sign_det returned -0x%04x\n", (unsigned int) -ret );
    }

    char tmp[1000];
    size_t olen;
    mbedtls_mpi_write_string(&r, 16, tmp, sizeof(tmp), &olen);
    printf("  + R: %s\n", tmp);
    mbedtls_mpi_write_string(&s, 16, tmp, sizeof(tmp), &olen);
    printf("  + S: %s\n", tmp);

    // mbedtls_printf( " ok (signature length = %u)\n", (unsigned int) sig_len );

    // dump_buf( "  + Signature: ", sig, sig_len );
}

int verify() {
    int ret = 1;
//     mbedtls_pk_context pk;
//     mbedtls_pk_init( &pk );
//     const unsigned char* myPubkey = "-----BEGIN PUBLIC KEY-----\n"\
// "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvDFoQlYqsEyph/OfvFNoiZoPLWBZ4SR7aNPcTybHVmn4CMa7EVs7Q+fzoj0+X0uzYoGDYVpWBOHmA8lWO7JJQg==\n"\
// "-----END PUBLIC KEY-----";

//     if( ( ret = mbedtls_pk_parse_public_key( &pk, myPubkey, strlen(myPubkey)+1 ) ) != 0 )
//     {
//         printf( " failed\n  ! mbedtls_pk_parse_public_keyfile returned -0x%04x\n", (unsigned int) -ret );
//     }

    mbedtls_ecdsa_context ecdsapubkey;
    mbedtls_ecdsa_init(&ecdsapubkey);
    // const mbedtls_ecp_keypair *keypair = mbedtls_pk_ec(pk);
    // mbedtls_ecdsa_from_keypair(&ecdsapubkey, keypair);
    // dump_pubkey( "  + Public key: ", &ecdsapubkey );

    // mbedtls_ecp_point pubkey;
    // mbedtls_ecp_point_init(&pubkey);
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

    mbedtls_mpi r;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_read_string(&r, 16, "4766CA8E3DC1F1BD61F11DE43266D1328F30355E1341D8E64CD4EA04EF78C845");
    mbedtls_mpi s;
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_string(&s, 16, "6B5344AC8B183E6BDB8184FB49500EB7F5CD636D0694809B81117079988E8B2F");
    if( ( ret = mbedtls_ecdsa_verify(&ecdsapubkey.grp, hashbyte, 32, &ecdsapubkey.Q, &r, &s) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecdsa_read_signature returned -0x%04x\n", (unsigned int) -ret );
    }

    if (!ret)
        printf( "\n  . OK (the signature is valid)\n\n" );
}

int main() {
    sign();
    verify();
}
