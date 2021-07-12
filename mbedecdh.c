#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"

static void dump_buf( const char *title, unsigned char *buf, size_t len )
{
    size_t i;

    printf( "%s", title );
    for( i = 0; i < len; i++ )
        printf("%c%c", "0123456789ABCDEF" [buf[i] / 16],
                       "0123456789ABCDEF" [buf[i] % 16] );
    printf( "\n" );
}

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

void getbytes(unsigned char* bytes, int value)
{
    bytes[0] = (value >> 24) & 0xFF;
    bytes[1] = (value >> 16) & 0xFF;
    bytes[2] = (value >> 8) & 0xFF;
    bytes[3] = value & 0xFF;
}

/*
 * KDF
 */
int generateKeyKDF(unsigned char* sharedZ)
{
    int ret;

    /*
     * One-pass-DH
     * otherInfo = ( AlgID || partyU's System Title || partyV's System Title )
     * Static-DH
     * otherInfo = ( AlgID || partyU's System Title || 0x08 + TransactionId || partyV's System Title )
     */
    // 6085740508030043545430303030304142434445464748
    // 6085740508030043545430303030300836303739433330414142434445464748
    size_t len_otherInfo;
    unsigned char* otherInfo = hexstr_to_char("6085740508030043545430303030300836303739433330414142434445464748", &len_otherInfo);

    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init( &md_ctx );
    md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    if( ( ret = mbedtls_md_setup( &md_ctx, md_info, 0 ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_md_setup returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    // NIST.SP.800-56A KDF
    unsigned char v[4];
    size_t hashlen, keylen, reps;
    hashlen = mbedtls_md_get_size( md_info );
    keylen = 32; // ECDH with P-256, so result is 256 bits (32 bytes)
    unsigned char key[keylen];
    unsigned char hash_output[MBEDTLS_MD_MAX_SIZE];
    reps = keylen/hashlen;

    for (int pos = 1; pos <= reps; pos++)
    {
        // Calculate hash
        if( ( ret = mbedtls_md_starts( &md_ctx ) ) != 0 )
        {
            printf( " failed\n  ! mbedtls_md_starts returned -0x%04x\n", (unsigned int) -ret );
            return ret;
        }
        // Add salt
        getbytes(v, pos);
        if( ( ret = mbedtls_md_update( &md_ctx, v, sizeof(v) ) ) != 0 )
        {
            printf( " failed\n  ! mbedtls_md_update returned -0x%04x\n", (unsigned int) -ret );
            return ret;
        }
        if( ( ret = mbedtls_md_update( &md_ctx, sharedZ, 32 ) ) != 0 )
        {
            printf( " failed\n  ! mbedtls_md_update returned -0x%04x\n", (unsigned int) -ret );
            return ret;
        }
        if( ( ret = mbedtls_md_update( &md_ctx, otherInfo, len_otherInfo ) ) != 0 )
        {
            printf( " failed\n  ! mbedtls_md_update returned -0x%04x\n", (unsigned int) -ret );
            return ret;
        }
        if( ( ret = mbedtls_md_finish( &md_ctx, hash_output ) ) != 0 )
        {
            printf( " failed\n  ! mbedtls_md_finish returned -0x%04x\n", (unsigned int) -ret );
            return ret;
        }
        // fill key length
        if ( pos < reps )
        {
            memcpy( hash_output, key + hashlen * ( pos - 1 ), hashlen );
            return ret;
        }
        else
        {
            if ( keylen % hashlen == 0)
            {
                memcpy( key + hashlen * ( pos - 1 ), hash_output , hashlen );
            }
            else
            {
                memcpy( key + hashlen * ( pos - 1 ), hash_output , keylen % hashlen );
            }
        }
    }

    dump_buf("  + Key: ", key, 32);

    printf( " ok\n" );

    mbedtls_md_free( &md_ctx );

    return ret;
}

int generateSharedSecret()
{
    int ret = 1;

    /*
     * Init Random number generator
     */
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    const char pers[] = "ecdh";
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               sizeof pers ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    /*
     * Assign party U's public key and party V's private key
     */
    mbedtls_ecdh_context ctx_srv;
    mbedtls_ecdh_init( &ctx_srv );
    
    mbedtls_ecp_group_load( &ctx_srv.grp, MBEDTLS_ECP_DP_SECP256R1 );

    // assign private key
    if( ( ret = mbedtls_mpi_read_string(&ctx_srv.d, 16, "CE69EFE1E68415AD5B9F4C8B2F3025CB1332DDBD881073309A53A526FD3D7DBD") ) != 0 )
    {
        printf( " failed\n  ! mbedtls_mpi_read_string returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    // read public key of the peer
    if( ( ret = mbedtls_ecp_point_read_string( &ctx_srv.Qp, 16, "BC316842562AB04CA987F39FBC5368899A0F2D6059E1247B68D3DC4F26C75669", "F808C6BB115B3B43E7F3A23D3E5F4BB3628183615A5604E1E603C9563BB24942" ) ) != 0 )
    {
        printf( " failed\n  ! mbedtls_ecp_point_read_string returned -0x%04x\n", (unsigned int) -ret );
        return ret;
    }

    // no need
    // ret = mbedtls_mpi_lset( &ctx_srv.Qp.Z, 1 );
    // if( ret != 0 )
    // {
    //     printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
    // }

    /*
     * save shared secret Z to mbedtls_mpi
     */
    // ret = mbedtls_ecdh_compute_shared( &ctx_srv.grp, &ctx_srv.z,
    //                                    &ctx_srv.Qp, &ctx_srv.d,
    //                                    mbedtls_ctr_drbg_random, &ctr_drbg );
    // if( ret != 0 )
    // {
    //     printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
    // }

    // unsigned char shared_secret_z[32];  // shared secret is 32 bytes
    // if (mbedtls_mpi_write_binary(&ctx_srv.z, shared_secret_z, 32) != 0)
    // {
    //     printf( " failed\n  ! mbedtls_mpi_write_binary returned -0x%04x\n", (unsigned int) -ret );
    // }
    // dump_buf("  + Z: ", shared_secret_z, 32);

    /*
     * save shared secret Z to byte array
     */
    size_t olen;
    unsigned char sharedZ[32];  // shared secret is 32 bytes
    ret = mbedtls_ecdh_calc_secret( &ctx_srv, &olen, sharedZ, 32, mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        printf( " failed\n  ! mbedtls_ecdh_calc_secret returned %d\n", ret );
        return ret;
    }
    dump_buf("  + Z: ", sharedZ, 32);

    generateKeyKDF(sharedZ);

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_ecdh_free( &ctx_srv );

    return ret;
}



int main( int argc, char *argv[] )
{
    generateSharedSecret();
}

