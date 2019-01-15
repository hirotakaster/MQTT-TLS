/*
 *  CTR_DRBG implementation based on AES-256 (NIST SP 800-90)
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The NIST SP 800-90 DRBGs are described in the following publication.
 *
 *  http://csrc.nist.gov/publications/nistpubs/800-90/SP800-90revised_March2007.pdf
 */

#include "Arduino.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_CTR_DRBG_C)

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform_util.h"

//#include <string.h>

#if defined(MBEDTLS_FS_IO)
//#include <stdio.h>
#endif

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
//#include <stdio.h>
#define mbedtls_printf Serial.println
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

/*
 * CTR_DRBG context initialization
 */
void mbedtls_ctr_drbg_init( mbedtls_ctr_drbg_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_ctr_drbg_context ) );

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_init( &ctx->mutex );
#endif
}

/*
 * Non-public function wrapped by mbedtls_ctr_drbg_seed(). Necessary to allow
 * NIST tests to succeed (which require known length fixed entropy)
 */
/* CTR_DRBG_Instantiate with derivation function (SP 800-90A &sect;10.2.1.3.2)
 * mbedtls_ctr_drbg_seed_entropy_len(ctx, f_entropy, p_entropy,
 *                                   custom, len, entropy_len)
 * implements
 * CTR_DRBG_Instantiate(entropy_input, nonce, personalization_string,
 *                      security_strength) -> initial_working_state
 * with inputs
 *   custom[:len] = nonce || personalization_string
 * where entropy_input comes from f_entropy for entropy_len bytes
 * and with outputs
 *   ctx = initial_working_state
 */
int mbedtls_ctr_drbg_seed_entropy_len(
                   mbedtls_ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len,
                   size_t entropy_len )
{
    int ret;
    unsigned char key[MBEDTLS_CTR_DRBG_KEYSIZE];

    memset( key, 0, MBEDTLS_CTR_DRBG_KEYSIZE );

    mbedtls_aes_init( &ctx->aes_ctx );
    Serial.println("mbedtls_ctr_drbg_seed_entropy_len:Mem Check(1):" + String::format("%d",System.freeMemory()));

    ctx->f_entropy = f_entropy;
    ctx->p_entropy = p_entropy;

    ctx->entropy_len = entropy_len;
    ctx->reseed_interval = MBEDTLS_CTR_DRBG_RESEED_INTERVAL;

    /*
     * Initialize with an empty key
     */
    if( ( ret = mbedtls_aes_setkey_enc( &ctx->aes_ctx, key, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 )
    {
        Serial.println("mbedtls_ctr_drbg_seed_entropy_len:Mem Check(2):" + String::format("%d",System.freeMemory()));
        return( ret );
    }

    if( ( ret = mbedtls_ctr_drbg_reseed( ctx, custom, len ) ) != 0 )
    {
        Serial.println("mbedtls_ctr_drbg_seed_entropy_len:Mem Check(3):" + String::format("%d",System.freeMemory()));
        return( ret );
    }
    return( 0 );
}

int mbedtls_ctr_drbg_seed( mbedtls_ctr_drbg_context *ctx,
                   int (*f_entropy)(void *, unsigned char *, size_t),
                   void *p_entropy,
                   const unsigned char *custom,
                   size_t len )
{
    return( mbedtls_ctr_drbg_seed_entropy_len( ctx, f_entropy, p_entropy, custom, len,
                                       MBEDTLS_CTR_DRBG_ENTROPY_LEN ) );
}

void mbedtls_ctr_drbg_free( mbedtls_ctr_drbg_context *ctx )
{
    if( ctx == NULL )
        return;

#if defined(MBEDTLS_THREADING_C)
    mbedtls_mutex_free( &ctx->mutex );
#endif
    mbedtls_aes_free( &ctx->aes_ctx );
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_ctr_drbg_context ) );
}

void mbedtls_ctr_drbg_set_prediction_resistance( mbedtls_ctr_drbg_context *ctx, int resistance )
{
    ctx->prediction_resistance = resistance;
}

void mbedtls_ctr_drbg_set_entropy_len( mbedtls_ctr_drbg_context *ctx, size_t len )
{
    ctx->entropy_len = len;
}

void mbedtls_ctr_drbg_set_reseed_interval( mbedtls_ctr_drbg_context *ctx, int interval )
{
    ctx->reseed_interval = interval;
}

static int block_cipher_df( unsigned char *output,
                            const unsigned char *data, size_t data_len )
{
    unsigned char buf[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT + MBEDTLS_CTR_DRBG_BLOCKSIZE + 16];
    unsigned char tmp[MBEDTLS_CTR_DRBG_SEEDLEN];
    unsigned char key[MBEDTLS_CTR_DRBG_KEYSIZE];
    unsigned char chain[MBEDTLS_CTR_DRBG_BLOCKSIZE];
    unsigned char *p, *iv;
    mbedtls_aes_context aes_ctx;
    int ret = 0;

    int i, j;
    size_t buf_len, use_len;

    if( data_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT )
        return( MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( buf, 0, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT + MBEDTLS_CTR_DRBG_BLOCKSIZE + 16 );
    mbedtls_aes_init( &aes_ctx );

    /*
     * Construct IV (16 bytes) and S in buffer
     * IV = Counter (in 32-bits) padded to 16 with zeroes
     * S = Length input string (in 32-bits) || Length of output (in 32-bits) ||
     *     data || 0x80
     *     (Total is padded to a multiple of 16-bytes with zeroes)
     */
    p = buf + MBEDTLS_CTR_DRBG_BLOCKSIZE;
    *p++ = ( data_len >> 24 ) & 0xff;
    *p++ = ( data_len >> 16 ) & 0xff;
    *p++ = ( data_len >> 8  ) & 0xff;
    *p++ = ( data_len       ) & 0xff;
    p += 3;
    *p++ = MBEDTLS_CTR_DRBG_SEEDLEN;
    memcpy( p, data, data_len );
    p[data_len] = 0x80;

    buf_len = MBEDTLS_CTR_DRBG_BLOCKSIZE + 8 + data_len + 1;

    for( i = 0; i < MBEDTLS_CTR_DRBG_KEYSIZE; i++ )
        key[i] = i;

    if( ( ret = mbedtls_aes_setkey_enc( &aes_ctx, key, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 )
    {
        goto exit;
    }

    /*
     * Reduce data to MBEDTLS_CTR_DRBG_SEEDLEN bytes of data
     */
    for( j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE )
    {
        p = buf;
        memset( chain, 0, MBEDTLS_CTR_DRBG_BLOCKSIZE );
        use_len = buf_len;

        while( use_len > 0 )
        {
            for( i = 0; i < MBEDTLS_CTR_DRBG_BLOCKSIZE; i++ )
                chain[i] ^= p[i];
            p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
            use_len -= ( use_len >= MBEDTLS_CTR_DRBG_BLOCKSIZE ) ?
                       MBEDTLS_CTR_DRBG_BLOCKSIZE : use_len;

            if( ( ret = mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, chain, chain ) ) != 0 )
            {
                goto exit;
            }
        }

        memcpy( tmp + j, chain, MBEDTLS_CTR_DRBG_BLOCKSIZE );

        /*
         * Update IV
         */
        buf[3]++;
    }

    /*
     * Do final encryption with reduced data
     */
    if( ( ret = mbedtls_aes_setkey_enc( &aes_ctx, tmp, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 )
    {
        goto exit;
    }
    iv = tmp + MBEDTLS_CTR_DRBG_KEYSIZE;
    p = output;

    for( j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE )
    {
        if( ( ret = mbedtls_aes_crypt_ecb( &aes_ctx, MBEDTLS_AES_ENCRYPT, iv, iv ) ) != 0 )
        {
            goto exit;
        }
        memcpy( p, iv, MBEDTLS_CTR_DRBG_BLOCKSIZE );
        p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
    }
exit:
    mbedtls_aes_free( &aes_ctx );
    /*
    * tidy up the stack
    */
    mbedtls_platform_zeroize( buf, sizeof( buf ) );
    mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
    mbedtls_platform_zeroize( key, sizeof( key ) );
    mbedtls_platform_zeroize( chain, sizeof( chain ) );
    if( 0 != ret )
    {
        /*
        * wipe partial seed from memory
        */
        mbedtls_platform_zeroize( output, MBEDTLS_CTR_DRBG_SEEDLEN );
    }

    return( ret );
}

/* CTR_DRBG_Update (SP 800-90A &sect;10.2.1.2)
 * ctr_drbg_update_internal(ctx, provided_data)
 * implements
 * CTR_DRBG_Update(provided_data, Key, V)
 * with inputs and outputs
 *   ctx->aes_ctx = Key
 *   ctx->counter = V
 */
static int ctr_drbg_update_internal( mbedtls_ctr_drbg_context *ctx,
                              const unsigned char data[MBEDTLS_CTR_DRBG_SEEDLEN] )
{
    unsigned char tmp[MBEDTLS_CTR_DRBG_SEEDLEN];
    unsigned char *p = tmp;
    int i, j;
    int ret = 0;

    memset( tmp, 0, MBEDTLS_CTR_DRBG_SEEDLEN );

    for( j = 0; j < MBEDTLS_CTR_DRBG_SEEDLEN; j += MBEDTLS_CTR_DRBG_BLOCKSIZE )
    {
        /*
         * Increase counter
         */
        for( i = MBEDTLS_CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        /*
         * Crypt counter block
         */
        if( ( ret = mbedtls_aes_crypt_ecb( &ctx->aes_ctx, MBEDTLS_AES_ENCRYPT, ctx->counter, p ) ) != 0 )
            goto exit;

        p += MBEDTLS_CTR_DRBG_BLOCKSIZE;
    }

    for( i = 0; i < MBEDTLS_CTR_DRBG_SEEDLEN; i++ )
        tmp[i] ^= data[i];

    /*
     * Update key and counter
     */
    if( ( ret = mbedtls_aes_setkey_enc( &ctx->aes_ctx, tmp, MBEDTLS_CTR_DRBG_KEYBITS ) ) != 0 )
        goto exit;
    memcpy( ctx->counter, tmp + MBEDTLS_CTR_DRBG_KEYSIZE, MBEDTLS_CTR_DRBG_BLOCKSIZE );

exit:
    mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
    return( ret );
}

/* CTR_DRBG_Instantiate with derivation function (SP 800-90A &sect;10.2.1.3.2)
 * mbedtls_ctr_drbg_update(ctx, additional, add_len)
 * implements
 * CTR_DRBG_Instantiate(entropy_input, nonce, personalization_string,
 *                      security_strength) -> initial_working_state
 * with inputs
 *   ctx->counter = all-bits-0
 *   ctx->aes_ctx = context from all-bits-0 key
 *   additional[:add_len] = entropy_input || nonce || personalization_string
 * and with outputs
 *   ctx = initial_working_state
 */
int mbedtls_ctr_drbg_update_ret( mbedtls_ctr_drbg_context *ctx,
                                 const unsigned char *additional,
                                 size_t add_len )
{
    unsigned char add_input[MBEDTLS_CTR_DRBG_SEEDLEN];
    int ret;

    if( add_len == 0 )
        return( 0 );

    if( ( ret = block_cipher_df( add_input, additional, add_len ) ) != 0 )
        goto exit;
    if( ( ret = ctr_drbg_update_internal( ctx, add_input ) ) != 0 )
        goto exit;

exit:
    mbedtls_platform_zeroize( add_input, sizeof( add_input ) );
    return( ret );
}

#if !defined(MBEDTLS_DEPRECATED_REMOVED)
void mbedtls_ctr_drbg_update( mbedtls_ctr_drbg_context *ctx,
                              const unsigned char *additional,
                              size_t add_len )
{
    /* MAX_INPUT would be more logical here, but we have to match
     * block_cipher_df()'s limits since we can't propagate errors */
    if( add_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT )
        add_len = MBEDTLS_CTR_DRBG_MAX_SEED_INPUT;
    (void) mbedtls_ctr_drbg_update_ret( ctx, additional, add_len );
}
#endif /* MBEDTLS_DEPRECATED_REMOVED */

/* CTR_DRBG_Reseed with derivation function (SP 800-90A &sect;10.2.1.4.2)
 * mbedtls_ctr_drbg_reseed(ctx, additional, len)
 * implements
 * CTR_DRBG_Reseed(working_state, entropy_input, additional_input)
 *                -> new_working_state
 * with inputs
 *   ctx contains working_state
 *   additional[:len] = additional_input
 * and entropy_input comes from calling ctx->f_entropy
 * and with output
 *   ctx contains new_working_state
 */
int mbedtls_ctr_drbg_reseed( mbedtls_ctr_drbg_context *ctx,
                     const unsigned char *additional, size_t len )
{
    unsigned char seed[MBEDTLS_CTR_DRBG_MAX_SEED_INPUT];
    size_t seedlen = 0;
    int ret;

    if( ctx->entropy_len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT ||
        len > MBEDTLS_CTR_DRBG_MAX_SEED_INPUT - ctx->entropy_len )
        return( MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( seed, 0, MBEDTLS_CTR_DRBG_MAX_SEED_INPUT );
    Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(1):" + String::format("%d",System.freeMemory()));
    /*
     * Gather entropy_len bytes of entropy to seed state
     */
    if( 0 != ctx->f_entropy( ctx->p_entropy, seed,
                             ctx->entropy_len ) )
    {
        Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(2):" + String::format("%d",System.freeMemory()));
        return( MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED );
    }

    seedlen += ctx->entropy_len;

    /*
     * Add additional data
     */
    if( additional && len )
    {
        Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(3):" + String::format("%d",System.freeMemory()));
        memcpy( seed + seedlen, additional, len );
        seedlen += len;
    }

    /*
     * Reduce to 384 bits
     */
    if( ( ret = block_cipher_df( seed, seed, seedlen ) ) != 0 ){
      Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(4):" + String::format("%d",System.freeMemory()));
      goto exit;
    }


    /*
     * Update state
     */
    if( ( ret = ctr_drbg_update_internal( ctx, seed ) ) != 0 ){

      Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(5):" + String::format("%d",System.freeMemory()));
      goto exit;
    }

    ctx->reseed_counter = 1;

exit:
    Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(6):" + String::format("%d",System.freeMemory()));
    mbedtls_platform_zeroize( seed, sizeof( seed ) );
    Serial.println("mbedtls_ctr_drbg_reseed:Mem Check(7):" + String::format("%d",System.freeMemory()));
    return( ret );
}

/* CTR_DRBG_Generate with derivation function (SP 800-90A &sect;10.2.1.5.2)
 * mbedtls_ctr_drbg_random_with_add(ctx, output, output_len, additional, add_len)
 * implements
 * CTR_DRBG_Reseed(working_state, entropy_input, additional[:add_len])
 *                -> working_state_after_reseed
 *                if required, then
 * CTR_DRBG_Generate(working_state_after_reseed,
 *                   requested_number_of_bits, additional_input)
 *                -> status, returned_bits, new_working_state
 * with inputs
 *   ctx contains working_state
 *   requested_number_of_bits = 8 * output_len
 *   additional[:add_len] = additional_input
 * and entropy_input comes from calling ctx->f_entropy
 * and with outputs
 *   status = SUCCESS (this function does the reseed internally)
 *   returned_bits = output[:output_len]
 *   ctx contains new_working_state
 */
int mbedtls_ctr_drbg_random_with_add( void *p_rng,
                              unsigned char *output, size_t output_len,
                              const unsigned char *additional, size_t add_len )
{
    int ret = 0;
    mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *) p_rng;
    unsigned char add_input[MBEDTLS_CTR_DRBG_SEEDLEN];
    unsigned char *p = output;
    unsigned char tmp[MBEDTLS_CTR_DRBG_BLOCKSIZE];
    int i;
    size_t use_len;

    if( output_len > MBEDTLS_CTR_DRBG_MAX_REQUEST )
        return( MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG );

    if( add_len > MBEDTLS_CTR_DRBG_MAX_INPUT )
        return( MBEDTLS_ERR_CTR_DRBG_INPUT_TOO_BIG );

    memset( add_input, 0, MBEDTLS_CTR_DRBG_SEEDLEN );

    if( ctx->reseed_counter > ctx->reseed_interval ||
        ctx->prediction_resistance )
    {
        if( ( ret = mbedtls_ctr_drbg_reseed( ctx, additional, add_len ) ) != 0 )
        {
            return( ret );
        }
        add_len = 0;
    }

    if( add_len > 0 )
    {
        if( ( ret = block_cipher_df( add_input, additional, add_len ) ) != 0 )
            goto exit;
        if( ( ret = ctr_drbg_update_internal( ctx, add_input ) ) != 0 )
            goto exit;
    }

    while( output_len > 0 )
    {
        /*
         * Increase counter
         */
        for( i = MBEDTLS_CTR_DRBG_BLOCKSIZE; i > 0; i-- )
            if( ++ctx->counter[i - 1] != 0 )
                break;

        /*
         * Crypt counter block
         */
        if( ( ret = mbedtls_aes_crypt_ecb( &ctx->aes_ctx, MBEDTLS_AES_ENCRYPT, ctx->counter, tmp ) ) != 0 )
            goto exit;

        use_len = ( output_len > MBEDTLS_CTR_DRBG_BLOCKSIZE ) ? MBEDTLS_CTR_DRBG_BLOCKSIZE :
                                                       output_len;
        /*
         * Copy random block to destination
         */
        memcpy( p, tmp, use_len );
        p += use_len;
        output_len -= use_len;
    }

    if( ( ret = ctr_drbg_update_internal( ctx, add_input ) ) != 0 )
        goto exit;

    ctx->reseed_counter++;

exit:
    mbedtls_platform_zeroize( add_input, sizeof( add_input ) );
    mbedtls_platform_zeroize( tmp, sizeof( tmp ) );
    return( 0 );
}

int mbedtls_ctr_drbg_random( void *p_rng, unsigned char *output, size_t output_len )
{
    int ret;
    mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *) p_rng;

#if defined(MBEDTLS_THREADING_C)
    if( ( ret = mbedtls_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    ret = mbedtls_ctr_drbg_random_with_add( ctx, output, output_len, NULL, 0 );

#if defined(MBEDTLS_THREADING_C)
    if( mbedtls_mutex_unlock( &ctx->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}

#endif /* MBEDTLS_CTR_DRBG_C */
