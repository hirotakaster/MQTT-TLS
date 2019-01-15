//#include "mbedtls/pk.h"
//#include <mbedtls/error.h>
#include "mbedtls/entropy.h"  //Memory crashes in entropy creation ***mbedtls offers a NVRAM usage... We could try that.
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform.h"
#include "Base64RK.h"

#include "JWT.h"

#define ECPARAMS MBEDTLS_ECP_DP_SECP192R1

//This is just temporary until createGCPJWT is called
size_t JWT::jwtSeedLen = 1; //Will be re-initialized later
unsigned char initSeed = 1;
unsigned char* JWT::jwtSeedPtr = &initSeed; //just point it somewhere until real initialization

//Constructor
JWT::JWT(){
}

JWT::~JWT(){
  free(base64Header);
  free(base64Payload);
  free(base64Signature);
}

/**    Reference: https://github.com/nkolban/esp32-snippets/blob/master/cloud/GCP/JWT/main.cpp
 * Create a JWT token for GCP.
 * For full details, perform a Google search on JWT.  However, in summary, we build two strings.  One that represents the
 * header and one that represents the payload.  Both are JSON and are as described in the GCP and JWT documentation.  Next
 * we base64url encode both strings.  Note that is distinct from normal/simple base64 encoding.  Once we have a string for
 * the base64url encoding of both header and payload, we concatenate both strings together separated by a ".".   This resulting
 * string is then signed using RSASSA which basically produces an SHA256 message digest that is then signed.  The resulting
 * binary is then itself converted into base64url and concatenated with the previously built base64url combined header and
 * payload and that is our resulting JWT token.
 * @param projectId The GCP project.
 * @param privateKey The PEM or DER of the private key.
 * @param privateKeySize The size in bytes of the private key.
 * @returns A JWT token for transmission to GCP.
 */
char* JWT::createGCPJWT(const char* projectId, const uint8_t* privateKeyFile, size_t privateKeySize, uint8_t expireInHours, unsigned char* jwtSeed, size_t myJwtSeedLen) {

    Serial.println("createGCPJWT:JWT Mem Check:" + String::format("%d",System.freeMemory()));
    const char header[28] = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";  //maybe change to RS256 to ECDSA eventually
    Serial.println("createGCPJWT:JWT Header Ready for b64 encoding:" + String::format("%s",header));

    size_t headerLen = sizeof(header)*4/3;
    boolean encodeSuccess = Base64::encode((uint8_t*) header, (size_t) header, base64Header, headerLen, TRUE);
    Serial.println("createGCPJWT:JWT Header b64 encoded:" + String::format("%d",encodeSuccess) + ":b64:"  + String::format("%s",base64Header));

    //Calculate expiration timestamp
    uint32_t iat = Time.now();              // Set the time now.
    uint32_t expTimestamp = iat + (expireInHours*60*60);      // Set the expiry time.

    //This should be 28 characters
    uint32_t payloadSize = 28;  //TODO improve
    String payload = String("{\"iat\":" + String::format("%d",iat) +
    ",\"exp\":" + String::format("%d",expTimestamp) +
    ",\"aud\":" + String::format("%s",projectId) +
    "\"}");

    size_t base64HeaderLen = sizeof(base64Payload);
    //b64 encoding 28 characters requires 38 characters at least, I'm just hardcoding this because

    Serial.println("createGCPJWT:JWT Payload (IAT, EXP, AUD) Ready for b64 encoding:" + String::format("%s",payload));
    encodeSuccess = Base64::encode((uint8_t*)payload.c_str(), (size_t) payloadSize, base64Payload, base64HeaderLen, TRUE);
    Serial.println("createGCPJWT:JWT Payload (IAT, EXP, AUD) b64 encoded:" + String::format("%d",encodeSuccess) + ":b64:"  + String::format("%s",base64Payload));

    //sprintf((char*)headerAndPayload, "%s.%s", base64Header, base64Payload);
    String headerAndPayload = String(String::format("%s",base64Header) + "." + String::format("%s",base64Payload));
    Serial.println("createGCPJWT:JWT Ready for encryption:" + String::format("%s",headerAndPayload));

    // At this point we have created the header and payload parts, converted both to base64 and concatenated them
    // together as a single string.  Now we need to sign them using RSASSA or ECDSA or .... I don't know yet

    //mbedtls_pk_context pk_context;  //Pulled out original pk signing to attempt based on ECDSA for smaller footprint
    //mbedtls_pk_init(&pk_context);
    Serial.println("createGCPJWT:JWT Mem Check(2):" + String::format("%d",System.freeMemory()));

    //Initializing ECDSA parameters based on mbedts example here:
    //     https://github.com/ARMmbed/mbedtls/blob/development/programs/pkey/ecdsa.c
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdsa_context ctx_sign, ctx_verify;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char message[100];
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sigLen;
    const char *pers = "ecdsa";

    Serial.println("createGCPJWT:JWT Mem Check(2.1):" + String::format("%d",System.freeMemory()));
    mbedtls_ecdsa_init( &ctx_sign );
    Serial.println("createGCPJWT:JWT Mem Check(2.2):" + String::format("%d",System.freeMemory()));
    mbedtls_ecdsa_init( &ctx_verify );
    Serial.println("createGCPJWT:JWT Mem Check(2.3):" + String::format("%d",System.freeMemory()));
    mbedtls_ctr_drbg_init(&ctr_drbg);
    Serial.println("createGCPJWT:JWT Mem Check(3):" + String::format("%d",System.freeMemory()));
    memset( sig, 0, sizeof( sig ) );
    memset( message, 0x25, sizeof( message ) );

    //set entropy pointers
    //if the seed is not pre-initialized, do it now
    if (jwtSeedLen <= 1) {
      jwtSeedPtr = jwtSeed;
      jwtSeedLen = myJwtSeedLen;
    }
    mbedtls_platform_set_nv_seed( buffer_nv_seed_read, buffer_nv_seed_write );

    mbedtls_entropy_init(&entropy);
    Serial.println("createGCPJWT:JWT Mem Check(4):" + String::format("%d",System.freeMemory()));
    size_t persLen = sizeof(pers); //10

    mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)pers,
        persLen);


    uint8_t digest[32];
    Serial.println("createGCPJWT:JWT Mem Check(5):" + String::format("%d",System.freeMemory()));

    //I'm not sure if this is the right process yet
    if( ( ret = mbedtls_ecdsa_genkey( &ctx_sign, ECPARAMS,
                              mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ){
      Serial.println("Failed to mbedtls_ecdsa_genkey: " + String::format("%d",ret) +
                     " (-0x" + String::format("%x",-ret) +
                     ")\n");

      return nullptr;
    }

    if( ( ret = mbedtls_sha256_ret( message, sizeof( message ), hash, 0 ) ) != 0 ){
      Serial.println("Failed to mbedtls_sha256_ret: " + String::format("%d",ret) +
                     " (-0x" + String::format("%x",-ret) +
                     ")\n");

      return nullptr;
    }

    size_t retSize;
    if( ( ret = mbedtls_ecdsa_write_signature( &ctx_sign, MBEDTLS_MD_SHA256,
                                       hash, sizeof( hash ),
                                       sig, &sigLen,
                                       mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ){
     Serial.println("Failed to mbedtls_ecdsa_write_signature: " + String::format("%d",ret) +
                    " (-0x" + String::format("%x",-ret) +
                    ")\n");

     return nullptr;
    }
    mbedtls_ecdsa_free( &ctx_verify );
    mbedtls_ecdsa_free( &ctx_sign );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    //Serial.println("createGCPJWT:JWT Output Buffer ready for b64 encoding:" + String::format("%s",oBuf));
    Serial.println("createGCPJWT:JWT Output Buffer ready for b64 encoding:" + String::format("%s",sig));
    size_t base64SignatureLen = sizeof(base64Signature);
    //encodeSuccess = Base64::encode((uint8_t*) oBuf, retSize, base64Signature, base64SignatureLen, TRUE);
    encodeSuccess = Base64::encode((uint8_t*) sig, sigLen, base64Signature, base64SignatureLen, TRUE);
    Serial.println("createGCPJWT:JWT Signature b64 encoded:" + String::format("%d",encodeSuccess) + ":b64:" + String::format("%s",base64Signature));
    //ORIGINAL base64url_encode((unsigned char *)oBuf, retSize, base64Signature);

    char* retData = (char*)malloc(headerAndPayload.length() + 1 + base64SignatureLen + 1); //base64SignatureLen, was strlen((char*)base64Signature)

    //sprintf(retData, "%s.%s", headerAndPayload, base64Signature);
    retData = (char*)String(String::format("%s",headerAndPayload) + "." + String::format("%s",base64Signature)).c_str();
    return retData;
}

//int JWT::mbedtls_ctr_drbg_random_ish( void *p_rng, unsigned char *output, size_t output_len ){
  //Pretend to generate a number because we can't run mbed-tls as we'd like.
//}

/*
 * NV seed read/write functions that use a buffer instead of a file
 *        From:https://github.com/Jigsaw-Code/outline-client/blob/master/third_party/mbedtls/tests/suites/test_suite_entropy.function
 */
//static unsigned char buffer_seed[MBEDTLS_ENTROPY_BLOCK_SIZE];

int JWT::buffer_nv_seed_read( unsigned char *buf, size_t buf_len )
{
    if( buf_len != JWT::jwtSeedLen )
        return( -1 );

    memcpy( buf, JWT::jwtSeedPtr, JWT::jwtSeedLen );
    return( 0 );
}

int JWT::buffer_nv_seed_write( unsigned char *buf, size_t buf_len )
{
    if( buf_len != JWT::jwtSeedLen )
        return( -1 );

    memcpy( JWT::jwtSeedPtr, buf, buf_len );
    return( 0 );
}
