//JWT Class Library
#include "Arduino.h"

#define BASE64_HEADER_LEN 100
#define BASE64_PAYLOAD_LEN 100
#define BASE64_SIGNATURE_LEN 600

class JWT {
 public:

  JWT(); // Constructor
  ~JWT();

  static unsigned char* jwtSeedPtr;
  static size_t jwtSeedLen;

  //TODO add function documentation
  static int buffer_nv_seed_read( unsigned char *buf, size_t buf_len );
  static int buffer_nv_seed_write( unsigned char *buf, size_t buf_len );
  char* createGCPJWT(const char* projectId, const uint8_t* privateKey, size_t privateKeySize, uint8_t expireInHours, unsigned char* jwtSeed, size_t myJwtSeedLen);

private:
  char base64Header[BASE64_HEADER_LEN];
  char base64Payload[BASE64_PAYLOAD_LEN];
  char base64Signature[BASE64_SIGNATURE_LEN];

  //TODO add function documentation
  static char* mbedtlsError(int errnum);
  static int randomish( void *p_rng, unsigned char *output, size_t output_len );
  //int mbedtls_ctr_drbg_random_ish( void *p_rng, unsigned char *output, size_t output_len );
};
