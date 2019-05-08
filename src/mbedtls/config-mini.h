/**
 * \file config.h
 *
 * \brief Configuration options (set of defines)
 *
 *  This set of compile-time options may be used to enable
 *  or disable features selectively, and reduce the global
 *  memory footprint.
 */
/*
 *  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
#define _CRT_SECURE_NO_DEPRECATE 1
#endif

#define MBEDTLS_HAVE_ASM

#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

#define MBEDTLS_REMOVE_ARC4_CIPHERSUITES
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

#define MBEDTLS_ERROR_STRERROR_DUMMY
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH
#define MBEDTLS_SSL_PROTO_TLS1_2

#define MBEDTLS_SSL_SESSION_TICKETS
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_X509_CHECK_KEY_USAGE
#define MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT

#define MBEDTLS_AESNI_C
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C

#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C

#define MBEDTLS_ENTROPY_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PADLOCK_C
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PLATFORM_C

#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C

#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_TIMING_C
#define MBEDTLS_VERSION_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CSR_PARSE_C

#define MBEDTLS_SSL_MAX_CONTENT_LEN             8192

#if defined(MBEDTLS_USER_CONFIG_FILE)
#include MBEDTLS_USER_CONFIG_FILE
#endif

#include "check_config.h"

#endif /* MBEDTLS_CONFIG_H */
