/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_H
#define KMIP_H

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
Types and Constants
*/

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef int32 bool32;

typedef uint8_t uint8;
typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint64_t uint64;

typedef size_t memory_index;

#ifdef intptr_t
typedef intptr_t intptr;
#else
typedef int64 intptr;
#endif

typedef float real32;
typedef double real64;

#define KMIP_TRUE (1)
#define KMIP_FALSE (0)

#define KMIP_UNSET (-1)

#define KMIP_MIN(a,b) (((a) < (b)) ? (a) : (b))

#define KMIP_OK                      (0)
#define KMIP_NOT_IMPLEMENTED         (-1)
#define KMIP_ERROR_BUFFER_FULL       (-2)
#define KMIP_ERROR_ATTR_UNSUPPORTED  (-3)
#define KMIP_TAG_MISMATCH            (-4)
#define KMIP_TYPE_MISMATCH           (-5)
#define KMIP_LENGTH_MISMATCH         (-6)
#define KMIP_PADDING_MISMATCH        (-7)
#define KMIP_BOOLEAN_MISMATCH        (-8)
#define KMIP_ENUM_MISMATCH           (-9)
#define KMIP_ENUM_UNSUPPORTED        (-10)
#define KMIP_INVALID_FOR_VERSION     (-11)
#define KMIP_MEMORY_ALLOC_FAILED     (-12)
#define KMIP_IO_FAILURE              (-13)
#define KMIP_EXCEED_MAX_MESSAGE_SIZE (-14)
#define KMIP_MALFORMED_RESPONSE      (-15)
#define KMIP_OBJECT_MISMATCH         (-16)
#define KMIP_ARG_INVALID             (-17)
#define KMIP_ERROR_BUFFER_UNDERFULL  (-18)
#define KMIP_INVALID_ENCODING        (-19)
#define KMIP_INVALID_FIELD           (-20)
#define KMIP_INVALID_LENGTH          (-21)

/*
Enumerations
*/

enum attestation_type
{
    /* KMIP 1.2 */
    KMIP_ATTEST_TPM_QUOTE            = 0x01,
    KMIP_ATTEST_TCG_INTEGRITY_REPORT = 0x02,
    KMIP_ATTEST_SAML_ASSERTION       = 0x03
};

enum attribute_type
{
    /* KMIP 1.0 */
    KMIP_ATTR_UNIQUE_IDENTIFIER                = 0,
    KMIP_ATTR_NAME                             = 1,
    KMIP_ATTR_OBJECT_TYPE                      = 2,
    KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM          = 3,
    KMIP_ATTR_CRYPTOGRAPHIC_LENGTH             = 4,
    KMIP_ATTR_OPERATION_POLICY_NAME            = 5,
    KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK         = 6,
    KMIP_ATTR_STATE                            = 7,
    KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION = 8,
    KMIP_ATTR_OBJECT_GROUP                     = 9,
    KMIP_ATTR_ACTIVATION_DATE                  = 10,
    KMIP_ATTR_DEACTIVATION_DATE                = 11,
    KMIP_ATTR_PROCESS_START_DATE               = 12,
    KMIP_ATTR_PROTECT_STOP_DATE                = 13,
    KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS         = 14
};

enum batch_error_continuation_option
{
    /* KMIP 1.0 */
    KMIP_BATCH_CONTINUE = 0x01,
    KMIP_BATCH_STOP     = 0x02,
    KMIP_BATCH_UNDO     = 0x03
};

enum block_cipher_mode
{
    /* KMIP 1.0 */
    KMIP_BLOCK_CBC                  = 0x01,
    KMIP_BLOCK_ECB                  = 0x02,
    KMIP_BLOCK_PCBC                 = 0x03,
    KMIP_BLOCK_CFB                  = 0x04,
    KMIP_BLOCK_OFB                  = 0x05,
    KMIP_BLOCK_CTR                  = 0x06,
    KMIP_BLOCK_CMAC                 = 0x07,
    KMIP_BLOCK_CCM                  = 0x08,
    KMIP_BLOCK_GCM                  = 0x09,
    KMIP_BLOCK_CBC_MAC              = 0x0A,
    KMIP_BLOCK_XTS                  = 0x0B,
    KMIP_BLOCK_AES_KEY_WRAP_PADDING = 0x0C,
    KMIP_BLOCK_NIST_KEY_WRAP        = 0x0D,
    KMIP_BLOCK_X9102_AESKW          = 0x0E,
    KMIP_BLOCK_X9102_TDKW           = 0x0F,
    KMIP_BLOCK_X9102_AKW1           = 0x10,
    KMIP_BLOCK_X9102_AKW2           = 0x11,
    /* KMIP 1.4 */
    KMIP_BLOCK_AEAD                 = 0x12
};

enum credential_type
{
    /* KMIP 1.0 */
    KMIP_CRED_USERNAME_AND_PASSWORD = 0x01,
    /* KMIP 1.1 */
    KMIP_CRED_DEVICE                = 0x02,
    /* KMIP 1.2 */
    KMIP_CRED_ATTESTATION           = 0x03,
    /* KMIP 2.0 */
    KMIP_CRED_ONE_TIME_PASSWORD     = 0x04,
    KMIP_CRED_HASHED_PASSWORD       = 0x05,
    KMIP_CRED_TICKET                = 0x06
};

enum cryptographic_algorithm
{
    /* KMIP 1.0 */
    KMIP_CRYPTOALG_DES               = 0x01,
    KMIP_CRYPTOALG_TRIPLE_DES        = 0x02,
    KMIP_CRYPTOALG_AES               = 0x03,
    KMIP_CRYPTOALG_RSA               = 0x04,
    KMIP_CRYPTOALG_DSA               = 0x05,
    KMIP_CRYPTOALG_ECDSA             = 0x06,
    KMIP_CRYPTOALG_HMAC_SHA1         = 0x07,
    KMIP_CRYPTOALG_HMAC_SHA224       = 0x08,
    KMIP_CRYPTOALG_HMAC_SHA256       = 0x09,
    KMIP_CRYPTOALG_HMAC_SHA384       = 0x0A,
    KMIP_CRYPTOALG_HMAC_SHA512       = 0x0B,
    KMIP_CRYPTOALG_HMAC_MD5          = 0x0C,
    KMIP_CRYPTOALG_DH                = 0x0D,
    KMIP_CRYPTOALG_ECDH              = 0x0E,
    KMIP_CRYPTOALG_ECMQV             = 0x0F,
    KMIP_CRYPTOALG_BLOWFISH          = 0x10,
    KMIP_CRYPTOALG_CAMELLIA          = 0x11,
    KMIP_CRYPTOALG_CAST5             = 0x12,
    KMIP_CRYPTOALG_IDEA              = 0x13,
    KMIP_CRYPTOALG_MARS              = 0x14,
    KMIP_CRYPTOALG_RC2               = 0x15,
    KMIP_CRYPTOALG_RC4               = 0x16,
    KMIP_CRYPTOALG_RC5               = 0x17,
    KMIP_CRYPTOALG_SKIPJACK          = 0x18,
    KMIP_CRYPTOALG_TWOFISH           = 0x19,
    /* KMIP 1.2 */
    KMIP_CRYPTOALG_EC                = 0x1A,
    /* KMIP 1.3 */
    KMIP_CRYPTOALG_ONE_TIME_PAD      = 0x1B,
    /* KMIP 1.4 */
    KMIP_CRYPTOALG_CHACHA20          = 0x1C,
    KMIP_CRYPTOALG_POLY1305          = 0x1D,
    KMIP_CRYPTOALG_CHACHA20_POLY1305 = 0x1E,
    KMIP_CRYPTOALG_SHA3_224          = 0x1F,
    KMIP_CRYPTOALG_SHA3_256          = 0x20,
    KMIP_CRYPTOALG_SHA3_384          = 0x21,
    KMIP_CRYPTOALG_SHA3_512          = 0x22,
    KMIP_CRYPTOALG_HMAC_SHA3_224     = 0x23,
    KMIP_CRYPTOALG_HMAC_SHA3_256     = 0x24,
    KMIP_CRYPTOALG_HMAC_SHA3_384     = 0x25,
    KMIP_CRYPTOALG_HMAC_SHA3_512     = 0x26,
    KMIP_CRYPTOALG_SHAKE_128         = 0x27,
    KMIP_CRYPTOALG_SHAKE_256         = 0x28,
    /* KMIP 2.0 */
    KMIP_CRYPTOALG_ARIA              = 0x29,
    KMIP_CRYPTOALG_SEED              = 0x2A,
    KMIP_CRYPTOALG_SM2               = 0x2B,
    KMIP_CRYPTOALG_SM3               = 0x2C,
    KMIP_CRYPTOALG_SM4               = 0x2D,
    KMIP_CRYPTOALG_GOST_R_34_10_2012 = 0x2E,
    KMIP_CRYPTOALG_GOST_R_34_11_2012 = 0x2F,
    KMIP_CRYPTOALG_GOST_R_34_13_2015 = 0x30,
    KMIP_CRYPTOALG_GOST_28147_89     = 0x31,
    KMIP_CRYPTOALG_XMSS              = 0x32,
    KMIP_CRYPTOALG_SPHINCS_256       = 0x33,
    KMIP_CRYPTOALG_MCELIECE          = 0x34,
    KMIP_CRYPTOALG_MCELIECE_6960119  = 0x35,
    KMIP_CRYPTOALG_MCELIECE_8192128  = 0x36,
    KMIP_CRYPTOALG_ED25519           = 0x37,
    KMIP_CRYPTOALG_ED448             = 0x38
};

enum cryptographic_usage_mask
{
    /* KMIP 1.0 */
    KMIP_CRYPTOMASK_SIGN                = 0x00000001,
    KMIP_CRYPTOMASK_VERIFY              = 0x00000002,
    KMIP_CRYPTOMASK_ENCRYPT             = 0x00000004,
    KMIP_CRYPTOMASK_DECRYPT             = 0x00000008,
    KMIP_CRYPTOMASK_WRAP_KEY            = 0x00000010,
    KMIP_CRYPTOMASK_UNWRAP_KEY          = 0x00000020,
    KMIP_CRYPTOMASK_EXPORT              = 0x00000040,
    KMIP_CRYPTOMASK_MAC_GENERATE        = 0x00000080,
    KMIP_CRYPTOMASK_MAC_VERIFY          = 0x00000100,
    KMIP_CRYPTOMASK_DERIVE_KEY          = 0x00000200,
    KMIP_CRYPTOMASK_CONTENT_COMMITMENT  = 0x00000400,
    KMIP_CRYPTOMASK_KEY_AGREEMENT       = 0x00000800,
    KMIP_CRYPTOMASK_CERTIFICATE_SIGN    = 0x00001000,
    KMIP_CRYPTOMASK_CRL_SIGN            = 0x00002000,
    KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM = 0x00004000,
    KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM = 0x00008000,
    KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT   = 0x00010000,
    KMIP_CRYPTOMASK_TRANSLATE_DECRYPT   = 0x00020000,
    KMIP_CRYPTOMASK_TRANSLATE_WRAP      = 0x00040000,
    KMIP_CRYPTOMASK_TRANSLATE_UNWRAP    = 0x00080000,
    /* KMIP 2.0 */
    KMIP_CRYPTOMASK_AUTHENTICATE        = 0x00100000,
    KMIP_CRYPTOMASK_UNRESTRICTED        = 0x00200000,
    KMIP_CRYPTOMASK_FPE_ENCRYPT         = 0x00400000,
    KMIP_CRYPTOMASK_FPE_DECRYPT         = 0x00800000
};

enum digital_signature_algorithm
{
    /* KMIP 1.1 */
    KMIP_DIGITAL_MD2_WITH_RSA      = 0x01,
    KMIP_DIGITAL_MD5_WITH_RSA      = 0x02,
    KMIP_DIGITAL_SHA1_WITH_RSA     = 0x03,
    KMIP_DIGITAL_SHA224_WITH_RSA   = 0x04,
    KMIP_DIGITAL_SHA256_WITH_RSA   = 0x05,
    KMIP_DIGITAL_SHA384_WITH_RSA   = 0x06,
    KMIP_DIGITAL_SHA512_WITH_RSA   = 0x07,
    KMIP_DIGITAL_RSASSA_PSS        = 0x08,
    KMIP_DIGITAL_DSA_WITH_SHA1     = 0x09,
    KMIP_DIGITAL_DSA_WITH_SHA224   = 0x0A,
    KMIP_DIGITAL_DSA_WITH_SHA256   = 0x0B,
    KMIP_DIGITAL_ECDSA_WITH_SHA1   = 0x0C,
    KMIP_DIGITAL_ECDSA_WITH_SHA224 = 0x0D,
    KMIP_DIGITAL_ECDSA_WITH_SHA256 = 0x0E,
    KMIP_DIGITAL_ECDSA_WITH_SHA384 = 0x0F,
    KMIP_DIGITAL_ECDSA_WITH_SHA512 = 0x10,
    /* KMIP 1.4 */
    KMIP_DIGITAL_SHA3_256_WITH_RSA = 0x11,
    KMIP_DIGITAL_SHA3_384_WITH_RSA = 0x12,
    KMIP_DIGITAL_SHA3_512_WITH_RSA = 0x13
};

enum encoding_option
{
    /* KMIP 1.1 */
    KMIP_ENCODE_NO_ENCODING   = 0x01,
    KMIP_ENCODE_TTLV_ENCODING = 0x02
};

enum hashing_algorithm
{
    /* KMIP 1.0 */
    KMIP_HASH_MD2        = 0x01,
    KMIP_HASH_MD4        = 0x02,
    KMIP_HASH_MD5        = 0x03,
    KMIP_HASH_SHA1       = 0x04,
    KMIP_HASH_SHA224     = 0x05,
    KMIP_HASH_SHA256     = 0x06,
    KMIP_HASH_SHA384     = 0x07,
    KMIP_HASH_SHA512     = 0x08,
    KMIP_HASH_RIPEMD160  = 0x09,
    KMIP_HASH_TIGER      = 0x0A,
    KMIP_HASH_WHIRLPOOL  = 0x0B,
    /* KMIP 1.2 */
    KMIP_HASH_SHA512_224 = 0x0C,
    KMIP_HASH_SHA512_256 = 0x0D,
    /* KMIP 1.4 */
    KMIP_HASH_SHA3_224   = 0x0E,
    KMIP_HASH_SHA3_256   = 0x0F,
    KMIP_HASH_SHA3_384   = 0x10,
    KMIP_HASH_SHA3_512   = 0x11
};

enum key_compression_type
{
    /* KMIP 1.0 */
    KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED          = 0x01,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME = 0x02,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2 = 0x03,
    KMIP_KEYCOMP_EC_PUB_X962_HYBRID           = 0x04
};

enum key_format_type
{
    /* KMIP 1.0 */
    KMIP_KEYFORMAT_RAW                     = 0x01,
    KMIP_KEYFORMAT_OPAQUE                  = 0x02,
    KMIP_KEYFORMAT_PKCS1                   = 0x03,
    KMIP_KEYFORMAT_PKCS8                   = 0x04,
    KMIP_KEYFORMAT_X509                    = 0x05,
    KMIP_KEYFORMAT_EC_PRIVATE_KEY          = 0x06,
    KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY     = 0x07,
    KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY   = 0x08,
    KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY    = 0x09,
    KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY   = 0x0A,
    KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY    = 0x0B,
    KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY    = 0x0C,
    KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY     = 0x0D,
    KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY = 0x0E, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY  = 0x0F, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY  = 0x10, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY   = 0x11, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY = 0x12, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY  = 0x13, /* Deprecated as of KMIP 1.3 */
    /* KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY    = 0x14,
    KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY     = 0x15,
    /* KMIP 1.4 */
    KMIP_KEYFORMAT_PKCS12                  = 0x16,
    /* KMIP 2.0 */
    KMIP_KEYFORMAT_PKCS10                  = 0x17
};

enum key_role_type
{
    /* KMIP 1.0 */
    KMIP_ROLE_BDK      = 0x01,
    KMIP_ROLE_CVK      = 0x02,
    KMIP_ROLE_DEK      = 0x03,
    KMIP_ROLE_MKAC     = 0x04,
    KMIP_ROLE_MKSMC    = 0x05,
    KMIP_ROLE_MKSMI    = 0x06,
    KMIP_ROLE_MKDAC    = 0x07,
    KMIP_ROLE_MKDN     = 0x08,
    KMIP_ROLE_MKCP     = 0x09,
    KMIP_ROLE_MKOTH    = 0x0A,
    KMIP_ROLE_KEK      = 0x0B,
    KMIP_ROLE_MAC16609 = 0x0C,
    KMIP_ROLE_MAC97971 = 0x0D,
    KMIP_ROLE_MAC97972 = 0x0E,
    KMIP_ROLE_MAC97973 = 0x0F,
    KMIP_ROLE_MAC97974 = 0x10,
    KMIP_ROLE_MAC97975 = 0x11,
    KMIP_ROLE_ZPK      = 0x12,
    KMIP_ROLE_PVKIBM   = 0x13,
    KMIP_ROLE_PVKPVV   = 0x14,
    KMIP_ROLE_PVKOTH   = 0x15,
    /* KMIP 1.4 */
    KMIP_ROLE_DUKPT    = 0x16,
    KMIP_ROLE_IV       = 0x17,
    KMIP_ROLE_TRKBK    = 0x18
};

enum key_wrap_type
{
    /* KMIP 1.4 */
    KMIP_WRAPTYPE_NOT_WRAPPED   = 0x01,
    KMIP_WRAPTYPE_AS_REGISTERED = 0x02
};

enum kmip_version
{
    KMIP_1_0 = 0,
    KMIP_1_1 = 1,
    KMIP_1_2 = 2,
    KMIP_1_3 = 3,
    KMIP_1_4 = 4,
    KMIP_2_0 = 5
};

enum mask_generator
{
    /* KMIP 1.4 */
    KMIP_MASKGEN_MGF1 = 0x01
};

enum name_type
{
    /* KMIP 1.0 */
    KMIP_NAME_UNINTERPRETED_TEXT_STRING = 0x01,
    KMIP_NAME_URI                       = 0x02
};

enum object_type
{
    /* KMIP 1.0 */
    KMIP_OBJTYPE_CERTIFICATE         = 0x01,
    KMIP_OBJTYPE_SYMMETRIC_KEY       = 0x02,
    KMIP_OBJTYPE_PUBLIC_KEY          = 0x03,
    KMIP_OBJTYPE_PRIVATE_KEY         = 0x04,
    KMIP_OBJTYPE_SPLIT_KEY           = 0x05,
    KMIP_OBJTYPE_TEMPLATE            = 0x06, /* Deprecated as of KMIP 1.3 */
    KMIP_OBJTYPE_SECRET_DATA         = 0x07,
    KMIP_OBJTYPE_OPAQUE_OBJECT       = 0x08,
    /* KMIP 1.2 */
    KMIP_OBJTYPE_PGP_KEY             = 0x09,
    /* KMIP 2.0 */
    KMIP_OBJTYPE_CERTIFICATE_REQUEST = 0x0A
};

enum operation
{
    // # KMIP 1.0
    KMIP_OP_CREATE               = 0x01,
    KMIP_OP_CREATE_KEY_PAIR      = 0x02,
    KMIP_OP_REGISTER             = 0x03,
    KMIP_OP_REKEY                = 0x04,
    KMIP_OP_DERIVE_KEY           = 0x05,
    KMIP_OP_CERTIFY              = 0x06,
    KMIP_OP_RECERTIFY            = 0x07,
    KMIP_OP_LOCATE               = 0x08,
    KMIP_OP_CHECK                = 0x09,
    KMIP_OP_GET                  = 0x0A,
    KMIP_OP_GET_ATTRIBUTES       = 0x0B,
    KMIP_OP_GET_ATTRIBUTE_LIST   = 0x0C,
    KMIP_OP_ADD_ATTRIBUTE        = 0x0D,
    KMIP_OP_MODIFY_ATTRIBUTE     = 0x0E,
    KMIP_OP_DELETE_ATTRIBUTE     = 0x0F,
    KMIP_OP_OBTAIN_LEASE         = 0x10,
    KMIP_OP_GET_USAGE_ALLOCATION = 0x11,
    KMIP_OP_ACTIVATE             = 0x12,
    KMIP_OP_REVOKE               = 0x13,
    KMIP_OP_DESTROY              = 0x14,
    KMIP_OP_ARCHIVE              = 0x15,
    KMIP_OP_RECOVER              = 0x16,
    KMIP_OP_VALIDATE             = 0x17,
    KMIP_OP_QUERY                = 0x18,
    KMIP_OP_CANCEL               = 0x19,
    KMIP_OP_POLL                 = 0x1A,
    KMIP_OP_NOTIFY               = 0x1B,
    KMIP_OP_PUT                  = 0x1C,
    // # KMIP 1.1
    KMIP_OP_REKEY_KEY_PAIR       = 0x1D,
    KMIP_OP_DISCOVER_VERSIONS    = 0x1E,
    //# KMIP 1.2
    KMIP_OP_ENCRYPT              = 0x1F,
    KMIP_OP_DECRYPT              = 0x20,
    KMIP_OP_SIGN                 = 0x21,
    KMIP_OP_SIGNATURE_VERIFY     = 0x22,
    KMIP_OP_MAC                  = 0x23,
    KMIP_OP_MAC_VERIFY           = 0x24,
    KMIP_OP_RNG_RETRIEVE         = 0x25,
    KMIP_OP_RNG_SEED             = 0x26,
    KMIP_OP_HASH                 = 0x27,
    KMIP_OP_CREATE_SPLIT_KEY     = 0x28,
    KMIP_OP_JOIN_SPLIT_KEY       = 0x29,
    // # KMIP 1.4
    KMIP_OP_IMPORT               = 0x2A,
    KMIP_OP_EXPORT               = 0x2B,
    // # KMIP 2.0
    KMIP_OP_LOG                  = 0x2C,
    KMIP_OP_LOGIN                = 0x2D,
    KMIP_OP_LOGOUT               = 0x2E,
    KMIP_OP_DELEGATED_LOGIN      = 0x2F,
    KMIP_OP_ADJUST_ATTRIBUTE     = 0x30,
    KMIP_OP_SET_ATTRIBUTE        = 0x31,
    KMIP_OP_SET_ENDPOINT_ROLE    = 0x32,
    KMIP_OP_PKCS_11              = 0x33,
    KMIP_OP_INTEROP              = 0x34,
    KMIP_OP_REPROVISION          = 0x35,
};

enum padding_method
{
    /* KMIP 1.0 */
    KMIP_PAD_NONE      = 0x01,
    KMIP_PAD_OAEP      = 0x02,
    KMIP_PAD_PKCS5     = 0x03,
    KMIP_PAD_SSL3      = 0x04,
    KMIP_PAD_ZEROS     = 0x05,
    KMIP_PAD_ANSI_X923 = 0x06,
    KMIP_PAD_ISO_10126 = 0x07,
    KMIP_PAD_PKCS1v15  = 0x08,
    KMIP_PAD_X931      = 0x09,
    KMIP_PAD_PSS       = 0x0A
};

enum protection_storage_mask
{
    /* KMIP 2.0 */
    KMIP_PROTECT_SOFTWARE          = 0x00000001,
    KMIP_PROTECT_HARDWARE          = 0x00000002,
    KMIP_PROTECT_ON_PROCESSOR      = 0x00000004,
    KMIP_PROTECT_ON_SYSTEM         = 0x00000008,
    KMIP_PROTECT_OFF_SYSTEM        = 0x00000010,
    KMIP_PROTECT_HYPERVISOR        = 0x00000020,
    KMIP_PROTECT_OPERATING_SYSTEM  = 0x00000040,
    KMIP_PROTECT_CONTAINER         = 0x00000080,
    KMIP_PROTECT_ON_PREMISES       = 0x00000100,
    KMIP_PROTECT_OFF_PREMISES      = 0x00000200,
    KMIP_PROTECT_SELF_MANAGED      = 0x00000400,
    KMIP_PROTECT_OUTSOURCED        = 0x00000800,
    KMIP_PROTECT_VALIDATED         = 0x00001000,
    KMIP_PROTECT_SAME_JURISDICTION = 0x00002000
};

enum query_function
{
    /* KMIP 1.0 */
    KMIP_QUERY_OPERATIONS                  = 0x0001,
    KMIP_QUERY_OBJECTS                     = 0x0002,
    KMIP_QUERY_SERVER_INFORMATION          = 0x0003,
    KMIP_QUERY_APPLICATION_NAMESPACES      = 0x0004,
    /* KMIP 1.1 */
    KMIP_QUERY_EXTENSION_LIST              = 0x0005,
    KMIP_QUERY_EXTENSION_MAP               = 0x0006,
    /* KMIP 1.2 */
    KMIP_QUERY_ATTESTATION_TYPES           = 0x0007,
    /* KMIP 1.3 */
    KMIP_QUERY_RNGS                        = 0x0008,
    KMIP_QUERY_VALIDATIONS                 = 0x0009,
    KMIP_QUERY_PROFILES                    = 0x000A,
    KMIP_QUERY_CAPABILITIES                = 0x000B,
    KMIP_QUERY_CLIENT_REGISTRATION_METHODS = 0x000C,
    /* KMIP 2.0 */
    KMIP_QUERY_DEFAULTS_INFORMATION        = 0x000D,
    KMIP_QUERY_STORAGE_PROTECTION_MASKS    = 0x000E
};

enum result_reason
{
    /* KMIP 1.0 */
    KMIP_REASON_GENERAL_FAILURE                       = 0x0100,
    KMIP_REASON_ITEM_NOT_FOUND                        = 0x0001,
    KMIP_REASON_RESPONSE_TOO_LARGE                    = 0x0002,
    KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL         = 0x0003,
    KMIP_REASON_INVALID_MESSAGE                       = 0x0004,
    KMIP_REASON_OPERATION_NOT_SUPPORTED               = 0x0005,
    KMIP_REASON_MISSING_DATA                          = 0x0006,
    KMIP_REASON_INVALID_FIELD                         = 0x0007,
    KMIP_REASON_FEATURE_NOT_SUPPORTED                 = 0x0008,
    KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER       = 0x0009,
    KMIP_REASON_CRYPTOGRAPHIC_FAILURE                 = 0x000A,
    KMIP_REASON_ILLEGAL_OPERATION                     = 0x000B,
    KMIP_REASON_PERMISSION_DENIED                     = 0x000C,
    KMIP_REASON_OBJECT_ARCHIVED                       = 0x000D,
    KMIP_REASON_INDEX_OUT_OF_BOUNDS                   = 0x000E,
    KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED   = 0x000F,
    KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED         = 0x0010,
    KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED    = 0x0011,
    /* KMIP 1.1 */
    KMIP_REASON_ENCODING_OPTION_FAILURE               = 0x0012,
    /* KMIP 1.2 */
    KMIP_REASON_KEY_VALUE_NOT_PRESENT                 = 0x0013,
    KMIP_REASON_ATTESTATION_REQUIRED                  = 0x0014,
    KMIP_REASON_ATTESTATION_FAILED                    = 0x0015,
    /* KMIP 1.4 */
    KMIP_REASON_SENSITIVE                             = 0x0016,
    KMIP_REASON_NOT_EXTRACTABLE                       = 0x0017,
    KMIP_REASON_OBJECT_ALREADY_EXISTS                 = 0x0018,
    /* KMIP 2.0 */
    KMIP_REASON_INVALID_TICKET                        = 0x0019,
    KMIP_REASON_USAGE_LIMIT_EXCEEDED                  = 0x001A,
    KMIP_REASON_NUMERIC_RANGE                         = 0x001B,
    KMIP_REASON_INVALID_DATA_TYPE                     = 0x001C,
    KMIP_REASON_READ_ONLY_ATTRIBUTE                   = 0x001D,
    KMIP_REASON_MULTI_VALUED_ATTRIBUTE                = 0x001E,
    KMIP_REASON_UNSUPPORTED_ATTRIBUTE                 = 0x001F,
    KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND          = 0x0020,
    KMIP_REASON_ATTRIBUTE_NOT_FOUND                   = 0x0021,
    KMIP_REASON_ATTRIBUTE_READ_ONLY                   = 0x0022,
    KMIP_REASON_ATTRIBUTE_SINGLE_VALUED               = 0x0023,
    KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS          = 0x0024,
    KMIP_REASON_BAD_PASSWORD                          = 0x0025,
    KMIP_REASON_CODEC_ERROR                           = 0x0026,
    /* Reserved                                       = 0x0027, */
    KMIP_REASON_ILLEGAL_OBJECT_TYPE                   = 0x0028,
    KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK = 0x0029,
    KMIP_REASON_INTERNAL_SERVER_ERROR                 = 0x002A,
    KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE = 0x002B,
    KMIP_REASON_INVALID_ATTRIBUTE                      = 0x002C,
    KMIP_REASON_INVALID_ATTRIBUTE_VALUE                = 0x002D,
    KMIP_REASON_INVALID_CORRELATION_VALUE              = 0x002E,
    KMIP_REASON_INVALID_CSR                            = 0x002F,
    KMIP_REASON_INVALID_OBJECT_TYPE                    = 0x0030,
    /* Reserved                                        = 0x0031, */
    KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED            = 0x0032,
    /* Reserved                                        = 0x0033, */
    KMIP_REASON_MISSING_INITIALIZATION_VECTOR          = 0x0034,
    KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE              = 0x0035,
    KMIP_REASON_OBJECT_DESTROYED                       = 0x0036,
    KMIP_REASON_OBJECT_NOT_FOUND                       = 0x0037,
    /* Reserved                                        = 0x0038, */
    KMIP_REASON_NOT_AUTHORISED                         = 0x0039,
    KMIP_REASON_SERVER_LIMIT_EXCEEDED                  = 0x003A,
    KMIP_REASON_UNKNOWN_ENUMERATION                    = 0x003B,
    KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION              = 0x003C,
    KMIP_REASON_UNKNOWN_TAG                            = 0x003D,
    KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS   = 0x003E,
    KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION           = 0x003F,
    KMIP_REASON_WRAPPING_OBJECT_ARCHIVED               = 0x0040,
    KMIP_REASON_WRAPPING_OBJECT_DESTROYED              = 0x0041,
    KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND              = 0x0042,
    KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE              = 0x0043,
    KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE         = 0x0044,
    KMIP_REASON_PKCS11_CODEC_ERROR                     = 0x0045,
    KMIP_REASON_PKCS11_INVALID_FUNCTION                = 0x0046,
    KMIP_REASON_PKCS11_INVALID_INTERFACE               = 0x0047,
    KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE = 0x0048,
    KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE  = 0x0049
};

enum result_status
{
    /* KMIP 1.0 */
    KMIP_STATUS_SUCCESS           = 0x00,
    KMIP_STATUS_OPERATION_FAILED  = 0x01,
    KMIP_STATUS_OPERATION_PENDING = 0x02,
    KMIP_STATUS_OPERATION_UNDONE  = 0x03
};

enum state
{
    /* KMIP 1.0 */
    KMIP_STATE_PRE_ACTIVE            = 0x01,
    KMIP_STATE_ACTIVE                = 0x02,
    KMIP_STATE_DEACTIVATED           = 0x03,
    KMIP_STATE_COMPROMISED           = 0x04,
    KMIP_STATE_DESTROYED             = 0x05,
    KMIP_STATE_DESTROYED_COMPROMISED = 0x06
};

enum tag
{
    KMIP_TAG_TAG                              = 0x000000,
    KMIP_TAG_TYPE                             = 0x000001,
    KMIP_TAG_DEFAULT                          = 0x420000,
    /* KMIP 1.0 */
    KMIP_TAG_ACTIVATION_DATE                  = 0x420001,
    KMIP_TAG_APPLICATION_DATA                 = 0x420002,
    KMIP_TAG_APPLICATION_NAMESPACE            = 0x420003,
    KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION = 0x420004,
    KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE   = 0x420006,
    KMIP_TAG_ASYNCHRONOUS_INDICATOR           = 0x420007,
    KMIP_TAG_ATTRIBUTE                        = 0x420008,
    KMIP_TAG_ATTRIBUTE_INDEX                  = 0x420009,
    KMIP_TAG_ATTRIBUTE_NAME                   = 0x42000A,
    KMIP_TAG_ATTRIBUTE_VALUE                  = 0x42000B,
    KMIP_TAG_AUTHENTICATION                   = 0x42000C,
    KMIP_TAG_BATCH_COUNT                      = 0x42000D,
    KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION  = 0x42000E,
    KMIP_TAG_BATCH_ITEM                       = 0x42000F,
    KMIP_TAG_BATCH_ORDER_OPTION               = 0x420010,
    KMIP_TAG_BLOCK_CIPHER_MODE                = 0x420011,
    KMIP_TAG_CREDENTIAL                       = 0x420023,
    KMIP_TAG_CREDENTIAL_TYPE                  = 0x420024,
    KMIP_TAG_CREDENTIAL_VALUE                 = 0x420025,
    KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM          = 0x420028,
    KMIP_TAG_CRYPTOGRAPHIC_LENGTH             = 0x42002A,
    KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS         = 0x42002B,
    KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK         = 0x42002C,
    KMIP_TAG_DEACTIVATION_DATE                = 0x42002F,
    KMIP_TAG_ENCRYPTION_KEY_INFORMATION       = 0x420036,
    KMIP_TAG_HASHING_ALGORITHM                = 0x420038,
    KMIP_TAG_IV_COUNTER_NONCE                 = 0x42003D,
    KMIP_TAG_KEY                              = 0x42003F,
    KMIP_TAG_KEY_BLOCK                        = 0x420040,
    KMIP_TAG_KEY_COMPRESSION_TYPE             = 0x420041,
    KMIP_TAG_KEY_FORMAT_TYPE                  = 0x420042,
    KMIP_TAG_KEY_MATERIAL                     = 0x420043,
    KMIP_TAG_KEY_VALUE                        = 0x420045,
    KMIP_TAG_KEY_WRAPPING_DATA                = 0x420046,
    KMIP_TAG_KEY_WRAPPING_SPECIFICATION       = 0x420047,
    KMIP_TAG_MAC_SIGNATURE                    = 0x42004D,
    KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION    = 0x42004E,
    KMIP_TAG_MAXIMUM_ITEMS                    = 0x42004F,
    KMIP_TAG_MAXIMUM_RESPONSE_SIZE            = 0x420050,
    KMIP_TAG_NAME                             = 0x420053,
    KMIP_TAG_NAME_TYPE                        = 0x420054,
    KMIP_TAG_NAME_VALUE                       = 0x420055,
    KMIP_TAG_OBJECT_GROUP                     = 0x420056,
    KMIP_TAG_OBJECT_TYPE                      = 0x420057,
    KMIP_TAG_OPERATION                        = 0x42005C,
    KMIP_TAG_OPERATION_POLICY_NAME            = 0x42005D,
    KMIP_TAG_PADDING_METHOD                   = 0x42005F,
    KMIP_TAG_PRIVATE_KEY                      = 0x420064,
    KMIP_TAG_PROCESS_START_DATE               = 0x420067,
    KMIP_TAG_PROTECT_STOP_DATE                = 0x420068,
    KMIP_TAG_PROTOCOL_VERSION                 = 0x420069,
    KMIP_TAG_PROTOCOL_VERSION_MAJOR           = 0x42006A,
    KMIP_TAG_PROTOCOL_VERSION_MINOR           = 0x42006B,
    KMIP_TAG_PUBLIC_KEY                       = 0x42006D,
    KMIP_TAG_QUERY_FUNCTION                   = 0x420074,
    KMIP_TAG_REQUEST_HEADER                   = 0x420077,
    KMIP_TAG_REQUEST_MESSAGE                  = 0x420078,
    KMIP_TAG_REQUEST_PAYLOAD                  = 0x420079,
    KMIP_TAG_RESPONSE_HEADER                  = 0x42007A,
    KMIP_TAG_RESPONSE_MESSAGE                 = 0x42007B,
    KMIP_TAG_RESPONSE_PAYLOAD                 = 0x42007C,
    KMIP_TAG_RESULT_MESSAGE                   = 0x42007D,
    KMIP_TAG_RESULT_REASON                    = 0x42007E,
    KMIP_TAG_RESULT_STATUS                    = 0x42007F,
    KMIP_TAG_KEY_ROLE_TYPE                    = 0x420083,
    KMIP_TAG_SERVER_INFORMATION               = 0x420088,
    KMIP_TAG_STATE                            = 0x42008D,
    KMIP_TAG_STORAGE_STATUS_MASK              = 0x42008E,
    KMIP_TAG_SYMMETRIC_KEY                    = 0x42008F,
    KMIP_TAG_TEMPLATE_ATTRIBUTE               = 0x420091,
    KMIP_TAG_TIME_STAMP                       = 0x420092,
    KMIP_TAG_UNIQUE_BATCH_ITEM_ID             = 0x420093,
    KMIP_TAG_UNIQUE_IDENTIFIER                = 0x420094,
    KMIP_TAG_USERNAME                         = 0x420099,
    KMIP_TAG_VENDOR_IDENTIFICATION            = 0x42009D,
    KMIP_TAG_WRAPPING_METHOD                  = 0x42009E,
    KMIP_TAG_PASSWORD                         = 0x4200A1,
    /* KMIP 1.1 */
    KMIP_TAG_DEVICE_IDENTIFIER                = 0x4200A2,
    KMIP_TAG_ENCODING_OPTION                  = 0x4200A3,
    KMIP_TAG_MACHINE_IDENTIFIER               = 0x4200A9,
    KMIP_TAG_MEDIA_IDENTIFIER                 = 0x4200AA,
    KMIP_TAG_NETWORK_IDENTIFIER               = 0x4200AB,
    KMIP_TAG_OBJECT_GROUP_MEMBER              = 0x4200AC,
    KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM      = 0x4200AE,
    KMIP_TAG_DEVICE_SERIAL_NUMBER             = 0x4200B0,
    /* KMIP 1.2 */
    KMIP_TAG_RANDOM_IV                        = 0x4200C5,
    KMIP_TAG_ATTESTATION_TYPE                 = 0x4200C7,
    KMIP_TAG_NONCE                            = 0x4200C8,
    KMIP_TAG_NONCE_ID                         = 0x4200C9,
    KMIP_TAG_NONCE_VALUE                      = 0x4200CA,
    KMIP_TAG_ATTESTATION_MEASUREMENT          = 0x4200CB,
    KMIP_TAG_ATTESTATION_ASSERTION            = 0x4200CC,
    KMIP_TAG_IV_LENGTH                        = 0x4200CD,
    KMIP_TAG_TAG_LENGTH                       = 0x4200CE,
    KMIP_TAG_FIXED_FIELD_LENGTH               = 0x4200CF,
    KMIP_TAG_COUNTER_LENGTH                   = 0x4200D0,
    KMIP_TAG_INITIAL_COUNTER_VALUE            = 0x4200D1,
    KMIP_TAG_INVOCATION_FIELD_LENGTH          = 0x4200D2,
    KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR    = 0x4200D3,
    KMIP_TAG_OFFSET_ITEMS                     = 0x4200D4,
    KMIP_TAG_LOCATED_ITEMS                    = 0x4200D5,
    /* KMIP 1.4 */
    KMIP_TAG_KEY_WRAP_TYPE                    = 0x4200F8,
    KMIP_TAG_SALT_LENGTH                      = 0x420100,
    KMIP_TAG_MASK_GENERATOR                   = 0x420101,
    KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM = 0x420102,
    KMIP_TAG_P_SOURCE                         = 0x420103,
    KMIP_TAG_TRAILER_FIELD                    = 0x420104,
    KMIP_TAG_CLIENT_CORRELATION_VALUE         = 0x420105,
    KMIP_TAG_SERVER_CORRELATION_VALUE         = 0x420106,
    /* KMIP 2.0 */
    KMIP_TAG_ATTRIBUTES                       = 0x420125,
    KMIP_TAG_SERVER_NAME                      = 0x42012D,
    KMIP_TAG_SERVER_SERIAL_NUMBER             = 0x42012E,
    KMIP_TAG_SERVER_VERSION                   = 0x42012F,
    KMIP_TAG_SERVER_LOAD                      = 0x420130,
    KMIP_TAG_PRODUCT_NAME                     = 0x420131,
    KMIP_TAG_BUILD_LEVEL                      = 0x420132,
    KMIP_TAG_BUILD_DATE                       = 0x420133,
    KMIP_TAG_CLUSTER_INFO                     = 0x420134,
    KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS     = 0x420135,
    KMIP_TAG_EPHEMERAL                        = 0x420154,
    KMIP_TAG_SERVER_HASHED_PASSWORD           = 0x420155,
    KMIP_TAG_PROTECTION_STORAGE_MASK          = 0x42015E,
    KMIP_TAG_PROTECTION_STORAGE_MASKS         = 0x42015F,
    KMIP_TAG_COMMON_PROTECTION_STORAGE_MASKS  = 0x420163,
    KMIP_TAG_PRIVATE_PROTECTION_STORAGE_MASKS = 0x420164,
    KMIP_TAG_PUBLIC_PROTECTION_STORAGE_MASKS  = 0x420165
};

enum type
{
    /* KMIP 1.0 */
    KMIP_TYPE_STRUCTURE          = 0x01,
    KMIP_TYPE_INTEGER            = 0x02,
    KMIP_TYPE_LONG_INTEGER       = 0x03,
    KMIP_TYPE_BIG_INTEGER        = 0x04,
    KMIP_TYPE_ENUMERATION        = 0x05,
    KMIP_TYPE_BOOLEAN            = 0x06,
    KMIP_TYPE_TEXT_STRING        = 0x07,
    KMIP_TYPE_BYTE_STRING        = 0x08,
    KMIP_TYPE_DATE_TIME          = 0x09,
    KMIP_TYPE_INTERVAL           = 0x0A,
    /* KMIP 2.0 */
    KMIP_TYPE_DATE_TIME_EXTENDED = 0x0B
};

enum wrapping_method
{
    /* KMIP 1.0 */
    KMIP_WRAP_ENCRYPT          = 0x01,
    KMIP_WRAP_MAC_SIGN         = 0x02,
    KMIP_WRAP_ENCRYPT_MAC_SIGN = 0x03,
    KMIP_WRAP_MAC_SIGN_ENCRYPT = 0x04,
    KMIP_WRAP_TR31             = 0x05
};

/*
Structures
*/

typedef struct linked_list_item
{
    struct linked_list_item *next;
    struct linked_list_item *prev;
    
    void *data;
} LinkedListItem;

typedef struct linked_list
{
    LinkedListItem *head;
    LinkedListItem *tail;

    size_t size;
} LinkedList;

typedef struct text_string
{
    char *value;
    size_t size;
} TextString;

typedef struct byte_string
{
    uint8 *value;
    size_t size;
} ByteString;

typedef struct error_frame
{
    char function[100];
    int line;
} ErrorFrame;

typedef struct kmip
{
    /* Encoding buffer */
    uint8 *buffer;
    uint8 *index;
    size_t size;
    
    /* KMIP message settings */
    enum kmip_version version;
    int max_message_size;
    LinkedList *credential_list;
    
    /* Error handling information */
    char *error_message;
    size_t error_message_size;
    /* TODO (ph) Switch the following to a LinkedList. */
    ErrorFrame errors[20];
    size_t error_frame_count;
    struct error_frame *frame_index;
    
    /* Memory management function pointers */
    void *(*calloc_func)(void *state, size_t num, size_t size);
    void *(*realloc_func)(void *state, void *ptr, size_t size);
    void (*free_func)(void *state, void *ptr);
    void *(*memcpy_func)(void *state, void *destination, const void* source, size_t size);
    void *(*memset_func)(void *ptr, int value, size_t size);
    void *state;
} KMIP;

typedef struct application_specific_information
{
    TextString *application_namespace;
    TextString *application_data;
} ApplicationSpecificInformation;

typedef struct attribute
{
    enum attribute_type type;
    int32 index;
    void *value;
} Attribute;

typedef struct attributes
{
    LinkedList *attribute_list;
} Attributes;

typedef struct name
{
    struct text_string *value;
    enum name_type type;
} Name;

typedef struct template_attribute
{
    /* TODO (ph) Change these to linked lists */
    Name *names;
    size_t name_count;
    Attribute *attributes;
    size_t attribute_count;
} TemplateAttribute;

typedef struct protocol_version
{
    int32 major;
    int32 minor;
} ProtocolVersion;

typedef struct protection_storage_masks
{
    /* KMIP 2.0 */
    LinkedList *masks;
} ProtectionStorageMasks;

typedef struct cryptographic_parameters
{
    /* KMIP 1.0 */
    enum block_cipher_mode block_cipher_mode;
    enum padding_method padding_method;
    enum hashing_algorithm hashing_algorithm;
    enum key_role_type key_role_type;
    /* KMIP 1.2 */
    enum digital_signature_algorithm digital_signature_algorithm;
    enum cryptographic_algorithm cryptographic_algorithm;
    bool32 random_iv;
    int32 iv_length;
    int32 tag_length;
    int32 fixed_field_length;
    int32 invocation_field_length;
    int32 counter_length;
    int32 initial_counter_value;
    /* KMIP 1.4 */
    int32 salt_length;
    enum mask_generator mask_generator;
    enum hashing_algorithm mask_generator_hashing_algorithm;
    ByteString *p_source;
    int32 trailer_field;
} CryptographicParameters;

typedef struct encryption_key_information
{
    TextString *unique_identifier;
    CryptographicParameters *cryptographic_parameters;
} EncryptionKeyInformation;

typedef struct mac_signature_key_information
{
    TextString *unique_identifier;
    CryptographicParameters *cryptographic_parameters;
} MACSignatureKeyInformation;

typedef struct key_wrapping_data
{
    /* KMIP 1.0 */
    enum wrapping_method wrapping_method;
    EncryptionKeyInformation *encryption_key_info;
    MACSignatureKeyInformation *mac_signature_key_info;
    ByteString *mac_signature;
    ByteString *iv_counter_nonce;
    /* KMIP 1.1 */
    enum encoding_option encoding_option;
} KeyWrappingData;

typedef struct transparent_symmetric_key
{
    ByteString *key;
} TransparentSymmetricKey;

typedef struct key_value
{
    void *key_material;
    /* TODO (ph) Change this to a linked list */
    Attribute *attributes;
    size_t attribute_count;
} KeyValue;

typedef struct key_block
{
    enum key_format_type key_format_type;
    enum key_compression_type key_compression_type;
    void *key_value;
    enum type key_value_type;
    enum cryptographic_algorithm cryptographic_algorithm;
    int32 cryptographic_length;
    KeyWrappingData *key_wrapping_data;
} KeyBlock;

typedef struct symmetric_key
{
    KeyBlock *key_block;
} SymmetricKey;

typedef struct public_key
{
    KeyBlock *key_block;
} PublicKey;

typedef struct private_key
{
    KeyBlock *key_block;
} PrivateKey;

typedef struct key_wrapping_specification
{
    /* KMIP 1.0 */
    enum wrapping_method wrapping_method;
    EncryptionKeyInformation *encryption_key_info;
    MACSignatureKeyInformation *mac_signature_key_info;
    /* TODO (ph) Change this to a linked list */
    TextString *attribute_names;
    size_t attribute_name_count;
    /* KMIP 1.1 */
    enum encoding_option encoding_option;
} KeyWrappingSpecification;

typedef struct nonce
{
    ByteString *nonce_id;
    ByteString *nonce_value;
} Nonce;

/* Operation Payloads */

typedef struct create_request_payload
{
    /* KMIP 1.0 */
    enum object_type object_type;
    TemplateAttribute *template_attribute;
    /* KMIP 2.0 */
    Attributes *attributes;
    ProtectionStorageMasks *protection_storage_masks;
} CreateRequestPayload;

typedef struct register_request_payload
{
    /* KMIP 1.0 */
    enum object_type object_type; // both
    TemplateAttribute *template_attribute;
    /* KMIP 2.0 */
    Attributes *attributes;
    ProtectionStorageMasks *protection_storage_masks;
    // TODO: data could be many things. But we only care about symmetric keys
    SymmetricKey object; // both 1.0 and 2.0
} RegisterRequestPayload;

typedef struct register_response_payload
{
    /* KMIP 1.0 */
    TextString *unique_identifier;
    TemplateAttribute *template_attribute;
} RegisterResponsePayload;

typedef struct create_response_payload
{
    /* KMIP 1.0 */
    enum object_type object_type;
    TextString *unique_identifier;
    TemplateAttribute *template_attribute;
} CreateResponsePayload;

typedef struct get_request_payload
{
    /* KMIP 1.0 */
    TextString *unique_identifier;
    enum key_format_type key_format_type;
    enum key_compression_type key_compression_type;
    KeyWrappingSpecification *key_wrapping_spec;
    /* KMIP 1.4 */
    enum key_wrap_type key_wrap_type;
} GetRequestPayload;

typedef struct get_response_payload
{
    enum object_type object_type;
    TextString *unique_identifier;
    void *object;
} GetResponsePayload;

typedef struct get_attribute_request_payload
{
    /* KMIP 1.0 */
    TextString *unique_identifier;
    TextString *attribute_name;
} GetAttributeRequestPayload;

typedef struct get_attribute_response_payload
{
    TextString *unique_identifier;
    Attribute *attribute;
    void *object;
} GetAttributeResponsePayload;

typedef struct destroy_request_payload
{
    TextString *unique_identifier;
} DestroyRequestPayload;

typedef struct destroy_response_payload
{
    TextString *unique_identifier;
} DestroyResponsePayload;

/* Authentication Structures */

typedef struct credential
{
    enum credential_type credential_type;
    void *credential_value;
} Credential;

typedef struct username_password_credential
{
    TextString *username;
    TextString *password;
} UsernamePasswordCredential;

typedef struct device_credential
{
    TextString *device_serial_number;
    TextString *password;
    TextString *device_identifier;
    TextString *network_identifier;
    TextString *machine_identifier;
    TextString *media_identifier;
} DeviceCredential;

typedef struct attestation_credential
{
    Nonce *nonce;
    enum attestation_type attestation_type;
    ByteString *attestation_measurement;
    ByteString *attestation_assertion;
} AttestationCredential;

typedef struct authentication
{
    /* NOTE (ph) KMIP 1.2+ supports multiple credentials here. */
    /* NOTE (ph) Polymorphism makes this tricky. Omitting for now. */
    /* TODO (ph) Credential structs are constant size, so no problem here. */
    /* TODO (ph) Change this to a linked list */
    Credential *credential;
} Authentication;

/* Message Structures */

typedef struct request_header
{
    /* KMIP 1.0 */
    ProtocolVersion *protocol_version;
    int32 maximum_response_size;
    bool32 asynchronous_indicator;
    Authentication *authentication;
    enum batch_error_continuation_option batch_error_continuation_option;
    bool32 batch_order_option;
    int64 time_stamp;
    int32 batch_count;
    /* KMIP 1.2 */
    bool32 attestation_capable_indicator;
    enum attestation_type *attestation_types;
    size_t attestation_type_count;
    /* KMIP 1.4 */
    TextString *client_correlation_value;
    TextString *server_correlation_value;
} RequestHeader;

typedef struct response_header
{
    /* KMIP 1.0 */
    ProtocolVersion *protocol_version;
    int64 time_stamp;
    int32 batch_count;
    /* KMIP 1.2 */
    Nonce *nonce;
    /* TODO (ph) Change this to a linked list */
    enum attestation_type *attestation_types;
    size_t attestation_type_count;
    /* KMIP 1.4 */
    TextString *client_correlation_value;
    TextString *server_correlation_value;
    /* KMIP 2.0 */
    ByteString *server_hashed_password;
} ResponseHeader;

typedef struct request_batch_item
{
    /* KMIP 1.0 */
    enum operation operation;
    ByteString *unique_batch_item_id;
    void *request_payload;
    /* KMIP 2.0 */
    bool32 ephemeral;
    /* NOTE (ph) Omitting the message extension field for now. */
} RequestBatchItem;

typedef struct response_batch_item
{
    enum operation operation;
    ByteString *unique_batch_item_id;
    enum result_status result_status;
    enum result_reason result_reason;
    TextString *result_message;
    ByteString *asynchronous_correlation_value;
    void *response_payload;
    /* NOTE (ph) Omitting the message extension field for now. */
} ResponseBatchItem;

typedef struct request_message
{
    RequestHeader *request_header;
    /* TODO (ph) Change this to a linked list */
    RequestBatchItem *batch_items;
    size_t batch_count;
} RequestMessage;

typedef struct response_message
{
    ResponseHeader *response_header;
    /* TODO (ph) Change this to a linked list */
    ResponseBatchItem *batch_items;
    size_t batch_count;
} ResponseMessage;

typedef struct functions
{
    LinkedList *function_list;
} Functions;

typedef struct operations
{
    LinkedList *operation_list;
} Operations;

typedef struct object_types
{
    LinkedList *object_list;
} ObjectTypes;

typedef struct alternative_endpoints
{
    LinkedList *endpoint_list;
} AltEndpoints;

typedef struct server_information
{
    TextString* server_name;
    TextString* server_serial_number;
    TextString* server_version;
    TextString* server_load;
    TextString* product_name;
    TextString* build_level;
    TextString* build_date;
    TextString* cluster_info;
    AltEndpoints* alternative_failover_endpoints;
    // Vendor-Specific               Any, MAY be repeated
} ServerInformation;


/*
typedef struct application_namespaces
{
    LinkedList *app_namespace_list;
} ApplicationNamespaces;
*/

typedef struct query_request_payload
{
    Functions* functions;
} QueryRequestPayload;

typedef struct query_response_payload
{
    Operations*             operations;              // Specifies an Operation that is supported by the server.
    ObjectTypes*            objects;                 // Specifies a Managed Object Type that is supported by the server.
    TextString*             vendor_identification;   // SHALL be returned if Query Server Information is requested. The Vendor Identification SHALL be a text string that uniquely identifies the vendor.
    ServerInformation*      server_information;      // Contains vendor-specific information possibly be of interest to the client.
 // ApplicationNamespaces*  application_namespaces;  // Specifies an Application Namespace supported by the server.
 // Extension Information         No, MAY be repeated  // SHALL be returned if Query Extension List or Query Extension Map is requested and supported by the server.
 // Attestation Type              No, MAY be repeated  // Specifies an Attestation Type that is supported by the server.
 // RNG Parameters                No, MAY be repeated  // Specifies the RNG that is supported by the server.
 // Profile Information           No, MAY be repeated  // Specifies the Profiles that are supported by the server.
 // Validation Information        No, MAY be repeated  // Specifies the validations that are supported by the server.
 // Capability Information        No, MAY be repeated  // Specifies the capabilities that are supported by the server.
 // Client Registration Method    No, MAY be repeated  // Specifies a Client Registration Method that is supported by the server.
 // Defaults Information          No                   // Specifies the defaults that the server will use if the client omits them.
 // Protection Storage Masks      Yes                  // Specifies the list of Protection Storage Mask values supported by the server. A server MAY elect to provide an empty list in the Response if it is unable or unwilling to provide this information.
} QueryResponsePayload;


#define MAX_QUERY_LEN    128
#define MAX_QUERY_OPS   0x40
#define MAX_QUERY_OBJS  0x20

typedef struct query_response
{
    size_t           operations_size;
    int              operations[MAX_QUERY_OPS];
    size_t           objects_size;
    int              objects[MAX_QUERY_OBJS];
    char             vendor_identification[MAX_QUERY_LEN];
    bool32           server_information_valid;
    char             server_name[MAX_QUERY_LEN];
    char             server_serial_number[MAX_QUERY_LEN];
    char             server_version[MAX_QUERY_LEN];
    char             server_load[MAX_QUERY_LEN];
    char             product_name[MAX_QUERY_LEN];
    char             build_level[MAX_QUERY_LEN];
    char             build_date[MAX_QUERY_LEN];
    char             cluster_info[MAX_QUERY_LEN];
} QueryResponse;

/*
Macros
*/

#define ARRAY_LENGTH(A) (sizeof((A)) / sizeof((A)[0]))

#define BUFFER_BYTES_LEFT(A) ((A)->size - ((A)->index - (A)->buffer))

#define CHECK_BUFFER_FULL(A, B) CHECK_BUFFER_SIZE((A), (B), KMIP_ERROR_BUFFER_FULL)

#define CHECK_BUFFER_SIZE(A, B, C)                      \
do                                                      \
{                                                       \
    if(BUFFER_BYTES_LEFT(A) < (B))                      \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return((C));                                    \
    }                                                   \
} while(0)

#define CHECK_RESULT(A, B)                              \
do                                                      \
{                                                       \
    if((B) != KMIP_OK)                                  \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return((B));                                    \
    }                                                   \
} while(0)

#define HANDLE_FAILURE(A, B)                        \
do                                                  \
{                                                   \
    kmip_push_error_frame((A), __func__, __LINE__); \
    return((B));                                    \
} while(0)

#define TAG_TYPE(A, B) (((A) << 8) | (uint8)(B))

#define CHECK_TAG_TYPE(A, B, C, D)                      \
do                                                      \
{                                                       \
    if((int32)((B) >> 8) != (int32)(C))                 \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_TAG_MISMATCH);                      \
    }                                                   \
    else if((int32)((B) & 0x000000FF) != (int32)(D))    \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_TYPE_MISMATCH);                     \
    }                                                   \
} while(0)

#define CHECK_LENGTH(A, B, C)                           \
do                                                      \
{                                                       \
    if((B) != (C))                                      \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_LENGTH_MISMATCH);                   \
    }                                                   \
} while(0)

#define CHECK_PADDING(A, B)                             \
do                                                      \
{                                                       \
    if((B) != 0)                                        \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_PADDING_MISMATCH);                  \
    }                                                   \
} while(0)

#define CHECK_BOOLEAN(A, B)                             \
do                                                      \
{                                                       \
    if(((B) != KMIP_TRUE) && ((B) != KMIP_FALSE))       \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_BOOLEAN_MISMATCH);                  \
    }                                                   \
} while(0)

#define CHECK_ENUM(A, B, C)                                     \
do                                                              \
{                                                               \
    int result = kmip_check_enum_value((A)->version, (B), (C)); \
    if(result != KMIP_OK)                                       \
    {                                                           \
        kmip_set_enum_error_message((A), (B), (C), result);     \
        kmip_push_error_frame((A), __func__, __LINE__);         \
        return(result);                                         \
    }                                                           \
} while(0)

#define CHECK_NEW_MEMORY(A, B, C, D)                    \
do                                                      \
{                                                       \
    if((B) == NULL)                                     \
    {                                                   \
        kmip_set_alloc_error_message((A), (C), (D));    \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_MEMORY_ALLOC_FAILED);               \
    }                                                   \
} while(0)

#define HANDLE_FAILED_ALLOC(A, B, C)                \
do                                                  \
{                                                   \
    kmip_set_alloc_error_message((A), (B), (C));    \
    kmip_push_error_frame((A), __func__, __LINE__); \
    return(KMIP_MEMORY_ALLOC_FAILED);               \
} while(0)

#define CHECK_ENCODE_ARGS(A, B)   \
do                                \
{                                 \
    if((A) == NULL)               \
    {                             \
        return(KMIP_ARG_INVALID); \
    }                             \
    if((B) == NULL)               \
    {                             \
        return(KMIP_OK);          \
    }                             \
} while(0)

#define CHECK_DECODE_ARGS(A, B)    \
do                                 \
{                                  \
    if((A) == NULL || (B) == NULL) \
    {                              \
        return(KMIP_ARG_INVALID);  \
    }                              \
} while(0)

#define CHECK_KMIP_VERSION(A, B)                        \
do                                                      \
{                                                       \
    if((A)->version < (B))                              \
    {                                                   \
        kmip_push_error_frame((A), __func__, __LINE__); \
        return(KMIP_INVALID_FOR_VERSION);               \
    }                                                   \
} while(0)

#define CALCULATE_PADDING(A) ((8 - ((A) % 8)) % 8)

/*
Miscellaneous Utilities
*/

size_t kmip_strnlen_s(const char *, size_t);
LinkedListItem *kmip_linked_list_pop(LinkedList *);
void kmip_linked_list_push(LinkedList *, LinkedListItem *);
void kmip_linked_list_enqueue(LinkedList *, LinkedListItem *);

/*
Memory Handlers
*/

void *kmip_calloc(void *, size_t, size_t);
void *kmip_realloc(void *, void *, size_t);
void kmip_free(void *, void *);
void *kmip_memcpy(void *, void *, const void *, size_t);

/*
Enumeration Utilities
*/

int kmip_get_enum_string_index(enum tag);
int kmip_check_enum_value(enum kmip_version, enum tag, int);

/*
Context Utilities
*/

void kmip_clear_errors(KMIP *);
void kmip_init(KMIP *, void *, size_t, enum kmip_version);
void kmip_init_error_message(KMIP *);
int kmip_add_credential(KMIP *, Credential *);
void kmip_remove_credentials(KMIP *);
void kmip_reset(KMIP *);
void kmip_rewind(KMIP *);
void kmip_set_buffer(KMIP *, void *, size_t);
void kmip_destroy(KMIP *);
void kmip_push_error_frame(KMIP *, const char *, const int);
void kmip_set_enum_error_message(KMIP *, enum tag, int, int);
void kmip_set_alloc_error_message(KMIP *, size_t, const char *);
void kmip_set_error_message(KMIP *, const char *);
int kmip_is_tag_next(const KMIP *, enum tag);
int kmip_is_tag_type_next(const KMIP *, enum tag, enum type);
size_t kmip_get_num_items_next(KMIP *, enum tag);
uint32 kmip_peek_tag(KMIP *);
int kmip_is_attribute_tag(uint32);

/*
Initialization Functions
*/

void kmip_init_application_specific_information(ApplicationSpecificInformation *);
void kmip_init_protocol_version(ProtocolVersion *, enum kmip_version);
void kmip_init_attribute(Attribute *);
void kmip_init_cryptographic_parameters(CryptographicParameters *);
void kmip_init_key_block(KeyBlock *);
void kmip_init_request_header(RequestHeader *);
void kmip_init_response_header(ResponseHeader *);
void kmip_init_request_batch_item(RequestBatchItem *);

/*
Printing Functions
*/

void kmip_print_buffer(FILE *, void *, int);
void kmip_print_stack_trace(FILE *, KMIP *);
void kmip_print_error_string(FILE *, int);
void kmip_print_batch_error_continuation_option(FILE *, enum batch_error_continuation_option);
void kmip_print_operation_enum(FILE *, enum operation);
void kmip_print_result_status_enum(FILE *, enum result_status);
void kmip_print_result_reason_enum(FILE *, enum result_reason);
void kmip_print_object_type_enum(FILE *, enum object_type);
void kmip_print_key_format_type_enum(FILE *, enum key_format_type);
void kmip_print_key_compression_type_enum(FILE *, enum key_compression_type);
void kmip_print_cryptographic_algorithm_enum(FILE *, enum cryptographic_algorithm);
void kmip_print_name_type_enum(FILE *, enum name_type);
void kmip_print_attribute_type_enum(FILE *, enum attribute_type);
void kmip_print_state_enum(FILE *, enum state);
void kmip_print_block_cipher_mode_enum(FILE *, enum block_cipher_mode);
void kmip_print_padding_method_enum(FILE *, enum padding_method);
void kmip_print_hashing_algorithm_enum(FILE *, enum hashing_algorithm);
void kmip_print_key_role_type_enum(FILE *, enum key_role_type);
void kmip_print_digital_signature_algorithm_enum(FILE *, enum digital_signature_algorithm);
void kmip_print_mask_generator_enum(FILE *, enum mask_generator);
void kmip_print_wrapping_method_enum(FILE *, enum wrapping_method);
void kmip_print_encoding_option_enum(FILE *, enum encoding_option);
void kmip_print_key_wrap_type_enum(FILE *, enum key_wrap_type);
void kmip_print_credential_type_enum(FILE *, enum credential_type);
void kmip_print_cryptographic_usage_mask_enums(FILE *, int, int32);
void kmip_print_integer(FILE *, int32);
void kmip_print_bool(FILE *, int32);
void kmip_print_text_string(FILE *, int, const char *, TextString *);
void kmip_print_byte_string(FILE *, int, const char *, ByteString *);
void kmip_print_date_time(FILE *, int64);
void kmip_print_protocol_version(FILE *, int, ProtocolVersion *);
void kmip_print_name(FILE *, int, Name *);
void kmip_print_nonce(FILE *, int, Nonce *);
void kmip_print_protection_storage_masks_enum(FILE *, int, int32);
void kmip_print_protection_storage_masks(FILE *, int, ProtectionStorageMasks *);
void kmip_print_application_specific_information(FILE *, int, ApplicationSpecificInformation *);
void kmip_print_cryptographic_parameters(FILE *, int, CryptographicParameters *);
void kmip_print_encryption_key_information(FILE *, int, EncryptionKeyInformation *);
void kmip_print_mac_signature_key_information(FILE *, int, MACSignatureKeyInformation *);
void kmip_print_key_wrapping_data(FILE *, int, KeyWrappingData *);
void kmip_print_attribute_value(FILE *, int, enum attribute_type, void *);
void kmip_print_attribute(FILE *, int, Attribute *);
void kmip_print_attributes(FILE *, int, Attributes *);
void kmip_print_key_material(FILE *, int, enum key_format_type, void *);
void kmip_print_key_value(FILE *, int, enum type, enum key_format_type, void *);
void kmip_print_key_block(FILE *, int, KeyBlock *);
void kmip_print_symmetric_key(FILE *, int, SymmetricKey *);
void kmip_print_object(FILE *, int, enum object_type, void *);
void kmip_print_key_wrapping_specification(FILE *, int, KeyWrappingSpecification *);
void kmip_print_template_attribute(FILE *, int, TemplateAttribute *);
void kmip_print_create_request_payload(FILE *, int, CreateRequestPayload *);
void kmip_print_create_response_payload(FILE *, int, CreateResponsePayload *);
void kmip_print_get_request_payload(FILE *, int, GetRequestPayload *);
void kmip_print_get_response_payload(FILE *, int, GetResponsePayload *);
void kmip_print_destroy_request_payload(FILE *, int, DestroyRequestPayload *);
void kmip_print_destroy_response_payload(FILE *, int, DestroyResponsePayload *);
void kmip_print_request_payload(FILE *, int, enum operation, void *);
void kmip_print_response_payload(FILE *, int, enum operation, void *);
void kmip_print_username_password_credential(FILE *, int, UsernamePasswordCredential *);
void kmip_print_device_credential(FILE *, int, DeviceCredential *);
void kmip_print_attestation_credential(FILE *, int, AttestationCredential *);
void kmip_print_credential_value(FILE *, int, enum credential_type, void *);
void kmip_print_credential(FILE *, int, Credential *);
void kmip_print_authentication(FILE *, int, Authentication *);
void kmip_print_request_batch_item(FILE *, int, RequestBatchItem *);
void kmip_print_response_batch_item(FILE *, int, ResponseBatchItem *);
void kmip_print_request_header(FILE *, int, RequestHeader *);
void kmip_print_response_header(FILE *, int, ResponseHeader *);
void kmip_print_request_message(FILE *, RequestMessage *);
void kmip_print_response_message(FILE *, ResponseMessage *);
void kmip_print_query_function_enum(FILE*, int, enum query_function);
void kmip_print_query_functions(FILE*, int, Functions*);
void kmip_print_operations(FILE*, int, Operations *);
void kmip_print_object_types(FILE*, int, ObjectTypes*);
void kmip_print_query_request_payload(FILE*, int, QueryRequestPayload *);
void kmip_print_query_response_payload(FILE*, int, QueryResponsePayload *);
void kmip_print_server_information(FILE*, int, ServerInformation*);

/*
Freeing Functions
*/

void kmip_free_buffer(KMIP *, void *, size_t);
void kmip_free_text_string(KMIP *, TextString *);
void kmip_free_byte_string(KMIP *, ByteString *);
void kmip_free_name(KMIP *, Name *);
void kmip_free_attribute(KMIP *, Attribute *);
void kmip_free_attributes(KMIP *, Attributes *);
void kmip_free_template_attribute(KMIP *, TemplateAttribute *);
void kmip_free_transparent_symmetric_key(KMIP *, TransparentSymmetricKey *);
void kmip_free_key_material(KMIP *, enum key_format_type, void **);
void kmip_free_key_value(KMIP *, enum key_format_type, KeyValue *);
void kmip_free_protection_storage_masks(KMIP *, ProtectionStorageMasks *);
void kmip_free_application_specific_information(KMIP *, ApplicationSpecificInformation *);
void kmip_free_cryptographic_parameters(KMIP *, CryptographicParameters *);
void kmip_free_encryption_key_information(KMIP *, EncryptionKeyInformation *);
void kmip_free_mac_signature_key_information(KMIP *, MACSignatureKeyInformation *);
void kmip_free_key_wrapping_data(KMIP *, KeyWrappingData *);
void kmip_free_key_block(KMIP *, KeyBlock *);
void kmip_free_symmetric_key(KMIP *, SymmetricKey *);
void kmip_free_public_key(KMIP *, PublicKey *);
void kmip_free_private_key(KMIP *, PrivateKey *);
void kmip_free_key_wrapping_specification(KMIP *, KeyWrappingSpecification *);
void kmip_free_create_request_payload(KMIP *, CreateRequestPayload *);
void kmip_free_create_response_payload(KMIP *, CreateResponsePayload *);
void kmip_free_get_request_payload(KMIP *, GetRequestPayload *);
void kmip_free_get_response_payload(KMIP *, GetResponsePayload *);
void kmip_free_destroy_request_payload(KMIP *, DestroyRequestPayload *);
void kmip_free_destroy_response_payload(KMIP *, DestroyResponsePayload *);
void kmip_free_request_batch_item(KMIP *, RequestBatchItem *);
void kmip_free_response_batch_item(KMIP *, ResponseBatchItem *);
void kmip_free_nonce(KMIP *, Nonce *);
void kmip_free_username_password_credential(KMIP *, UsernamePasswordCredential *);
void kmip_free_device_credential(KMIP *, DeviceCredential *);
void kmip_free_attestation_credential(KMIP *, AttestationCredential *);
void kmip_free_credential_value(KMIP *, enum credential_type, void **);
void kmip_free_credential(KMIP *, Credential *);
void kmip_free_authentication(KMIP *, Authentication *);
void kmip_free_request_header(KMIP *, RequestHeader *);
void kmip_free_response_header(KMIP *, ResponseHeader *);
void kmip_free_request_message(KMIP *, RequestMessage *);
void kmip_free_response_message(KMIP *, ResponseMessage *);
void kmip_free_query_functions(KMIP *ctx, Functions*);
void kmip_free_query_request_payload(KMIP *, QueryRequestPayload *);
void kmip_free_query_response_payload(KMIP *, QueryResponsePayload *);
void kmip_free_operations(KMIP *ctx, Operations *value);
void kmip_free_objects(KMIP *ctx, ObjectTypes* value);
void kmip_free_server_information(KMIP* ctx, ServerInformation* value);

/*
Copying Functions
*/

int32 * kmip_deep_copy_int32(KMIP *, const int32 *);
int64 * kmip_deep_copy_int64(KMIP *, const int64 *);
TextString * kmip_deep_copy_text_string(KMIP *, const TextString *);
ByteString * kmip_deep_copy_byte_string(KMIP *, const ByteString *);
Name * kmip_deep_copy_name(KMIP *, const Name *);
CryptographicParameters * kmip_deep_copy_cryptographic_parameters(KMIP *, const CryptographicParameters *);
ApplicationSpecificInformation * kmip_deep_copy_application_specific_information(KMIP *, const ApplicationSpecificInformation *);
Attribute * kmip_deep_copy_attribute(KMIP *, const Attribute *);
char* kmip_copy_textstring(char* dest, TextString* src, size_t size);
void kmip_copy_objects(int objs[], size_t* objs_size, ObjectTypes *value, unsigned max_objs);
void kmip_copy_operations(int ops[], size_t* ops_size, Operations *value, unsigned max_ops);
void kmip_copy_query_result(QueryResponse* query_result, QueryResponsePayload *pld);

/*
Comparison Functions
*/

int kmip_compare_text_string(const TextString *, const TextString *);
int kmip_compare_byte_string(const ByteString *, const ByteString *);
int kmip_compare_name(const Name *, const Name *);
int kmip_compare_attribute(const Attribute *, const Attribute *);
int kmip_compare_attributes(const Attributes *, const Attributes *);
int kmip_compare_template_attribute(const TemplateAttribute *, const TemplateAttribute *);
int kmip_compare_protocol_version(const ProtocolVersion *, const ProtocolVersion *);
int kmip_compare_transparent_symmetric_key(const TransparentSymmetricKey *, const TransparentSymmetricKey *);
int kmip_compare_key_material(enum key_format_type, void **, void **);
int kmip_compare_key_value(enum key_format_type, const KeyValue *, const KeyValue *);
int kmip_compare_protection_storage_masks(const ProtectionStorageMasks *, const ProtectionStorageMasks *);
int kmip_compare_application_specific_information(const ApplicationSpecificInformation *, const ApplicationSpecificInformation *);
int kmip_compare_cryptographic_parameters(const CryptographicParameters *, const CryptographicParameters *);
int kmip_compare_encryption_key_information(const EncryptionKeyInformation *, const EncryptionKeyInformation *);
int kmip_compare_mac_signature_key_information(const MACSignatureKeyInformation *, const MACSignatureKeyInformation *);
int kmip_compare_key_wrapping_data(const KeyWrappingData *, const KeyWrappingData *);
int kmip_compare_key_block(const KeyBlock *, const KeyBlock *);
int kmip_compare_symmetric_key(const SymmetricKey *, const SymmetricKey *);
int kmip_compare_public_key(const PublicKey *, const PublicKey *);
int kmip_compare_private_key(const PrivateKey *, const PrivateKey *);
int kmip_compare_key_wrapping_specification(const KeyWrappingSpecification *, const KeyWrappingSpecification *);
int kmip_compare_create_request_payload(const CreateRequestPayload *, const CreateRequestPayload *);
int kmip_compare_create_response_payload(const CreateResponsePayload *, const CreateResponsePayload *);
int kmip_compare_get_request_payload(const GetRequestPayload *, const GetRequestPayload *);
int kmip_compare_get_response_payload(const GetResponsePayload *, const GetResponsePayload *);
int kmip_compare_destroy_request_payload(const DestroyRequestPayload *, const DestroyRequestPayload *);
int kmip_compare_destroy_response_payload(const DestroyResponsePayload *, const DestroyResponsePayload *);
int kmip_compare_request_batch_item(const RequestBatchItem *, const RequestBatchItem *);
int kmip_compare_response_batch_item(const ResponseBatchItem *, const ResponseBatchItem *);
int kmip_compare_nonce(const Nonce *, const Nonce *);
int kmip_compare_username_password_credential(const UsernamePasswordCredential *, const UsernamePasswordCredential *);
int kmip_compare_device_credential(const DeviceCredential *, const DeviceCredential *);
int kmip_compare_attestation_credential(const AttestationCredential *, const AttestationCredential *);
int kmip_compare_credential_value(enum credential_type, void **, void **);
int kmip_compare_credential(const Credential *, const Credential *);
int kmip_compare_authentication(const Authentication *, const Authentication *);
int kmip_compare_request_header(const RequestHeader *, const RequestHeader *);
int kmip_compare_response_header(const ResponseHeader *, const ResponseHeader *);
int kmip_compare_request_message(const RequestMessage *, const RequestMessage *);
int kmip_compare_response_message(const ResponseMessage *, const ResponseMessage *);
int kmip_compare_query_functions(const Functions *, const Functions *);
int kmip_compare_operations(const Operations *, const Operations *);
int kmip_compare_objects(const ObjectTypes *, const ObjectTypes *);
int kmip_compare_server_information(const ServerInformation *a, const ServerInformation *b);
int kmip_compare_alternative_endpoints(const AltEndpoints* a, const AltEndpoints* b);
int kmip_compare_query_request_payload(const QueryRequestPayload *, const QueryRequestPayload *);
int kmip_compare_query_response_payload(const QueryResponsePayload *, const QueryResponsePayload *);

/*
Encoding Functions
*/

int kmip_encode_int8_be(KMIP *, int8);
int kmip_encode_int32_be(KMIP *, int32);
int kmip_encode_int64_be(KMIP *, int64);
int kmip_encode_integer(KMIP *, enum tag, int32);
int kmip_encode_long(KMIP *, enum tag, int64);
int kmip_encode_enum(KMIP *, enum tag, int32);
int kmip_encode_bool(KMIP *, enum tag, bool32);
int kmip_encode_text_string(KMIP *, enum tag, const TextString *);
int kmip_encode_byte_string(KMIP *, enum tag, const ByteString *);
int kmip_encode_date_time(KMIP *, enum tag, int64);
int kmip_encode_interval(KMIP *, enum tag, uint32);
int kmip_encode_length(KMIP *, intptr);
int kmip_encode_name(KMIP *, const Name *);
int kmip_encode_attribute_name(KMIP *, enum attribute_type);
int kmip_encode_attribute_v1(KMIP *, const Attribute *);
int kmip_encode_attribute_v2(KMIP *, const Attribute *);
int kmip_encode_attribute(KMIP *, const Attribute *);
int kmip_encode_attributes(KMIP *, const Attributes *);
int kmip_encode_template_attribute(KMIP *, const TemplateAttribute *);
int kmip_encode_protocol_version(KMIP *, const ProtocolVersion *);
int kmip_encode_protection_storage_masks(KMIP *, const ProtectionStorageMasks *);
int kmip_encode_application_specific_information(KMIP *, const ApplicationSpecificInformation *);
int kmip_encode_cryptographic_parameters(KMIP *, const CryptographicParameters *);
int kmip_encode_encryption_key_information(KMIP *, const EncryptionKeyInformation *);
int kmip_encode_mac_signature_key_information(KMIP *, const MACSignatureKeyInformation *);
int kmip_encode_key_wrapping_data(KMIP *, const KeyWrappingData *);
int kmip_encode_transparent_symmetric_key(KMIP *, const TransparentSymmetricKey *);
int kmip_encode_key_material(KMIP *, enum key_format_type, const void *);
int kmip_encode_key_value(KMIP *, enum key_format_type, const KeyValue *);
int kmip_encode_key_block(KMIP *, const KeyBlock *);
int kmip_encode_symmetric_key(KMIP *, const SymmetricKey *);
int kmip_encode_public_key(KMIP *, const PublicKey *);
int kmip_encode_private_key(KMIP *, const PrivateKey *);
int kmip_encode_key_wrapping_specification(KMIP *, const KeyWrappingSpecification *);
int kmip_encode_create_request_payload(KMIP *, const CreateRequestPayload *);
int kmip_encode_create_response_payload(KMIP *, const CreateResponsePayload *);
int kmip_encode_get_request_payload(KMIP *, const GetRequestPayload *);
int kmip_encode_get_response_payload(KMIP *, const GetResponsePayload *);
int kmip_encode_destroy_request_payload(KMIP *, const DestroyRequestPayload *);
int kmip_encode_destroy_response_payload(KMIP *, const DestroyResponsePayload *);
int kmip_encode_nonce(KMIP *, const Nonce *);
int kmip_encode_username_password_credential(KMIP *, const UsernamePasswordCredential *);
int kmip_encode_device_credential(KMIP *, const DeviceCredential *);
int kmip_encode_attestation_credential(KMIP *, const AttestationCredential *);
int kmip_encode_credential_value(KMIP *, enum credential_type, void *);
int kmip_encode_credential(KMIP *, const Credential *);
int kmip_encode_authentication(KMIP *, const Authentication *);
int kmip_encode_request_header(KMIP *, const RequestHeader *);
int kmip_encode_response_header(KMIP *, const ResponseHeader *);
int kmip_encode_request_batch_item(KMIP *, const RequestBatchItem *);
int kmip_encode_response_batch_item(KMIP *, const ResponseBatchItem *);
int kmip_encode_request_message(KMIP *, const RequestMessage *);
int kmip_encode_response_message(KMIP *, const ResponseMessage *);
int kmip_encode_query_functions(KMIP *ctx, const Functions*);
int kmip_encode_query_request_payload(KMIP *, const QueryRequestPayload *);
int kmip_encode_query_response_payload(KMIP *, const QueryResponsePayload *);

/*
Decoding Functions
*/

int kmip_decode_int8_be(KMIP *, void *);
int kmip_decode_int32_be(KMIP *, void *);
int kmip_decode_int64_be(KMIP *, void *);
int kmip_decode_integer(KMIP *, enum tag, int32 *);
int kmip_decode_long(KMIP *, enum tag, int64 *);
int kmip_decode_enum(KMIP *, enum tag, void *);
int kmip_decode_bool(KMIP *, enum tag, bool32 *);
int kmip_decode_text_string(KMIP *, enum tag, TextString *);
int kmip_decode_byte_string(KMIP *, enum tag, ByteString *);
int kmip_decode_date_time(KMIP *, enum tag, int64 *);
int kmip_decode_interval(KMIP *, enum tag, uint32 *);
int kmip_decode_name(KMIP *, Name *);
int kmip_decode_attribute_name(KMIP *, enum attribute_type *);
int kmip_decode_attribute_v1(KMIP *, Attribute *);
int kmip_decode_attribute_v2(KMIP *, Attribute *);
int kmip_decode_attribute(KMIP *, Attribute *);
int kmip_decode_attributes(KMIP *, Attributes *);
int kmip_decode_template_attribute(KMIP *, TemplateAttribute *);
int kmip_decode_protocol_version(KMIP *, ProtocolVersion *);
int kmip_decode_transparent_symmetric_key(KMIP *, TransparentSymmetricKey *);
int kmip_decode_key_material(KMIP *, enum key_format_type, void **);
int kmip_decode_key_value(KMIP *, enum key_format_type, KeyValue *);
int kmip_decode_protection_storage_masks(KMIP *, ProtectionStorageMasks *);
int kmip_decode_application_specific_information(KMIP *, ApplicationSpecificInformation *);
int kmip_decode_cryptographic_parameters(KMIP *, CryptographicParameters *);
int kmip_decode_encryption_key_information(KMIP *, EncryptionKeyInformation *);
int kmip_decode_mac_signature_key_information(KMIP *, MACSignatureKeyInformation *);
int kmip_decode_key_wrapping_data(KMIP *, KeyWrappingData *);
int kmip_decode_key_block(KMIP *, KeyBlock *);
int kmip_decode_symmetric_key(KMIP *, SymmetricKey *);
int kmip_decode_public_key(KMIP *, PublicKey *);
int kmip_decode_private_key(KMIP *, PrivateKey *);
int kmip_decode_key_wrapping_specification(KMIP *, KeyWrappingSpecification *);
int kmip_decode_create_request_payload(KMIP *, CreateRequestPayload *);
int kmip_decode_create_response_payload(KMIP *, CreateResponsePayload *);
int kmip_decode_get_request_payload(KMIP *, GetRequestPayload *);
int kmip_decode_get_response_payload(KMIP *, GetResponsePayload *);
int kmip_decode_destroy_request_payload(KMIP *, DestroyRequestPayload *);
int kmip_decode_destroy_response_payload(KMIP *, DestroyResponsePayload *);
int kmip_decode_request_batch_item(KMIP *, RequestBatchItem *);
int kmip_decode_response_batch_item(KMIP *, ResponseBatchItem *);
int kmip_decode_nonce(KMIP *, Nonce *);
int kmip_decode_username_password_credential(KMIP *, UsernamePasswordCredential *);
int kmip_decode_device_credential(KMIP *, DeviceCredential *);
int kmip_decode_attestation_credential(KMIP *, AttestationCredential *);
int kmip_decode_credential_value(KMIP *, enum credential_type, void **);
int kmip_decode_credential(KMIP *, Credential *);
int kmip_decode_authentication(KMIP *, Authentication *);
int kmip_decode_request_header(KMIP *, RequestHeader *);
int kmip_decode_response_header(KMIP *, ResponseHeader *);
int kmip_decode_request_message(KMIP *, RequestMessage *);
int kmip_decode_response_message(KMIP *, ResponseMessage *);
int kmip_decode_query_functions(KMIP *ctx, Functions*);
int kmip_decode_operations(KMIP *, Operations *);
int kmip_decode_object_types(KMIP *, ObjectTypes *);
int kmip_decode_query_request_payload(KMIP *, QueryRequestPayload *);
int kmip_decode_query_response_payload(KMIP *, QueryResponsePayload *);
int kmip_decode_server_information(KMIP *ctx, ServerInformation *);

#ifdef __cplusplus
}
#endif

#endif  /* KMIP_H */
