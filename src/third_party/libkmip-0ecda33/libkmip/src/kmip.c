/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_memset.h"
#include "kmip_locate.h"


/*
Miscellaneous Utilities
*/

size_t
kmip_strnlen_s(const char *str, size_t strsz)
{
    if(str == NULL)
    {
        return(0);
    }
    
    size_t length = 0;
    for(const char *i = str; *i != 0; i++)
    {
        length++;
        if(length >= strsz)
        {
            return(strsz);
        }
    }
    return(length);
}

LinkedListItem *
kmip_linked_list_pop(LinkedList *list)
{
    if(list == NULL)
    {
        return(NULL);
    }
    
    LinkedListItem *popped = list->head;
    
    if(popped != NULL)
    {
        list->head = popped->next;
        popped->next = NULL;
        popped->prev = NULL;
        
        if(list->head != NULL)
        {
            list->head->prev = NULL;
        }

        if(popped == list->tail)
        {
            list->tail = NULL;
        }
        
        if(list->size > 0)
        {
            list->size -= 1;
        }
    }
    else
    {
        if(list->size != 0)
        {
            list->size = 0;
        }
    }
    
    return(popped);
}

void
kmip_linked_list_push(LinkedList *list, LinkedListItem *item)
{
    if(list != NULL && item != NULL)
    {
        LinkedListItem *head = list->head;
        list->head = item;
        item->next = head;
        item->prev = NULL;
        list->size += 1;
        
        if(head != NULL)
        {
            head->prev = item;
        }

        if(list->tail == NULL)
        {
            list->tail = list->head;
        }
    }
}

void
kmip_linked_list_enqueue(LinkedList *list, LinkedListItem *item)
{
    if(list != NULL && item != NULL)
    {
        LinkedListItem *tail = list->tail;
        list->tail = item;
        item->next = NULL;
        item->prev = tail;
        list->size += 1;

        if(tail != NULL)
        {
            tail->next = item;
        }

        if(list->head == NULL)
        {
            list->head = list->tail;
        }
    }
}

/*
Memory Handlers
*/

void *
kmip_calloc(void *state, size_t num, size_t size)
{
    (void)state;
    return(calloc(num, size));
}

void *
kmip_realloc(void *state, void *ptr, size_t size)
{
    (void)state;
    return(realloc(ptr, size));
}

void
kmip_free(void *state, void *ptr)
{
    (void)state;
    free(ptr);
    return;
}

/* TODO (ph) Consider replacing this with memcpy_s, ala memset_s. */
void *
kmip_memcpy(void *state, void *destination, const void *source, size_t size)
{
    (void)state;
    return(memcpy(destination, source, size));
}

/*
Enumeration Utilities
*/

static const char *kmip_attribute_names[26] = {
    "Attestation Type",
    "BatchErrorContinuation Option",
    "BlockCipher Mode",
    "Credential Type",
    "Cryptographic Algorithm",
    "Cryptographic Usage Mask",
    "DigitalSignature Algorithm",
    "Encoding Option",
    "Hashing Algorithm",
    "Key Compression Type",
    "Key Format Type",
    "Key Role Type",
    "Key Wrap Type",
    "Mask Generator",
    "Name Type",
    "Object Type",
    "Operation",
    "Padding Method",
    "Protection Storage Mask",
    "Result Reason",
    "Result Status",
    "State",
    "Tag", /*?*/
    "Type", /*?*/
    "Wrapping Method",
    "Unknown" /* Catch all for unsupported enumerations */
};

int
kmip_get_enum_string_index(enum tag t)
{
    switch(t)
    {
        case KMIP_TAG_ATTESTATION_TYPE:
        return(0);
        break;
        
        case KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION:
        return(1);
        break;
        
        case KMIP_TAG_BLOCK_CIPHER_MODE:
        return(2);
        break;
        
        case KMIP_TAG_CREDENTIAL_TYPE:
        return(3);
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
        return(4);
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
        return(5);
        break;
        
        case KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM:
        return(6);
        break;
        
        case KMIP_TAG_ENCODING_OPTION:
        return(7);
        break;
        
        case KMIP_TAG_HASHING_ALGORITHM:
        return(8);
        break;
        
        case KMIP_TAG_KEY_COMPRESSION_TYPE:
        return(9);
        break;
        
        case KMIP_TAG_KEY_FORMAT_TYPE:
        return(10);
        break;
        
        case KMIP_TAG_KEY_ROLE_TYPE:
        return(11);
        break;
        
        case KMIP_TAG_KEY_WRAP_TYPE:
        return(12);
        break;
        
        case KMIP_TAG_MASK_GENERATOR:
        return(13);
        break;
        
        case KMIP_TAG_NAME_TYPE:
        return(14);
        break;
        
        case KMIP_TAG_OBJECT_TYPE:
        return(15);
        break;
        
        case KMIP_TAG_OPERATION:
        return(16);
        break;
        
        case KMIP_TAG_PADDING_METHOD:
        return(17);
        break;

        case KMIP_TAG_PROTECTION_STORAGE_MASK:
        return(18);
        break;
        
        case KMIP_TAG_RESULT_REASON:
        return(19);
        break;
        
        case KMIP_TAG_RESULT_STATUS:
        return(20);
        break;
        
        case KMIP_TAG_STATE:
        return(21);
        break;
        
        case KMIP_TAG_TAG:
        return(22);
        break;
        
        case KMIP_TAG_TYPE:
        return(23);
        break;
        
        case KMIP_TAG_WRAPPING_METHOD:
        return(24);
        break;
        
        default:
        return(25);
        break;
    };
}

int
kmip_check_enum_value(enum kmip_version version, enum tag t, int value)
{
    switch(t)
    {
        case KMIP_TAG_ATTESTATION_TYPE:
        switch(value)
        {
            case KMIP_ATTEST_TPM_QUOTE:
            case KMIP_ATTEST_TCG_INTEGRITY_REPORT:
            case KMIP_ATTEST_SAML_ASSERTION:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION:
        switch(value)
        {
            case KMIP_BATCH_CONTINUE:
            case KMIP_BATCH_STOP:
            case KMIP_BATCH_UNDO:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_BLOCK_CIPHER_MODE:
        switch(value)
        {
            case KMIP_BLOCK_CBC:
            case KMIP_BLOCK_ECB:
            case KMIP_BLOCK_PCBC:
            case KMIP_BLOCK_CFB:
            case KMIP_BLOCK_OFB:
            case KMIP_BLOCK_CTR:
            case KMIP_BLOCK_CMAC:
            case KMIP_BLOCK_CCM:
            case KMIP_BLOCK_GCM:
            case KMIP_BLOCK_CBC_MAC:
            case KMIP_BLOCK_XTS:
            case KMIP_BLOCK_AES_KEY_WRAP_PADDING:
            case KMIP_BLOCK_NIST_KEY_WRAP:
            case KMIP_BLOCK_X9102_AESKW:
            case KMIP_BLOCK_X9102_TDKW:
            case KMIP_BLOCK_X9102_AKW1:
            case KMIP_BLOCK_X9102_AKW2:
            return(KMIP_OK);
            break;
            
            case KMIP_BLOCK_AEAD:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_CREDENTIAL_TYPE:
        switch(value)
        {
            case KMIP_CRED_USERNAME_AND_PASSWORD:
            return(KMIP_OK);
            break;
            
            case KMIP_CRED_DEVICE:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_CRED_ATTESTATION:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            /* KMIP 2.0 */
            case KMIP_CRED_ONE_TIME_PASSWORD:
            case KMIP_CRED_HASHED_PASSWORD:
            case KMIP_CRED_TICKET:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
        switch(value)
        {
            case KMIP_CRYPTOALG_DES:
            case KMIP_CRYPTOALG_TRIPLE_DES:
            case KMIP_CRYPTOALG_AES:
            case KMIP_CRYPTOALG_RSA:
            case KMIP_CRYPTOALG_DSA:
            case KMIP_CRYPTOALG_ECDSA:
            case KMIP_CRYPTOALG_HMAC_SHA1:
            case KMIP_CRYPTOALG_HMAC_SHA224:
            case KMIP_CRYPTOALG_HMAC_SHA256:
            case KMIP_CRYPTOALG_HMAC_SHA384:
            case KMIP_CRYPTOALG_HMAC_SHA512:
            case KMIP_CRYPTOALG_HMAC_MD5:
            case KMIP_CRYPTOALG_DH:
            case KMIP_CRYPTOALG_ECDH:
            case KMIP_CRYPTOALG_ECMQV:
            case KMIP_CRYPTOALG_BLOWFISH:
            case KMIP_CRYPTOALG_CAMELLIA:
            case KMIP_CRYPTOALG_CAST5:
            case KMIP_CRYPTOALG_IDEA:
            case KMIP_CRYPTOALG_MARS:
            case KMIP_CRYPTOALG_RC2:
            case KMIP_CRYPTOALG_RC4:
            case KMIP_CRYPTOALG_RC5:
            case KMIP_CRYPTOALG_SKIPJACK:
            case KMIP_CRYPTOALG_TWOFISH:
            return(KMIP_OK);
            break;
            
            case KMIP_CRYPTOALG_EC:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_CRYPTOALG_ONE_TIME_PAD:
            if(version >= KMIP_1_3)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_CRYPTOALG_CHACHA20:
            case KMIP_CRYPTOALG_POLY1305:
            case KMIP_CRYPTOALG_CHACHA20_POLY1305:
            case KMIP_CRYPTOALG_SHA3_224:
            case KMIP_CRYPTOALG_SHA3_256:
            case KMIP_CRYPTOALG_SHA3_384:
            case KMIP_CRYPTOALG_SHA3_512:
            case KMIP_CRYPTOALG_HMAC_SHA3_224:
            case KMIP_CRYPTOALG_HMAC_SHA3_256:
            case KMIP_CRYPTOALG_HMAC_SHA3_384:
            case KMIP_CRYPTOALG_HMAC_SHA3_512:
            case KMIP_CRYPTOALG_SHAKE_128:
            case KMIP_CRYPTOALG_SHAKE_256:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            /* KMIP 2.0 */
            case KMIP_CRYPTOALG_ARIA:
            case KMIP_CRYPTOALG_SEED:
            case KMIP_CRYPTOALG_SM2:
            case KMIP_CRYPTOALG_SM3:
            case KMIP_CRYPTOALG_SM4:
            case KMIP_CRYPTOALG_GOST_R_34_10_2012:
            case KMIP_CRYPTOALG_GOST_R_34_11_2012:
            case KMIP_CRYPTOALG_GOST_R_34_13_2015:
            case KMIP_CRYPTOALG_GOST_28147_89:
            case KMIP_CRYPTOALG_XMSS:
            case KMIP_CRYPTOALG_SPHINCS_256:
            case KMIP_CRYPTOALG_MCELIECE:
            case KMIP_CRYPTOALG_MCELIECE_6960119:
            case KMIP_CRYPTOALG_MCELIECE_8192128:
            case KMIP_CRYPTOALG_ED25519:
            case KMIP_CRYPTOALG_ED448:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
        switch(value)
        {
            case KMIP_CRYPTOMASK_SIGN:
            case KMIP_CRYPTOMASK_VERIFY:
            case KMIP_CRYPTOMASK_ENCRYPT:
            case KMIP_CRYPTOMASK_DECRYPT:
            case KMIP_CRYPTOMASK_WRAP_KEY:
            case KMIP_CRYPTOMASK_UNWRAP_KEY:
            case KMIP_CRYPTOMASK_EXPORT:
            case KMIP_CRYPTOMASK_MAC_GENERATE:
            case KMIP_CRYPTOMASK_MAC_VERIFY:
            case KMIP_CRYPTOMASK_DERIVE_KEY:
            case KMIP_CRYPTOMASK_CONTENT_COMMITMENT:
            case KMIP_CRYPTOMASK_KEY_AGREEMENT:
            case KMIP_CRYPTOMASK_CERTIFICATE_SIGN:
            case KMIP_CRYPTOMASK_CRL_SIGN:
            case KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM:
            case KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM:
            case KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT:
            case KMIP_CRYPTOMASK_TRANSLATE_DECRYPT:
            case KMIP_CRYPTOMASK_TRANSLATE_WRAP:
            case KMIP_CRYPTOMASK_TRANSLATE_UNWRAP:
            return(KMIP_OK);
            break;

            /* KMIP 2.0 */
            case KMIP_CRYPTOMASK_AUTHENTICATE:
            case KMIP_CRYPTOMASK_UNRESTRICTED:
            case KMIP_CRYPTOMASK_FPE_ENCRYPT:
            case KMIP_CRYPTOMASK_FPE_DECRYPT:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM:
        switch(value)
        {
            case KMIP_DIGITAL_MD2_WITH_RSA:
            case KMIP_DIGITAL_MD5_WITH_RSA:
            case KMIP_DIGITAL_SHA1_WITH_RSA:
            case KMIP_DIGITAL_SHA224_WITH_RSA:
            case KMIP_DIGITAL_SHA256_WITH_RSA:
            case KMIP_DIGITAL_SHA384_WITH_RSA:
            case KMIP_DIGITAL_SHA512_WITH_RSA:
            case KMIP_DIGITAL_RSASSA_PSS:
            case KMIP_DIGITAL_DSA_WITH_SHA1:
            case KMIP_DIGITAL_DSA_WITH_SHA224:
            case KMIP_DIGITAL_DSA_WITH_SHA256:
            case KMIP_DIGITAL_ECDSA_WITH_SHA1:
            case KMIP_DIGITAL_ECDSA_WITH_SHA224:
            case KMIP_DIGITAL_ECDSA_WITH_SHA256:
            case KMIP_DIGITAL_ECDSA_WITH_SHA384:
            case KMIP_DIGITAL_ECDSA_WITH_SHA512:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_DIGITAL_SHA3_256_WITH_RSA:
            case KMIP_DIGITAL_SHA3_384_WITH_RSA:
            case KMIP_DIGITAL_SHA3_512_WITH_RSA:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_ENCODING_OPTION:
        switch(value)
        {
            case KMIP_ENCODE_NO_ENCODING:
            case KMIP_ENCODE_TTLV_ENCODING:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;

        case KMIP_TAG_HASHING_ALGORITHM:
        switch(value)
        {
            case KMIP_HASH_MD2:
            case KMIP_HASH_MD4:
            case KMIP_HASH_MD5:
            case KMIP_HASH_SHA1:
            case KMIP_HASH_SHA224:
            case KMIP_HASH_SHA256:
            case KMIP_HASH_SHA384:
            case KMIP_HASH_SHA512:
            case KMIP_HASH_RIPEMD160:
            case KMIP_HASH_TIGER:
            case KMIP_HASH_WHIRLPOOL:
            return(KMIP_OK);
            break;
            
            case KMIP_HASH_SHA512_224:
            case KMIP_HASH_SHA512_256:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_HASH_SHA3_224:
            case KMIP_HASH_SHA3_256:
            case KMIP_HASH_SHA3_384:
            case KMIP_HASH_SHA3_512:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_COMPRESSION_TYPE:
        switch(value)
        {
            case KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED:
            case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME:
            case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2:
            case KMIP_KEYCOMP_EC_PUB_X962_HYBRID:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_FORMAT_TYPE:
        switch(value)
        {
            case KMIP_KEYFORMAT_RAW:
            case KMIP_KEYFORMAT_OPAQUE:
            case KMIP_KEYFORMAT_PKCS1:
            case KMIP_KEYFORMAT_PKCS8:
            case KMIP_KEYFORMAT_X509:
            case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
            case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
            return(KMIP_OK);
            break;
            
            /* The following set is deprecated as of KMIP 1.3 */
            case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
            case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
            /* TODO (ph) What should happen if version >= 1.3? */
            return(KMIP_OK);
            break;
            
            case KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY:
            case KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY:
            if(version >= KMIP_1_3)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            case KMIP_KEYFORMAT_PKCS12:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            /* KMIP 2.0 */
            case KMIP_KEYFORMAT_PKCS10:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_ROLE_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_ROLE_BDK:
            case KMIP_ROLE_CVK:
            case KMIP_ROLE_DEK:
            case KMIP_ROLE_MKAC:
            case KMIP_ROLE_MKSMC:
            case KMIP_ROLE_MKSMI:
            case KMIP_ROLE_MKDAC:
            case KMIP_ROLE_MKDN:
            case KMIP_ROLE_MKCP:
            case KMIP_ROLE_MKOTH:
            case KMIP_ROLE_KEK:
            case KMIP_ROLE_MAC16609:
            case KMIP_ROLE_MAC97971:
            case KMIP_ROLE_MAC97972:
            case KMIP_ROLE_MAC97973:
            case KMIP_ROLE_MAC97974:
            case KMIP_ROLE_MAC97975:
            case KMIP_ROLE_ZPK:
            case KMIP_ROLE_PVKIBM:
            case KMIP_ROLE_PVKPVV:
            case KMIP_ROLE_PVKOTH:
            return(KMIP_OK);
            break;
            
            /* KMIP 1.4 */
            case KMIP_ROLE_DUKPT:
            case KMIP_ROLE_IV:
            case KMIP_ROLE_TRKBK:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_KEY_WRAP_TYPE:
        switch(value)
        {
            /* KMIP 1.4 */
            case KMIP_WRAPTYPE_NOT_WRAPPED:
            case KMIP_WRAPTYPE_AS_REGISTERED:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_MASK_GENERATOR:
        switch(value)
        {
            /* KMIP 1.4 */
            case KMIP_MASKGEN_MGF1:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_NAME_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
            case KMIP_NAME_URI:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_OBJECT_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_OBJTYPE_CERTIFICATE:
            case KMIP_OBJTYPE_SYMMETRIC_KEY:
            case KMIP_OBJTYPE_PUBLIC_KEY:
            case KMIP_OBJTYPE_PRIVATE_KEY:
            case KMIP_OBJTYPE_SPLIT_KEY:
            case KMIP_OBJTYPE_SECRET_DATA:
            case KMIP_OBJTYPE_OPAQUE_OBJECT:
            return(KMIP_OK);
            break;
            
            /* The following set is deprecated as of KMIP 1.3 */
            case KMIP_OBJTYPE_TEMPLATE:
            /* TODO (ph) What should happen if version >= 1.3? */
            return(KMIP_OK);
            break;
            
            /* KMIP 1.2 */
            case KMIP_OBJTYPE_PGP_KEY:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            /* KMIP 2.0 */
            case KMIP_OBJTYPE_CERTIFICATE_REQUEST:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_OPERATION:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_OP_CREATE:
            case KMIP_OP_GET:
            case KMIP_OP_GET_ATTRIBUTES:
            case KMIP_OP_DESTROY:
            case KMIP_OP_QUERY:
            case KMIP_OP_LOCATE:
            case KMIP_OP_REGISTER:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_PADDING_METHOD:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_PAD_NONE:
            case KMIP_PAD_OAEP:
            case KMIP_PAD_PKCS5:
            case KMIP_PAD_SSL3:
            case KMIP_PAD_ZEROS:
            case KMIP_PAD_ANSI_X923:
            case KMIP_PAD_ISO_10126:
            case KMIP_PAD_PKCS1v15:
            case KMIP_PAD_X931:
            case KMIP_PAD_PSS:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;

        case KMIP_TAG_PROTECTION_STORAGE_MASK:
        {
            switch(value)
            {
                /* KMIP 2.0 */
                case KMIP_PROTECT_SOFTWARE:
                case KMIP_PROTECT_HARDWARE:
                case KMIP_PROTECT_ON_PROCESSOR:
                case KMIP_PROTECT_ON_SYSTEM:
                case KMIP_PROTECT_OFF_SYSTEM:
                case KMIP_PROTECT_HYPERVISOR:
                case KMIP_PROTECT_OPERATING_SYSTEM:
                case KMIP_PROTECT_CONTAINER:
                case KMIP_PROTECT_ON_PREMISES:
                case KMIP_PROTECT_OFF_PREMISES:
                case KMIP_PROTECT_SELF_MANAGED:
                case KMIP_PROTECT_OUTSOURCED:
                case KMIP_PROTECT_VALIDATED:
                case KMIP_PROTECT_SAME_JURISDICTION:
                if(version >= KMIP_2_0)
                    return(KMIP_OK);
                else
                    return(KMIP_INVALID_FOR_VERSION);
                break;

                default:
                return(KMIP_ENUM_MISMATCH);
                break;
            };
        };
        break;
        
        case KMIP_TAG_RESULT_REASON:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_REASON_GENERAL_FAILURE:
            case KMIP_REASON_ITEM_NOT_FOUND:
            case KMIP_REASON_RESPONSE_TOO_LARGE:
            case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
            case KMIP_REASON_INVALID_MESSAGE:
            case KMIP_REASON_OPERATION_NOT_SUPPORTED:
            case KMIP_REASON_MISSING_DATA:
            case KMIP_REASON_INVALID_FIELD:
            case KMIP_REASON_FEATURE_NOT_SUPPORTED:
            case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
            case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
            case KMIP_REASON_ILLEGAL_OPERATION:
            case KMIP_REASON_PERMISSION_DENIED:
            case KMIP_REASON_OBJECT_ARCHIVED:
            case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
            case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
            case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
            case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
            return(KMIP_OK);
            break;
            
            /* KMIP 1.1 */
            case KMIP_REASON_ENCODING_OPTION_FAILURE:
            if(version >= KMIP_1_1)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            /* KMIP 1.2 */
            case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
            case KMIP_REASON_ATTESTATION_REQUIRED:
            case KMIP_REASON_ATTESTATION_FAILED:
            if(version >= KMIP_1_2)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            /* KMIP 1.4 */
            case KMIP_REASON_SENSITIVE:
            case KMIP_REASON_NOT_EXTRACTABLE:
            case KMIP_REASON_OBJECT_ALREADY_EXISTS:
            if(version >= KMIP_1_4)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;
            
            /* KMIP 2.0 */
            case KMIP_REASON_INVALID_TICKET:
            case KMIP_REASON_USAGE_LIMIT_EXCEEDED:
            case KMIP_REASON_NUMERIC_RANGE:
            case KMIP_REASON_INVALID_DATA_TYPE:
            case KMIP_REASON_READ_ONLY_ATTRIBUTE:
            case KMIP_REASON_MULTI_VALUED_ATTRIBUTE:
            case KMIP_REASON_UNSUPPORTED_ATTRIBUTE:
            case KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND:
            case KMIP_REASON_ATTRIBUTE_NOT_FOUND:
            case KMIP_REASON_ATTRIBUTE_READ_ONLY:
            case KMIP_REASON_ATTRIBUTE_SINGLE_VALUED:
            case KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS:
            case KMIP_REASON_BAD_PASSWORD:
            case KMIP_REASON_CODEC_ERROR:
            case KMIP_REASON_ILLEGAL_OBJECT_TYPE:
            case KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK:
            case KMIP_REASON_INTERNAL_SERVER_ERROR:
            case KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE:
            case KMIP_REASON_INVALID_ATTRIBUTE:
            case KMIP_REASON_INVALID_ATTRIBUTE_VALUE:
            case KMIP_REASON_INVALID_CORRELATION_VALUE:
            case KMIP_REASON_INVALID_CSR:
            case KMIP_REASON_INVALID_OBJECT_TYPE:
            case KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED:
            case KMIP_REASON_MISSING_INITIALIZATION_VECTOR:
            case KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE:
            case KMIP_REASON_OBJECT_DESTROYED:
            case KMIP_REASON_OBJECT_NOT_FOUND:
            case KMIP_REASON_NOT_AUTHORISED:
            case KMIP_REASON_SERVER_LIMIT_EXCEEDED:
            case KMIP_REASON_UNKNOWN_ENUMERATION:
            case KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION:
            case KMIP_REASON_UNKNOWN_TAG:
            case KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS:
            case KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION:
            case KMIP_REASON_WRAPPING_OBJECT_ARCHIVED:
            case KMIP_REASON_WRAPPING_OBJECT_DESTROYED:
            case KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND:
            case KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE:
            case KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE:
            case KMIP_REASON_PKCS11_CODEC_ERROR:
            case KMIP_REASON_PKCS11_INVALID_FUNCTION:
            case KMIP_REASON_PKCS11_INVALID_INTERFACE:
            case KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE:
            case KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_RESULT_STATUS:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_STATUS_SUCCESS:
            case KMIP_STATUS_OPERATION_FAILED:
            case KMIP_STATUS_OPERATION_PENDING:
            case KMIP_STATUS_OPERATION_UNDONE:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_STATE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_STATE_PRE_ACTIVE:
            case KMIP_STATE_ACTIVE:
            case KMIP_STATE_DEACTIVATED:
            case KMIP_STATE_COMPROMISED:
            case KMIP_STATE_DESTROYED:
            case KMIP_STATE_DESTROYED_COMPROMISED:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_TAG:
        return(KMIP_OK);
        break;
        
        case KMIP_TAG_TYPE:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_TYPE_STRUCTURE:
            case KMIP_TYPE_INTEGER:
            case KMIP_TYPE_LONG_INTEGER:
            case KMIP_TYPE_BIG_INTEGER:
            case KMIP_TYPE_ENUMERATION:
            case KMIP_TYPE_BOOLEAN:
            case KMIP_TYPE_TEXT_STRING:
            case KMIP_TYPE_BYTE_STRING:
            case KMIP_TYPE_DATE_TIME:
            case KMIP_TYPE_INTERVAL:
            return(KMIP_OK);
            break;
            
            /* KMIP 2.0 */
            case KMIP_TYPE_DATE_TIME_EXTENDED:
            if(version >= KMIP_2_0)
                return(KMIP_OK);
            else
                return(KMIP_INVALID_FOR_VERSION);
            break;

            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_WRAPPING_METHOD:
        switch(value)
        {
            /* KMIP 1.0 */
            case KMIP_WRAP_ENCRYPT:
            case KMIP_WRAP_MAC_SIGN:
            case KMIP_WRAP_ENCRYPT_MAC_SIGN:
            case KMIP_WRAP_MAC_SIGN_ENCRYPT:
            case KMIP_WRAP_TR31:
            return(KMIP_OK);
            break;
            
            default:
            return(KMIP_ENUM_MISMATCH);
            break;
        };
        break;
        
        case KMIP_TAG_QUERY_FUNCTION:
        switch (value)
        {
            /* KMIP 1.0 */
            case KMIP_QUERY_OPERATIONS:
            case KMIP_QUERY_OBJECTS:
            case KMIP_QUERY_SERVER_INFORMATION:
            case KMIP_QUERY_APPLICATION_NAMESPACES:
                return(KMIP_OK);
                break;

            /* KMIP 1.1 */
            case KMIP_QUERY_EXTENSION_LIST:
            case KMIP_QUERY_EXTENSION_MAP:
                {
                    if(version >= KMIP_1_1)
                        return(KMIP_OK);
                    else
                        return(KMIP_INVALID_FOR_VERSION);
                }
                break;

            /* KMIP 1.2 */
            case KMIP_QUERY_ATTESTATION_TYPES:
                {
                    if(version >= KMIP_1_2)
                        return(KMIP_OK);
                    else
                        return(KMIP_INVALID_FOR_VERSION);
                }
                break;

            /* KMIP 1.3 */
            case KMIP_QUERY_RNGS:
            case KMIP_QUERY_VALIDATIONS:
            case KMIP_QUERY_PROFILES:
            case KMIP_QUERY_CAPABILITIES:
            case KMIP_QUERY_CLIENT_REGISTRATION_METHODS:
                {
                    if(version >= KMIP_1_3)
                        return(KMIP_OK);
                    else
                        return(KMIP_INVALID_FOR_VERSION);
                }
                break;

            /* KMIP 2.0 */
            case KMIP_QUERY_DEFAULTS_INFORMATION:
            case KMIP_QUERY_STORAGE_PROTECTION_MASKS:
                {
                    if(version >= KMIP_2_0)
                        return(KMIP_OK);
                    else
                        return(KMIP_INVALID_FOR_VERSION);
                }
                break;

            default:
                return(KMIP_ENUM_MISMATCH);
                break;
        }
        break;
        
        default:
        return(KMIP_ENUM_UNSUPPORTED);
        break;
    };
}

/*
Context Utilities
*/

void
kmip_clear_errors(KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    for(size_t i = 0; i < ARRAY_LENGTH(ctx->errors); i++)
    {
        ctx->errors[i] = (ErrorFrame){{0},0};
    }
    ctx->frame_index = ctx->errors;
    
    if(ctx->error_message != NULL)
    {
        ctx->free_func(ctx->state, ctx->error_message);
        ctx->error_message = NULL;
    }
}

void
kmip_init(KMIP *ctx, void *buffer, size_t buffer_size, enum kmip_version v)
{
    if(ctx == NULL)
    {
        return;
    }
    
    ctx->buffer = (uint8 *)buffer;
    ctx->index = ctx->buffer;
    ctx->size = buffer_size;
    ctx->version = v;
    
    if(ctx->calloc_func == NULL)
    {
        ctx->calloc_func = &kmip_calloc;
    }
    if(ctx->realloc_func == NULL)
    {
        ctx->realloc_func = &kmip_realloc;
    }
    if(ctx->memset_func == NULL)
    {
        ctx->memset_func = &kmip_memset;
    }
    if(ctx->free_func == NULL)
    {
        ctx->free_func = &kmip_free;
    }
    if(ctx->memcpy_func == NULL)
        ctx->memcpy_func = &kmip_memcpy;
    
    ctx->max_message_size = 8192;
    ctx->error_message_size = 200;
    ctx->error_message = NULL;
    
    ctx->error_frame_count = 20;
    
    ctx->credential_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    
    kmip_clear_errors(ctx);
}

void
kmip_init_error_message(KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    if(ctx->error_message == NULL)
    {
        ctx->error_message = ctx->calloc_func(ctx->state, ctx->error_message_size, sizeof(char));
    }
}

int
kmip_add_credential(KMIP *ctx, Credential *cred)
{
    if(ctx == NULL || cred == NULL)
    {
        return(KMIP_UNSET);
    }
    
    LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
    if(item != NULL)
    {
        item->data = cred;
        kmip_linked_list_push(ctx->credential_list, item);
        return(KMIP_OK);
    }
    
    return(KMIP_UNSET);
}

void
kmip_remove_credentials(KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    LinkedListItem *item = kmip_linked_list_pop(ctx->credential_list);
    while(item != NULL)
    {
        ctx->memset_func(item, 0, sizeof(LinkedListItem));
        ctx->free_func(ctx->state, item);
        
        item = kmip_linked_list_pop(ctx->credential_list);
    }
}

void
kmip_reset(KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    if(ctx->buffer != NULL)
    {
        kmip_memset(ctx->buffer, 0, ctx->size);
    }
    ctx->index = ctx->buffer;
    
    kmip_clear_errors(ctx);
}

void
kmip_rewind(KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    ctx->index = ctx->buffer;
    
    kmip_clear_errors(ctx);
}

void
kmip_set_buffer(KMIP *ctx, void *buffer, size_t buffer_size)
{
    if(ctx == NULL)
    {
        return;
    }
    
    /* TODO (ph) Add own_buffer if buffer == NULL? */
    ctx->buffer = (uint8 *)buffer;
    ctx->index = ctx->buffer;
    ctx->size = buffer_size;
}

void
kmip_destroy(KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    kmip_reset(ctx);
    kmip_set_buffer(ctx, NULL, 0);

    kmip_remove_credentials(ctx);
    ctx->memset_func(ctx->credential_list, 0, sizeof(LinkedList));
    ctx->free_func(ctx->state, ctx->credential_list);
    
    ctx->calloc_func = NULL;
    ctx->realloc_func = NULL;
    ctx->memset_func = NULL;
    ctx->free_func = NULL;
    ctx->memcpy_func = NULL;
    ctx->state = NULL;
}

void
kmip_push_error_frame(KMIP *ctx, const char *function, const int line)
{
    if(ctx == NULL)
    {
        return;
    }
    
    for(size_t i = 0; i < 20; i++)
    {
        ErrorFrame *frame = &ctx->errors[i];
        if(frame->line == 0)
        {
            ctx->frame_index = frame;
            strncpy(frame->function, function, sizeof(frame->function) - 1);
            frame->line = line;
            break;
        }
    }
}

void
kmip_set_enum_error_message(KMIP *ctx, enum tag t, int value, int result)
{
    if(ctx == NULL)
    {
        return;
    }
    
    switch(result)
    {
        /* TODO (ph) Update error message for KMIP version 2.0+ */
        case KMIP_INVALID_FOR_VERSION:
        kmip_init_error_message(ctx);
        snprintf(ctx->error_message, ctx->error_message_size, "KMIP 1.%d does not support %s enumeration value (%d)", ctx->version, kmip_attribute_names[kmip_get_enum_string_index(t)], value);
        break;
        
        default: /* KMIP_ENUM_MISMATCH */
        kmip_init_error_message(ctx);
        snprintf(ctx->error_message, ctx->error_message_size, "Invalid %s enumeration value (%d)", kmip_attribute_names[kmip_get_enum_string_index(t)], value);
        break;
    };
}

void
kmip_set_alloc_error_message(KMIP *ctx, size_t size, const char *type)
{
    if(ctx == NULL)
    {
        return;
    }
    
    kmip_init_error_message(ctx);
    snprintf(ctx->error_message, ctx->error_message_size, "Could not allocate %zd bytes for a %s", size, type);
}

void
kmip_set_error_message(KMIP *ctx, const char *message)
{
    if(ctx == NULL)
    {
        return;
    }
    
    kmip_init_error_message(ctx);
    snprintf(ctx->error_message, ctx->error_message_size, "%s", message);
}

int
kmip_is_tag_next(const KMIP *ctx, enum tag t)
{
    if(ctx == NULL)
    {
        return(KMIP_FALSE);
    }
    
    uint8 *index = ctx->index;
    
    if((ctx->size - (uint64)(index - ctx->buffer)) < 3)
    {
        return(KMIP_FALSE);
    }
    
    uint32 tag = 0;
    
    tag |= ((uint32)*index++ << 16);
    tag |= ((uint32)*index++ << 8);
    tag |= ((uint32)*index   << 0);
    
    if(tag != t)
    {
        return(KMIP_FALSE);
    }
    
    return(KMIP_TRUE);
}

int
kmip_is_tag_type_next(const KMIP *ctx, enum tag t, enum type s)
{
    if(ctx == NULL)
    {
        return(KMIP_FALSE);
    }
    
    uint8 *index = ctx->index;
    
    if((ctx->size - (uint64)(index - ctx->buffer)) < 4)
    {
        return(KMIP_FALSE);
    }
    
    uint32 tag_type = 0;
    
    tag_type |= ((uint32)*index++ << 24);
    tag_type |= ((uint32)*index++ << 16);
    tag_type |= ((uint32)*index++ << 8);
    tag_type |= ((uint32)*index   << 0);
    
    if(tag_type != TAG_TYPE(t, s))
    {
        return(KMIP_FALSE);
    }
    
    return(KMIP_TRUE);
}

size_t
kmip_get_num_items_next(KMIP *ctx, enum tag t)
{
    if(ctx == NULL)
    {
        return(0);
    }
    
    size_t count = 0;
    
    uint8 *index = ctx->index;
    uint32 length = 0;
    
    while((ctx->size - (uint64)(ctx->index - ctx->buffer)) > 8)
    {
        if(kmip_is_tag_next(ctx, t))
        {
            ctx->index += 4;
            
            length = 0;
            length |= ((int32)*ctx->index++ << 24);
            length |= ((int32)*ctx->index++ << 16);
            length |= ((int32)*ctx->index++ << 8);
            length |= ((int32)*ctx->index++ << 0);
            length += CALCULATE_PADDING(length);
            
            if((ctx->size - (ctx->index - ctx->buffer)) >= length)
            {
                ctx->index += length;
                count++;
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
    
    ctx->index = index;
    return(count);
}

uint32
kmip_peek_tag(KMIP *ctx)
{
    if(BUFFER_BYTES_LEFT(ctx) < 3)
    {
        return(0);
    }

    uint8 *index = ctx->index;
    uint32 tag = 0;

    tag |= ((int32)*index++ << 16);
    tag |= ((int32)*index++ << 8);
    tag |= ((int32)*index   << 0);

    return(tag);
}

int
kmip_is_attribute_tag(uint32 value)
{
    enum tag attribute_tags[] = {
        KMIP_TAG_UNIQUE_IDENTIFIER,
        KMIP_TAG_NAME,
        KMIP_TAG_OBJECT_TYPE,
        KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
        KMIP_TAG_CRYPTOGRAPHIC_LENGTH,
        KMIP_TAG_OPERATION_POLICY_NAME,
        KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
        KMIP_TAG_STATE
    };

    for(size_t i = 0; i < ARRAY_LENGTH(attribute_tags); i++)
    {
        if(attribute_tags[i] == value)
        {
            return(KMIP_TRUE);
        }
    }

    return(KMIP_FALSE);
}

/*
Initialization Functions
*/

void
kmip_init_application_specific_information(ApplicationSpecificInformation *value)
{
    if(value == NULL)
    {
        return;
    }

    value->application_namespace = NULL;
    value->application_data = NULL;
}

void
kmip_init_protocol_version(ProtocolVersion *value, enum kmip_version kmip_version)
{
    if(value == NULL)
    {
        return;
    }
    
    switch(kmip_version)
    {
        case KMIP_2_0:
        {
            value->major = 2;
            value->minor = 0;
        };
        break;

        case KMIP_1_4:
        {
            value->major = 1;
            value->minor = 4;
        };
        break;
        
        case KMIP_1_3:
        {
            value->major = 1;
            value->minor = 3;
        };
        break;
        
        case KMIP_1_2:
        {
            value->major = 1;
            value->minor = 2;
        };
        break;
        
        case KMIP_1_1:
        {
            value->major = 1;
            value->minor = 1;
        };
        break;
        
        case KMIP_1_0:
        default:
        {
            value->major = 1;
            value->minor = 0;
        };
        break;
    };
}

void
kmip_init_attribute(Attribute *value)
{
    if(value == NULL)
    {
        return;
    }
    
    value->type = 0;
    value->index = KMIP_UNSET;
    value->value = NULL;
}

void
kmip_init_cryptographic_parameters(CryptographicParameters *value)
{
    if(value == NULL)
    {
        return;
    }
    
    value->block_cipher_mode = 0;
    value->padding_method = 0;
    value->hashing_algorithm = 0;
    value->key_role_type = 0;
    
    value->digital_signature_algorithm = 0;
    value->cryptographic_algorithm = 0;
    value->random_iv = KMIP_UNSET;
    value->iv_length = KMIP_UNSET;
    value->tag_length = KMIP_UNSET;
    value->fixed_field_length = KMIP_UNSET;
    value->invocation_field_length = KMIP_UNSET;
    value->counter_length = KMIP_UNSET;
    value->initial_counter_value = KMIP_UNSET;
    
    value->salt_length = KMIP_UNSET;
    value->mask_generator = 0;
    value->mask_generator_hashing_algorithm = 0;
    value->p_source = NULL;
    value->trailer_field = KMIP_UNSET;
}

void
kmip_init_key_block(KeyBlock *value)
{
    if(value == NULL)
    {
        return;
    }
    
    value->key_format_type = 0;
    value->key_compression_type = 0;
    value->key_value = NULL;
    value->key_value_type = 0;
    value->cryptographic_algorithm = 0;
    value->cryptographic_length = KMIP_UNSET;
    value->key_wrapping_data = NULL;
}

void
kmip_init_request_header(RequestHeader *value)
{
    if(value == NULL)
    {
        return;
    }
    
    value->protocol_version = NULL;
    value->maximum_response_size = KMIP_UNSET;
    value->asynchronous_indicator = KMIP_UNSET;
    value->authentication = NULL;
    value->batch_error_continuation_option = 0;
    value->batch_order_option = KMIP_UNSET;
    value->time_stamp = 0;
    value->batch_count = KMIP_UNSET;
    
    value->attestation_capable_indicator = KMIP_UNSET;
    value->attestation_types = NULL;
    value->attestation_type_count = 0;
    
    value->client_correlation_value = NULL;
    value->server_correlation_value = NULL;
}

void
kmip_init_response_header(ResponseHeader *value)
{
    if(value == NULL)
    {
        return;
    }
    
    value->protocol_version = NULL;
    value->time_stamp = 0;
    value->batch_count = KMIP_UNSET;
    
    value->nonce = NULL;
    value->attestation_types = NULL;
    value->attestation_type_count = 0;
    
    value->client_correlation_value = NULL;
    value->server_correlation_value = NULL;

    value->server_hashed_password = NULL;
}

void
kmip_init_request_batch_item(RequestBatchItem *value)
{
    if(value == NULL)
    {
        return;
    }

    value->operation = 0;
    value->unique_batch_item_id = NULL;
    value->request_payload = NULL;

    value->ephemeral = KMIP_UNSET;
}

/*
Printing Functions
*/

void
kmip_print_buffer(FILE *f, void *buffer, int size)
{
    if(buffer == NULL)
    {
        return;
    }
    
    uint8 *index = (uint8 *)buffer;
    for(int i = 0; i < size; i++)
    {
        if(i % 16 == 0)
        {
            fprintf(f, "\n0x");
        }
        fprintf(f, "%02X", index[i]);
    }
}

void
kmip_print_stack_trace(FILE *f, KMIP *ctx)
{
    if(ctx == NULL)
    {
        return;
    }
    
    ErrorFrame *index = ctx->frame_index;
    do
    {
        fprintf(f, "- %s @ line: %d\n", index->function, index->line);
    } while(index-- != ctx->errors);
}

void
kmip_print_error_string(FILE *f, int value)
{
    /* TODO (ph) Move this to a static string array. */
    switch(value)
    {
        case 0:
        {
            fprintf(f, "KMIP_OK");
        } break;
        
        case -1:
        {
            fprintf(f, "KMIP_NOT_IMPLEMENTED");
        } break;
        
        case -2:
        {
            fprintf(f, "KMIP_ERROR_BUFFER_FULL");
        } break;
        
        case -3:
        {
            fprintf(f, "KMIP_ERROR_ATTR_UNSUPPORTED");
        } break;
        
        case -4:
        {
            fprintf(f, "KMIP_TAG_MISMATCH");
        } break;
        
        case -5:
        {
            fprintf(f, "KMIP_TYPE_MISMATCH");
        } break;
        
        case -6:
        {
            fprintf(f, "KMIP_LENGTH_MISMATCH");
        } break;
        
        case -7:
        {
            fprintf(f, "KMIP_PADDING_MISMATCH");
        } break;
        
        case -8:
        {
            fprintf(f, "KMIP_BOOLEAN_MISMATCH");
        } break;
        
        case -9:
        {
            fprintf(f, "KMIP_ENUM_MISMATCH");
        } break;
        
        case -10:
        {
            fprintf(f, "KMIP_ENUM_UNSUPPORTED");
        } break;
        
        case -11:
        {
            fprintf(f, "KMIP_INVALID_FOR_VERSION");
        } break;
        
        case -12:
        {
            fprintf(f, "KMIP_MEMORY_ALLOC_FAILED");
        } break;

        case -13:
        {
            fprintf(f, "KMIP_IO_FAILURE");
        } break;

        case -14:
        {
            fprintf(f, "KMIP_EXCEED_MAX_MESSAGE_SIZE");
        } break;

        case -15:
        {
            fprintf(f, "KMIP_MALFORMED_RESPONSE");
        } break;

        case -16:
        {
            fprintf(f, "KMIP_OBJECT_MISMATCH");
        } break;

        case -17:
        {
            fprintf(f, "KMIP_ARG_INVALID");
        } break;

        case -18:
        {
            fprintf(f, "KMIP_ERROR_BUFFER_UNDERFULL");
        } break;

        default:
        {
            fprintf(f, "Unrecognized Error Code");
        } break;
    };
    
    return;
}

void
kmip_print_attestation_type_enum(FILE *f, enum attestation_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ATTEST_TPM_QUOTE:
        fprintf(f, "TPM Quote");
        break;
        
        case KMIP_ATTEST_TCG_INTEGRITY_REPORT:
        fprintf(f, "TCG Integrity Report");
        break;
        
        case KMIP_ATTEST_SAML_ASSERTION:
        fprintf(f, "SAML Assertion");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_batch_error_continuation_option(FILE *f, enum batch_error_continuation_option value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_BATCH_CONTINUE:
        fprintf(f, "Continue");
        break;
        
        case KMIP_BATCH_STOP:
        fprintf(f, "Stop");
        break;
        
        case KMIP_BATCH_UNDO:
        fprintf(f, "Undo");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_operation_enum(FILE *f, enum operation value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_OP_CREATE:
        fprintf(f, "Create");
        break;

        case KMIP_OP_CREATE_KEY_PAIR:
        fprintf(f, "Create Key Pair");
        break;

        case KMIP_OP_REGISTER:
        fprintf(f, "Register");
        break;

        case KMIP_OP_REKEY:
        fprintf(f, "Rekey");
        break;

        case KMIP_OP_DERIVE_KEY:
        fprintf(f, "Derive Key");
        break;

        case KMIP_OP_CERTIFY:
        fprintf(f, "Certify");
        break;

        case KMIP_OP_RECERTIFY:
        fprintf(f, "Recertify");
        break;

        case KMIP_OP_LOCATE:
        fprintf(f, "Locate");
        break;

        case KMIP_OP_CHECK:
        fprintf(f, "Check");
        break;

        case KMIP_OP_GET:
        fprintf(f, "Get");
        break;

        case KMIP_OP_GET_ATTRIBUTES:
        fprintf(f, "Get Attributes");
        break;

        case KMIP_OP_GET_ATTRIBUTE_LIST:
        fprintf(f, "Get Attribute List");
        break;

        case KMIP_OP_ADD_ATTRIBUTE:
        fprintf(f, "Add Attribute");
        break;

        case KMIP_OP_MODIFY_ATTRIBUTE:
        fprintf(f, "Modify Attribute");
        break;

        case KMIP_OP_DELETE_ATTRIBUTE:
        fprintf(f, "Delete Attribute");
        break;

        case KMIP_OP_OBTAIN_LEASE:
        fprintf(f, "Obtain Lease");
        break;

        case KMIP_OP_GET_USAGE_ALLOCATION:
        fprintf(f, "Get Usage Allocation");
        break;

        case KMIP_OP_ACTIVATE:
        fprintf(f, "Activate");
        break;

        case KMIP_OP_REVOKE:
        fprintf(f, "Revoke");
        break;

        case KMIP_OP_DESTROY:
        fprintf(f, "Destroy");
        break;

        case KMIP_OP_ARCHIVE:
        fprintf(f, "Archive");
        break;

        case KMIP_OP_RECOVER:
        fprintf(f, "Recover");
        break;

        case KMIP_OP_VALIDATE:
        fprintf(f, "Validate");
        break;

        case KMIP_OP_QUERY:
        printf("Query");
        break;

        case KMIP_OP_CANCEL:
        fprintf(f, "Cancel");
        break;

        case KMIP_OP_POLL:
        fprintf(f, "Poll");
        break;

        case KMIP_OP_NOTIFY:
        fprintf(f, "Notify");
        break;

        case KMIP_OP_PUT:
        fprintf(f, "Put");
        break;

        // # KMIP 1.1
        case KMIP_OP_REKEY_KEY_PAIR:
        fprintf(f, "Rekey Key Pair");
        break;

        case KMIP_OP_DISCOVER_VERSIONS:
        fprintf(f, "Discover Versions");
        break;

        //# KMIP 1.2
        case KMIP_OP_ENCRYPT:
        fprintf(f, "Encrypt");
        break;

        case KMIP_OP_DECRYPT:
        fprintf(f, "Decrypt");
        break;

        case KMIP_OP_SIGN:
        fprintf(f, "Sign");
        break;

        case KMIP_OP_SIGNATURE_VERIFY:
        fprintf(f, "Signature Verify");
        break;

        case KMIP_OP_MAC:
        fprintf(f, "MAC");
        break;

        case KMIP_OP_MAC_VERIFY:
        fprintf(f, "MAC Verify");
        break;

        case KMIP_OP_RNG_RETRIEVE:
        fprintf(f, "RNG Retrieve");
        break;

        case KMIP_OP_RNG_SEED:
        fprintf(f, "RNG Seed");
        break;

        case KMIP_OP_HASH:
        fprintf(f, "Hash");
        break;

        case KMIP_OP_CREATE_SPLIT_KEY:
        fprintf(f, "Create Split Key");
        break;

        case KMIP_OP_JOIN_SPLIT_KEY:
        fprintf(f, "Split Key");
        break;

        // # KMIP 1.4
        case KMIP_OP_IMPORT:
        fprintf(f, "Import");
        break;

        case KMIP_OP_EXPORT:
        fprintf(f, "Export");
        break;

        // # KMIP 2.0
        case KMIP_OP_LOG:
        fprintf(f, "Log");
        break;

        case KMIP_OP_LOGIN:
        fprintf(f, "Login");
        break;

        case KMIP_OP_LOGOUT:
        fprintf(f, "Logout");
        break;

        case KMIP_OP_DELEGATED_LOGIN:
        fprintf(f, "Delegated Login");
        break;

        case KMIP_OP_ADJUST_ATTRIBUTE:
        fprintf(f, "Adjust Attribute");
        break;

        case KMIP_OP_SET_ATTRIBUTE:
        fprintf(f, "Set Attribute");
        break;

        case KMIP_OP_SET_ENDPOINT_ROLE:
        fprintf(f, "Set Endpoint Role");
        break;

        case KMIP_OP_PKCS_11:
        fprintf(f, "PKCS11");
        break;

        case KMIP_OP_INTEROP:
        fprintf(f, "Interop");
        break;

        case KMIP_OP_REPROVISION:
        fprintf(f, "Reprovision");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_result_status_enum(FILE *f, enum result_status value)
{
    switch(value)
    {
        case KMIP_STATUS_SUCCESS:
        fprintf(f, "Success");
        break;
        
        case KMIP_STATUS_OPERATION_FAILED:
        fprintf(f, "Operation Failed");
        break;
        
        case KMIP_STATUS_OPERATION_PENDING:
        fprintf(f, "Operation Pending");
        break;
        
        case KMIP_STATUS_OPERATION_UNDONE:
        fprintf(f, "Operation Undone");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_result_reason_enum(FILE *f, enum result_reason value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_REASON_GENERAL_FAILURE:
        fprintf(f, "General Failure");
        break;
        
        case KMIP_REASON_ITEM_NOT_FOUND:
        fprintf(f, "Item Not Found");
        break;
        
        case KMIP_REASON_RESPONSE_TOO_LARGE:
        fprintf(f, "Response Too Large");
        break;
        
        case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
        fprintf(f, "Authentication Not Successful");
        break;
        
        case KMIP_REASON_INVALID_MESSAGE:
        fprintf(f, "Invalid Message");
        break;
        
        case KMIP_REASON_OPERATION_NOT_SUPPORTED:
        fprintf(f, "Operation Not Supported");
        break;
        
        case KMIP_REASON_MISSING_DATA:
        fprintf(f, "Missing Data");
        break;
        
        case KMIP_REASON_INVALID_FIELD:
        fprintf(f, "Invalid Field");
        break;
        
        case KMIP_REASON_FEATURE_NOT_SUPPORTED:
        fprintf(f, "Feature Not Supported");
        break;
        
        case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
        fprintf(f, "Operation Canceled By Requester");
        break;
        
        case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
        fprintf(f, "Cryptographic Failure");
        break;
        
        case KMIP_REASON_ILLEGAL_OPERATION:
        fprintf(f, "Illegal Operation");
        break;
        
        case KMIP_REASON_PERMISSION_DENIED:
        fprintf(f, "Permission Denied");
        break;
        
        case KMIP_REASON_OBJECT_ARCHIVED:
        fprintf(f, "Object Archived");
        break;
        
        case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
        fprintf(f, "Index Out Of Bounds");
        break;
        
        case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
        fprintf(f, "Application Namespace Not Supported");
        break;
        
        case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
        fprintf(f, "Key Format Type Not Supported");
        break;
        
        case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
        fprintf(f, "Key Compression Type Not Supported");
        break;
        
        case KMIP_REASON_ENCODING_OPTION_FAILURE:
        fprintf(f, "Encoding Option Failure");
        break;
        
        case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
        fprintf(f, "Key Value Not Present");
        break;
        
        case KMIP_REASON_ATTESTATION_REQUIRED:
        fprintf(f, "Attestation Required");
        break;
        
        case KMIP_REASON_ATTESTATION_FAILED:
        fprintf(f, "Attestation Failed");
        break;
        
        case KMIP_REASON_SENSITIVE:
        fprintf(f, "Sensitive");
        break;
        
        case KMIP_REASON_NOT_EXTRACTABLE:
        fprintf(f, "Not Extractable");
        break;
        
        case KMIP_REASON_OBJECT_ALREADY_EXISTS:
        fprintf(f, "Object Already Exists");
        break;
        
        case KMIP_REASON_INVALID_TICKET:
        fprintf(f, "Invalid Ticket");
        break;

        case KMIP_REASON_USAGE_LIMIT_EXCEEDED:
        fprintf(f, "Usage Limit Exceeded");
        break;

        case KMIP_REASON_NUMERIC_RANGE:
        fprintf(f, "Numeric Range");
        break;

        case KMIP_REASON_INVALID_DATA_TYPE:
        fprintf(f, "Invalid Data Type");
        break;

        case KMIP_REASON_READ_ONLY_ATTRIBUTE:
        fprintf(f, "Read Only Attribute");
        break;

        case KMIP_REASON_MULTI_VALUED_ATTRIBUTE:
        fprintf(f, "Multi Valued Attribute");
        break;

        case KMIP_REASON_UNSUPPORTED_ATTRIBUTE:
        fprintf(f, "Unsupported Attribute");
        break;

        case KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND:
        fprintf(f, "Attribute Instance Not Found");
        break;

        case KMIP_REASON_ATTRIBUTE_NOT_FOUND:
        fprintf(f, "Attribute Not Found");
        break;

        case KMIP_REASON_ATTRIBUTE_READ_ONLY:
        fprintf(f, "Attribute Read Only");
        break;

        case KMIP_REASON_ATTRIBUTE_SINGLE_VALUED:
        fprintf(f, "Attribute Single Valued");
        break;

        case KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS:
        fprintf(f, "Bad Cryptographic Parameters");
        break;

        case KMIP_REASON_BAD_PASSWORD:
        fprintf(f, "Bad Password");
        break;

        case KMIP_REASON_CODEC_ERROR:
        fprintf(f, "Codec Error");
        break;

        case KMIP_REASON_ILLEGAL_OBJECT_TYPE:
        fprintf(f, "Illegal Object Type");
        break;

        case KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK:
        fprintf(f, "Incompatible Cryptographic Usage Mask");
        break;

        case KMIP_REASON_INTERNAL_SERVER_ERROR:
        fprintf(f, "Internal Server Error");
        break;

        case KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE:
        fprintf(f, "Invalid Asynchronous Correlation Value");
        break;

        case KMIP_REASON_INVALID_ATTRIBUTE:
        fprintf(f, "Invalid Attribute");
        break;

        case KMIP_REASON_INVALID_ATTRIBUTE_VALUE:
        fprintf(f, "Invalid Attribute Value");
        break;

        case KMIP_REASON_INVALID_CORRELATION_VALUE:
        fprintf(f, "Invalid Correlation Value");
        break;

        case KMIP_REASON_INVALID_CSR:
        fprintf(f, "Invalid CSR");
        break;

        case KMIP_REASON_INVALID_OBJECT_TYPE:
        fprintf(f, "Invalid Object Type");
        break;

        case KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED:
        fprintf(f, "Key Wrap Type Not Supported");
        break;

        case KMIP_REASON_MISSING_INITIALIZATION_VECTOR:
        fprintf(f, "Missing Initialization Vector");
        break;

        case KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE:
        fprintf(f, "Non Unique Name Attribute");
        break;

        case KMIP_REASON_OBJECT_DESTROYED:
        fprintf(f, "Object Destroyed");
        break;

        case KMIP_REASON_OBJECT_NOT_FOUND:
        fprintf(f, "Object Not Found");
        break;

        case KMIP_REASON_NOT_AUTHORISED:
        fprintf(f, "Not Authorised");
        break;

        case KMIP_REASON_SERVER_LIMIT_EXCEEDED:
        fprintf(f, "Server Limit Exceeded");
        break;

        case KMIP_REASON_UNKNOWN_ENUMERATION:
        fprintf(f, "Unknown Enumeration");
        break;

        case KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION:
        fprintf(f, "Unknown Message Extension");
        break;

        case KMIP_REASON_UNKNOWN_TAG:
        fprintf(f, "Unknown Tag");
        break;

        case KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS:
        fprintf(f, "Unsupported Cryptographic Parameters");
        break;

        case KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION:
        fprintf(f, "Unsupported Protocol Version");
        break;

        case KMIP_REASON_WRAPPING_OBJECT_ARCHIVED:
        fprintf(f, "Wrapping Object Archived");
        break;

        case KMIP_REASON_WRAPPING_OBJECT_DESTROYED:
        fprintf(f, "Wrapping Object Destroyed");
        break;

        case KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND:
        fprintf(f, "Wrapping Object Not Found");
        break;

        case KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE:
        fprintf(f, "Wrong Key Lifecycle State");
        break;

        case KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE:
        fprintf(f, "Protection Storage Unavailable");
        break;

        case KMIP_REASON_PKCS11_CODEC_ERROR:
        fprintf(f, "PKCS#11 Codec Error");
        break;

        case KMIP_REASON_PKCS11_INVALID_FUNCTION:
        fprintf(f, "PKCS#11 Invalid Function");
        break;

        case KMIP_REASON_PKCS11_INVALID_INTERFACE:
        fprintf(f, "PKCS#11 Invalid Interface");
        break;

        case KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE:
        fprintf(f, "Private Protection Storage Unavailable");
        break;

        case KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE:
        fprintf(f, "Public Protection Storage Unavailable");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_object_type_enum(FILE *f, enum object_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_OBJTYPE_CERTIFICATE:
        fprintf(f, "Certificate");
        break;
        
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        fprintf(f, "Symmetric Key");
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        fprintf(f, "Public Key");
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        fprintf(f, "Private Key");
        break;
        
        case KMIP_OBJTYPE_SPLIT_KEY:
        fprintf(f, "Split Key");
        break;
        
        case KMIP_OBJTYPE_TEMPLATE:
        fprintf(f, "Template");
        break;
        
        case KMIP_OBJTYPE_SECRET_DATA:
        fprintf(f, "Secret Data");
        break;
        
        case KMIP_OBJTYPE_OPAQUE_OBJECT:
        fprintf(f, "Opaque Object");
        break;
        
        case KMIP_OBJTYPE_PGP_KEY:
        fprintf(f, "PGP Key");
        break;

        case KMIP_OBJTYPE_CERTIFICATE_REQUEST:
        fprintf(f, "Certificate Request");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_format_type_enum(FILE *f, enum key_format_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_KEYFORMAT_RAW:
        fprintf(f, "Raw");
        break;
        
        case KMIP_KEYFORMAT_OPAQUE:
        fprintf(f, "Opaque");
        break;
        
        case KMIP_KEYFORMAT_PKCS1:
        fprintf(f, "PKCS1");
        break;
        
        case KMIP_KEYFORMAT_PKCS8:
        fprintf(f, "PKCS8");
        break;
        
        case KMIP_KEYFORMAT_X509:
        fprintf(f, "X509");
        break;
        
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        fprintf(f, "EC Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        fprintf(f, "Transparent Symmetric Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        fprintf(f, "Transparent DSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        fprintf(f, "Transparent DSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        fprintf(f, "Transparent RSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        fprintf(f, "Transparent RSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        fprintf(f, "Transparent DH Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        fprintf(f, "Transparent DH Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        fprintf(f, "Transparent ECDSA Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        fprintf(f, "Transparent ECDSA Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        fprintf(f, "Transparent ECDH Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        fprintf(f, "Transparent ECDH Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        fprintf(f, "Transparent ECMQV Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        fprintf(f, "Transparent ECMQV Public Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY:
        fprintf(f, "Transparent EC Private Key");
        break;
        
        case KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY:
        fprintf(f, "Transparent EC Public Key");
        break;
        
        case KMIP_KEYFORMAT_PKCS12:
        fprintf(f, "PKCS#12");
        break;
        
        case KMIP_KEYFORMAT_PKCS10:
        fprintf(f, "PKCS#10");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_compression_type_enum(FILE *f, enum key_compression_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED:
        fprintf(f, "EC Public Key Type Uncompressed");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME:
        fprintf(f, "EC Public Key Type X9.62 Compressed Prime");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2:
        fprintf(f, "EC Public Key Type X9.62 Compressed Char2");
        break;
        
        case KMIP_KEYCOMP_EC_PUB_X962_HYBRID:
        fprintf(f, "EC Public Key Type X9.62 Hybrid");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_cryptographic_algorithm_enum(FILE *f, enum cryptographic_algorithm value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_CRYPTOALG_DES:
        fprintf(f, "DES");
        break;
        
        case KMIP_CRYPTOALG_TRIPLE_DES:
        fprintf(f, "3DES");
        break;
        
        case KMIP_CRYPTOALG_AES:
        fprintf(f, "AES");
        break;
        
        case KMIP_CRYPTOALG_RSA:
        fprintf(f, "RSA");
        break;
        
        case KMIP_CRYPTOALG_DSA:
        fprintf(f, "DSA");
        break;
        
        case KMIP_CRYPTOALG_ECDSA:
        fprintf(f, "ECDSA");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA1:
        fprintf(f, "SHA1");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA224:
        fprintf(f, "SHA224");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA256:
        fprintf(f, "SHA256");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA384:
        fprintf(f, "SHA384");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA512:
        fprintf(f, "SHA512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_MD5:
        fprintf(f, "MD5");
        break;
        
        case KMIP_CRYPTOALG_DH:
        fprintf(f, "DH");
        break;
        
        case KMIP_CRYPTOALG_ECDH:
        fprintf(f, "ECDH");
        break;
        
        case KMIP_CRYPTOALG_ECMQV:
        fprintf(f, "ECMQV");
        break;
        
        case KMIP_CRYPTOALG_BLOWFISH:
        fprintf(f, "Blowfish");
        break;
        
        case KMIP_CRYPTOALG_CAMELLIA:
        fprintf(f, "Camellia");
        break;
        
        case KMIP_CRYPTOALG_CAST5:
        fprintf(f, "CAST5");
        break;
        
        case KMIP_CRYPTOALG_IDEA:
        fprintf(f, "IDEA");
        break;
        
        case KMIP_CRYPTOALG_MARS:
        fprintf(f, "MARS");
        break;
        
        case KMIP_CRYPTOALG_RC2:
        fprintf(f, "RC2");
        break;
        
        case KMIP_CRYPTOALG_RC4:
        fprintf(f, "RC4");
        break;
        
        case KMIP_CRYPTOALG_RC5:
        fprintf(f, "RC5");
        break;
        
        case KMIP_CRYPTOALG_SKIPJACK:
        fprintf(f, "Skipjack");
        break;
        
        case KMIP_CRYPTOALG_TWOFISH:
        fprintf(f, "Twofish");
        break;
        
        case KMIP_CRYPTOALG_EC:
        fprintf(f, "EC");
        break;
        
        case KMIP_CRYPTOALG_ONE_TIME_PAD:
        fprintf(f, "One Time Pad");
        break;
        
        case KMIP_CRYPTOALG_CHACHA20:
        fprintf(f, "ChaCha20");
        break;
        
        case KMIP_CRYPTOALG_POLY1305:
        fprintf(f, "Poly1305");
        break;
        
        case KMIP_CRYPTOALG_CHACHA20_POLY1305:
        fprintf(f, "ChaCha20 Poly1305");
        break;
        
        case KMIP_CRYPTOALG_SHA3_224:
        fprintf(f, "SHA3-224");
        break;
        
        case KMIP_CRYPTOALG_SHA3_256:
        fprintf(f, "SHA3-256");
        break;
        
        case KMIP_CRYPTOALG_SHA3_384:
        fprintf(f, "SHA3-384");
        break;
        
        case KMIP_CRYPTOALG_SHA3_512:
        fprintf(f, "SHA3-512");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_224:
        fprintf(f, "HMAC SHA3-224");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_256:
        fprintf(f, "HMAC SHA3-256");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_384:
        fprintf(f, "HMAC SHA3-384");
        break;
        
        case KMIP_CRYPTOALG_HMAC_SHA3_512:
        fprintf(f, "HMAC SHA3-512");
        break;
        
        case KMIP_CRYPTOALG_SHAKE_128:
        fprintf(f, "SHAKE-128");
        break;
        
        case KMIP_CRYPTOALG_SHAKE_256:
        fprintf(f, "SHAKE-256");
        break;
        
        case KMIP_CRYPTOALG_ARIA:
        fprintf(f, "ARIA");
        break;

        case KMIP_CRYPTOALG_SEED:
        fprintf(f, "SEED");
        break;

        case KMIP_CRYPTOALG_SM2:
        fprintf(f, "SM2");
        break;

        case KMIP_CRYPTOALG_SM3:
        fprintf(f, "SM3");
        break;

        case KMIP_CRYPTOALG_SM4:
        fprintf(f, "SM4");
        break;

        case KMIP_CRYPTOALG_GOST_R_34_10_2012:
        fprintf(f, "GOST R 34.10-2012");
        break;

        case KMIP_CRYPTOALG_GOST_R_34_11_2012:
        fprintf(f, "GOST R 34.11-2012");
        break;

        case KMIP_CRYPTOALG_GOST_R_34_13_2015:
        fprintf(f, "GOST R 34.13-2015");
        break;

        case KMIP_CRYPTOALG_GOST_28147_89:
        fprintf(f, "GOST 28147-89");
        break;

        case KMIP_CRYPTOALG_XMSS:
        fprintf(f, "XMSS");
        break;

        case KMIP_CRYPTOALG_SPHINCS_256:
        fprintf(f, "SPHINCS-256");
        break;

        case KMIP_CRYPTOALG_MCELIECE:
        fprintf(f, "McEliece");
        break;

        case KMIP_CRYPTOALG_MCELIECE_6960119:
        fprintf(f, "McEliece 6960119");
        break;

        case KMIP_CRYPTOALG_MCELIECE_8192128:
        fprintf(f, "McEliece 8192128");
        break;

        case KMIP_CRYPTOALG_ED25519:
        fprintf(f, "Ed25519");
        break;

        case KMIP_CRYPTOALG_ED448:
        fprintf(f, "Ed448");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_name_type_enum(FILE *f, enum name_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_NAME_UNINTERPRETED_TEXT_STRING:
        fprintf(f, "Uninterpreted Text String");
        break;
        
        case KMIP_NAME_URI:
        fprintf(f, "URI");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_attribute_type_enum(FILE *f, enum attribute_type value)
{
    if((int)value == KMIP_UNSET)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            fprintf(f, "Application Specific Information");
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        fprintf(f, "Unique Identifier");
        break;
        
        case KMIP_ATTR_NAME:
        fprintf(f, "Name");
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        fprintf(f, "Object Type");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        fprintf(f, "Cryptographic Algorithm");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        fprintf(f, "Cryptographic Length");
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        fprintf(f, "Operation Policy Name");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        fprintf(f, "Cryptographic Usage Mask");
        break;
        
        case KMIP_ATTR_STATE:
        fprintf(f, "State");
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            fprintf(f, "Object Group");
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        {
            fprintf(f, "Activation Date");
        } break;

        case KMIP_ATTR_DEACTIVATION_DATE:
        {
            fprintf(f, "Deactivation Date");
        } break;

        case KMIP_ATTR_PROCESS_START_DATE:
        {
            fprintf(f, "Process Start Date");
        } break;

        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            fprintf(f, "Protect Stop Date");
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            fprintf(f, "Cryptographic Parameters");
        } break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_state_enum(FILE *f, enum state value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_STATE_PRE_ACTIVE:
        fprintf(f, "Pre-Active");
        break;
        
        case KMIP_STATE_ACTIVE:
        fprintf(f, "Active");
        break;
        
        case KMIP_STATE_DEACTIVATED:
        fprintf(f, "Deactivated");
        break;
        
        case KMIP_STATE_COMPROMISED:
        fprintf(f, "Compromised");
        break;
        
        case KMIP_STATE_DESTROYED:
        fprintf(f, "Destroyed");
        break;
        
        case KMIP_STATE_DESTROYED_COMPROMISED:
        fprintf(f, "Destroyed Compromised");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_block_cipher_mode_enum(FILE *f, enum block_cipher_mode value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_BLOCK_CBC:
        fprintf(f, "CBC");
        break;
        
        case KMIP_BLOCK_ECB:
        fprintf(f, "ECB");
        break;
        
        case KMIP_BLOCK_PCBC:
        fprintf(f, "PCBC");
        break;
        
        case KMIP_BLOCK_CFB:
        fprintf(f, "CFB");
        break;
        
        case KMIP_BLOCK_OFB:
        fprintf(f, "OFB");
        break;
        
        case KMIP_BLOCK_CTR:
        fprintf(f, "CTR");
        break;
        
        case KMIP_BLOCK_CMAC:
        fprintf(f, "CMAC");
        break;
        
        case KMIP_BLOCK_CCM:
        fprintf(f, "CCM");
        break;
        
        case KMIP_BLOCK_GCM:
        fprintf(f, "GCM");
        break;
        
        case KMIP_BLOCK_CBC_MAC:
        fprintf(f, "CBC-MAC");
        break;
        
        case KMIP_BLOCK_XTS:
        fprintf(f, "XTS");
        break;
        
        case KMIP_BLOCK_AES_KEY_WRAP_PADDING:
        fprintf(f, "AESKeyWrapPadding");
        break;
        
        case KMIP_BLOCK_NIST_KEY_WRAP:
        fprintf(f, "NISTKeyWrap");
        break;
        
        case KMIP_BLOCK_X9102_AESKW:
        fprintf(f, "X9.102 AESKW");
        break;
        
        case KMIP_BLOCK_X9102_TDKW:
        fprintf(f, "X9.102 TDKW");
        break;
        
        case KMIP_BLOCK_X9102_AKW1:
        fprintf(f, "X9.102 AKW1");
        break;
        
        case KMIP_BLOCK_X9102_AKW2:
        fprintf(f, "X9.102 AKW2");
        break;
        
        case KMIP_BLOCK_AEAD:
        fprintf(f, "AEAD");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_padding_method_enum(FILE *f, enum padding_method value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_PAD_NONE:
        fprintf(f, "None");
        break;
        
        case KMIP_PAD_OAEP:
        fprintf(f, "OAEP");
        break;
        
        case KMIP_PAD_PKCS5:
        fprintf(f, "PKCS5");
        break;
        
        case KMIP_PAD_SSL3:
        fprintf(f, "SSL3");
        break;
        
        case KMIP_PAD_ZEROS:
        fprintf(f, "Zeros");
        break;
        
        case KMIP_PAD_ANSI_X923:
        fprintf(f, "ANSI X9.23");
        break;
        
        case KMIP_PAD_ISO_10126:
        fprintf(f, "ISO 10126");
        break;
        
        case KMIP_PAD_PKCS1v15:
        fprintf(f, "PKCS1 v1.5");
        break;
        
        case KMIP_PAD_X931:
        fprintf(f, "X9.31");
        break;
        
        case KMIP_PAD_PSS:
        fprintf(f, "PSS");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_hashing_algorithm_enum(FILE *f, enum hashing_algorithm value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_HASH_MD2:
        fprintf(f, "MD2");
        break;
        
        case KMIP_HASH_MD4:
        fprintf(f, "MD4");
        break;
        
        case KMIP_HASH_MD5:
        fprintf(f, "MD5");
        break;
        
        case KMIP_HASH_SHA1:
        fprintf(f, "SHA-1");
        break;
        
        case KMIP_HASH_SHA224:
        fprintf(f, "SHA-224");
        break;
        
        case KMIP_HASH_SHA256:
        fprintf(f, "SHA-256");
        break;
        
        case KMIP_HASH_SHA384:
        fprintf(f, "SHA-384");
        break;
        
        case KMIP_HASH_SHA512:
        fprintf(f, "SHA-512");
        break;
        
        case KMIP_HASH_RIPEMD160:
        fprintf(f, "RIPEMD-160");
        break;
        
        case KMIP_HASH_TIGER:
        fprintf(f, "Tiger");
        break;
        
        case KMIP_HASH_WHIRLPOOL:
        fprintf(f, "Whirlpool");
        break;
        
        case KMIP_HASH_SHA512_224:
        fprintf(f, "SHA-512/224");
        break;
        
        case KMIP_HASH_SHA512_256:
        fprintf(f, "SHA-512/256");
        break;
        
        case KMIP_HASH_SHA3_224:
        fprintf(f, "SHA-3-224");
        break;
        
        case KMIP_HASH_SHA3_256:
        fprintf(f, "SHA-3-256");
        break;
        
        case KMIP_HASH_SHA3_384:
        fprintf(f, "SHA-3-384");
        break;
        
        case KMIP_HASH_SHA3_512:
        fprintf(f, "SHA-3-512");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_role_type_enum(FILE *f, enum key_role_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ROLE_BDK:
        fprintf(f, "BDK");
        break;
        
        case KMIP_ROLE_CVK:
        fprintf(f, "CVK");
        break;
        
        case KMIP_ROLE_DEK:
        fprintf(f, "DEK");
        break;
        
        case KMIP_ROLE_MKAC:
        fprintf(f, "MKAC");
        break;
        
        case KMIP_ROLE_MKSMC:
        fprintf(f, "MKSMC");
        break;
        
        case KMIP_ROLE_MKSMI:
        fprintf(f, "MKSMI");
        break;
        
        case KMIP_ROLE_MKDAC:
        fprintf(f, "MKDAC");
        break;
        
        case KMIP_ROLE_MKDN:
        fprintf(f, "MKDN");
        break;
        
        case KMIP_ROLE_MKCP:
        fprintf(f, "MKCP");
        break;
        
        case KMIP_ROLE_MKOTH:
        fprintf(f, "MKOTH");
        break;
        
        case KMIP_ROLE_KEK:
        fprintf(f, "KEK");
        break;
        
        case KMIP_ROLE_MAC16609:
        fprintf(f, "MAC16609");
        break;
        
        case KMIP_ROLE_MAC97971:
        fprintf(f, "MAC97971");
        break;
        
        case KMIP_ROLE_MAC97972:
        fprintf(f, "MAC97972");
        break;
        
        case KMIP_ROLE_MAC97973:
        fprintf(f, "MAC97973");
        break;
        
        case KMIP_ROLE_MAC97974:
        fprintf(f, "MAC97974");
        break;
        
        case KMIP_ROLE_MAC97975:
        fprintf(f, "MAC97975");
        break;
        
        case KMIP_ROLE_ZPK:
        fprintf(f, "ZPK");
        break;
        
        case KMIP_ROLE_PVKIBM:
        fprintf(f, "PVKIBM");
        break;
        
        case KMIP_ROLE_PVKPVV:
        fprintf(f, "PVKPVV");
        break;
        
        case KMIP_ROLE_PVKOTH:
        fprintf(f, "PVKOTH");
        break;
        
        case KMIP_ROLE_DUKPT:
        fprintf(f, "DUKPT");
        break;
        
        case KMIP_ROLE_IV:
        fprintf(f, "IV");
        break;
        
        case KMIP_ROLE_TRKBK:
        fprintf(f, "TRKBK");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_digital_signature_algorithm_enum(FILE *f, enum digital_signature_algorithm value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_DIGITAL_MD2_WITH_RSA:
        fprintf(f, "MD2 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_MD5_WITH_RSA:
        fprintf(f, "MD5 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA1_WITH_RSA:
        fprintf(f, "SHA-1 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA224_WITH_RSA:
        fprintf(f, "SHA-224 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA256_WITH_RSA:
        fprintf(f, "SHA-256 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA384_WITH_RSA:
        fprintf(f, "SHA-384 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_SHA512_WITH_RSA:
        fprintf(f, "SHA-512 with RSA Encryption (PKCS#1 v1.5)");
        break;
        
        case KMIP_DIGITAL_RSASSA_PSS:
        fprintf(f, "RSASSA-PSS (PKCS#1 v2.1)");
        break;
        
        case KMIP_DIGITAL_DSA_WITH_SHA1:
        fprintf(f, "DSA with SHA-1");
        break;
        
        case KMIP_DIGITAL_DSA_WITH_SHA224:
        fprintf(f, "DSA with SHA224");
        break;
        
        case KMIP_DIGITAL_DSA_WITH_SHA256:
        fprintf(f, "DSA with SHA256");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA1:
        fprintf(f, "ECDSA with SHA-1");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA224:
        fprintf(f, "ECDSA with SHA224");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA256:
        fprintf(f, "ECDSA with SHA256");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA384:
        fprintf(f, "ECDSA with SHA384");
        break;
        
        case KMIP_DIGITAL_ECDSA_WITH_SHA512:
        fprintf(f, "ECDSA with SHA512");
        break;
        
        case KMIP_DIGITAL_SHA3_256_WITH_RSA:
        fprintf(f, "SHA3-256 with RSA Encryption");
        break;
        
        case KMIP_DIGITAL_SHA3_384_WITH_RSA:
        fprintf(f, "SHA3-384 with RSA Encryption");
        break;
        
        case KMIP_DIGITAL_SHA3_512_WITH_RSA:
        fprintf(f, "SHA3-512 with RSA Encryption");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_mask_generator_enum(FILE *f, enum mask_generator value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_MASKGEN_MGF1:
        fprintf(f, "MGF1");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_wrapping_method_enum(FILE *f, enum wrapping_method value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_WRAP_ENCRYPT:
        fprintf(f, "Encrypt");
        break;
        
        case KMIP_WRAP_MAC_SIGN:
        fprintf(f, "MAC/sign");
        break;
        
        case KMIP_WRAP_ENCRYPT_MAC_SIGN:
        fprintf(f, "Encrypt then MAC/sign");
        break;
        
        case KMIP_WRAP_MAC_SIGN_ENCRYPT:
        fprintf(f, "MAC/sign then encrypt");
        break;
        
        case KMIP_WRAP_TR31:
        fprintf(f, "TR-31");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_encoding_option_enum(FILE *f, enum encoding_option value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_ENCODE_NO_ENCODING:
        fprintf(f, "No Encoding");
        break;
        
        case KMIP_ENCODE_TTLV_ENCODING:
        fprintf(f, "TTLV Encoding");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_key_wrap_type_enum(FILE *f, enum key_wrap_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_WRAPTYPE_NOT_WRAPPED:
        fprintf(f, "Not Wrapped");
        break;
        
        case KMIP_WRAPTYPE_AS_REGISTERED:
        fprintf(f, "As Registered");
        break;
        
        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_credential_type_enum(FILE *f, enum credential_type value)
{
    if(value == 0)
    {
        fprintf(f, "-");
        return;
    }
    
    switch(value)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        fprintf(f, "Username and Password");
        break;
        
        case KMIP_CRED_DEVICE:
        fprintf(f, "Device");
        break;
        
        case KMIP_CRED_ATTESTATION:
        fprintf(f, "Attestation");
        break;

        case KMIP_CRED_ONE_TIME_PASSWORD:
        fprintf(f, "One Time Password");
        break;

        case KMIP_CRED_HASHED_PASSWORD:
        fprintf(f, "Hashed Password");
        break;

        case KMIP_CRED_TICKET:
        fprintf(f, "Ticket");
        break;

        default:
        fprintf(f, "Unknown");
        break;
    };
}

void
kmip_print_cryptographic_usage_mask_enums(FILE *f, int indent, int32 value)
{
    fprintf(f, "\n");
    
    if((value & KMIP_CRYPTOMASK_SIGN) == KMIP_CRYPTOMASK_SIGN)
    {
        fprintf(f, "%*sSign\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_VERIFY) == KMIP_CRYPTOMASK_VERIFY)
    {
        fprintf(f, "%*sVerify\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_ENCRYPT) == KMIP_CRYPTOMASK_ENCRYPT)
    {
        fprintf(f, "%*sEncrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_DECRYPT) == KMIP_CRYPTOMASK_DECRYPT)
    {
        fprintf(f, "%*sDecrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_WRAP_KEY) == KMIP_CRYPTOMASK_WRAP_KEY)
    {
        fprintf(f, "%*sWrap Key\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_UNWRAP_KEY) == KMIP_CRYPTOMASK_UNWRAP_KEY)
    {
        fprintf(f, "%*sUnwrap Key\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_EXPORT) == KMIP_CRYPTOMASK_EXPORT)
    {
        fprintf(f, "%*sExport\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_MAC_GENERATE) == KMIP_CRYPTOMASK_MAC_GENERATE)
    {
        fprintf(f, "%*sMAC Generate\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_MAC_VERIFY) == KMIP_CRYPTOMASK_MAC_VERIFY)
    {
        fprintf(f, "%*sMAC Verify\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_DERIVE_KEY) == KMIP_CRYPTOMASK_DERIVE_KEY)
    {
        fprintf(f, "%*sDerive Key\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_CONTENT_COMMITMENT) == KMIP_CRYPTOMASK_CONTENT_COMMITMENT)
    {
        fprintf(f, "%*sContent Commitment\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_KEY_AGREEMENT) == KMIP_CRYPTOMASK_KEY_AGREEMENT)
    {
        fprintf(f, "%*sKey Agreement\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_CERTIFICATE_SIGN) == KMIP_CRYPTOMASK_CERTIFICATE_SIGN)
    {
        fprintf(f, "%*sCertificate Sign\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_CRL_SIGN) == KMIP_CRYPTOMASK_CRL_SIGN)
    {
        fprintf(f, "%*sCRL Sign\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM) == KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM)
    {
        fprintf(f, "%*sGenerate Cryptogram\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM) == KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM)
    {
        fprintf(f, "%*sValidate Cryptogram\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT) == KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT)
    {
        fprintf(f, "%*sTranslate Encrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_DECRYPT) == KMIP_CRYPTOMASK_TRANSLATE_DECRYPT)
    {
        fprintf(f, "%*sTranslate Decrypt\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_WRAP) == KMIP_CRYPTOMASK_TRANSLATE_WRAP)
    {
        fprintf(f, "%*sTranslate Wrap\n", indent, "");
    }
    
    if((value & KMIP_CRYPTOMASK_TRANSLATE_UNWRAP) == KMIP_CRYPTOMASK_TRANSLATE_UNWRAP)
    {
        fprintf(f, "%*sTranslate Unwrap\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_AUTHENTICATE) == KMIP_CRYPTOMASK_AUTHENTICATE)
    {
        fprintf(f, "%*sAuthenticate\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_UNRESTRICTED) == KMIP_CRYPTOMASK_UNRESTRICTED)
    {
        fprintf(f, "%*sUnrestricted\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_FPE_ENCRYPT) == KMIP_CRYPTOMASK_FPE_ENCRYPT)
    {
        fprintf(f, "%*sFPE Encrypt\n", indent, "");
    }

    if((value & KMIP_CRYPTOMASK_FPE_DECRYPT) == KMIP_CRYPTOMASK_FPE_DECRYPT)
    {
        fprintf(f, "%*sFPE Decrypt\n", indent, "");
    }
}

void
kmip_print_protection_storage_mask_enum(FILE *f, int indent, int32 value)
{
    fprintf(f, "\n");

    if((value & KMIP_PROTECT_SOFTWARE) == KMIP_PROTECT_SOFTWARE)
    {
        fprintf(f, "%*sSoftware\n", indent, "");
    }

    if((value & KMIP_PROTECT_HARDWARE) == KMIP_PROTECT_HARDWARE)
    {
        fprintf(f, "%*sHardware\n", indent, "");
    }

    if((value & KMIP_PROTECT_ON_PROCESSOR) == KMIP_PROTECT_ON_PROCESSOR)
    {
        fprintf(f, "%*sOn Processor\n", indent, "");
    }

    if((value & KMIP_PROTECT_ON_SYSTEM) == KMIP_PROTECT_ON_SYSTEM)
    {
        fprintf(f, "%*sOn System\n", indent, "");
    }

    if((value & KMIP_PROTECT_OFF_SYSTEM) == KMIP_PROTECT_OFF_SYSTEM)
    {
        fprintf(f, "%*sOff System\n", indent, "");
    }

    if((value & KMIP_PROTECT_HYPERVISOR) == KMIP_PROTECT_HYPERVISOR)
    {
        fprintf(f, "%*sHypervisor\n", indent, "");
    }

    if((value & KMIP_PROTECT_OPERATING_SYSTEM) == KMIP_PROTECT_OPERATING_SYSTEM)
    {
        fprintf(f, "%*sOperating System\n", indent, "");
    }

    if((value & KMIP_PROTECT_CONTAINER) == KMIP_PROTECT_CONTAINER)
    {
        fprintf(f, "%*sContainer\n", indent, "");
    }

    if((value & KMIP_PROTECT_ON_PREMISES) == KMIP_PROTECT_ON_PREMISES)
    {
        fprintf(f, "%*sOn Premises\n", indent, "");
    }

    if((value & KMIP_PROTECT_OFF_PREMISES) == KMIP_PROTECT_OFF_PREMISES)
    {
        fprintf(f, "%*sOff Premises\n", indent, "");
    }

    if((value & KMIP_PROTECT_SELF_MANAGED) == KMIP_PROTECT_SELF_MANAGED)
    {
        fprintf(f, "%*sSelf Managed\n", indent, "");
    }

    if((value & KMIP_PROTECT_OUTSOURCED) == KMIP_PROTECT_OUTSOURCED)
    {
        fprintf(f, "%*sOutsourced\n", indent, "");
    }

    if((value & KMIP_PROTECT_VALIDATED) == KMIP_PROTECT_VALIDATED)
    {
        fprintf(f, "%*sValidated\n", indent, "");
    }

    if((value & KMIP_PROTECT_SAME_JURISDICTION) == KMIP_PROTECT_SAME_JURISDICTION)
    {
        fprintf(f, "%*sSame Jurisdiction\n", indent, "");
    }
}

void
kmip_print_protection_storage_masks(FILE *f, int indent, ProtectionStorageMasks *value)
{
    fprintf(f, "%*sProtection Storage Masks @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->masks != NULL)
    {
        fprintf(f, "%*sMasks: %zu\n", indent + 2, "", value->masks->size);
        LinkedListItem *curr = value->masks->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sMask: %zu", indent + 4, "", count);
            int32 mask = *(int32 *)curr->data;
            kmip_print_protection_storage_mask_enum(f, indent + 6, mask);

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_integer(FILE *f, int32 value)
{
    switch(value)
    {
        case KMIP_UNSET:
        fprintf(f, "-");
        break;
        
        default:
        fprintf(f, "%d", value);
        break;
    };
}

void
kmip_print_bool(FILE *f, int32 value)
{
    switch(value)
    {
        case KMIP_TRUE:
        fprintf(f, "True");
        break;
        
        case KMIP_FALSE:
        fprintf(f, "False");
        break;
        
        default:
        fprintf(f, "-");
        break;
    };
}

void
kmip_print_text_string(FILE *f, int indent, const char *name, TextString *value)
{
    fprintf(f, "%*s%s @ %p\n", indent, "", name, (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sValue: %.*s\n", indent + 2, "", (int)value->size, value->value);
    }
    
    return;
}

void
kmip_print_byte_string(FILE *f, int indent, const char *name, ByteString *value)
{
    fprintf(f, "%*s%s @ %p\n", indent, "", name, (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sValue:", indent + 2, "");
        for(size_t i = 0; i < value->size; i++)
        {
            if(i % 16 == 0)
            {
                fprintf(f, "\n%*s0x", indent + 4, "");
            }
            fprintf(f, "%02X", value->value[i]);
        }
        fprintf(f, "\n");
    }
    
    return;
}

void
kmip_print_date_time(FILE *f, int64 value)
{
    if(value <= KMIP_UNSET)
    {
        fprintf(f, "-");
    }
    else
    {
        /* NOTE: This cast is only problematic if the current year is 2038+
        *  AND time_t is equivalent to an int32 data type. If these conditions
        *  are true, the cast will overflow and the time value will appear to
        *  be set in 1901+.
        *
        *  No system should be using 32-bit time in 2038. If this impacts you,
        *  upgrade your system.
        */
        time_t t = (time_t)value;

        /* NOTE: The data pointed to by utc_time may change if gmtime is
        *  called again before utc_time is used.
        */
        struct tm *utc_time = gmtime(&t);
        fprintf(f, "%s", asctime(utc_time));
    }
    return;
}

void
kmip_print_protocol_version(FILE *f, int indent, ProtocolVersion *value)
{
    fprintf(f, "%*sProtocol Version @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sMajor: %d\n", indent + 2, "", value->major);
        fprintf(f, "%*sMinor: %d\n", indent + 2, "", value->minor);
    }
    
    return;
}

void
kmip_print_name(FILE *f, int indent, Name *value)
{
    fprintf(f, "%*sName @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Name Value", value->value);
        
        fprintf(f, "%*sName Type: ", indent + 2, "");
        kmip_print_name_type_enum(f, value->type);
        fprintf(f, "\n");
    }
}

void
kmip_print_nonce(FILE *f, int indent, Nonce *value)
{
    fprintf(f, "%*sNonce @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_byte_string(f, indent + 2, "Nonce ID", value->nonce_id);
        kmip_print_byte_string(f, indent + 2, "Nonce Value", value->nonce_value);
    }
    
    return;
}

void
kmip_print_application_specific_information(FILE *f, int indent, ApplicationSpecificInformation *value)
{
    fprintf(f, "%*sApplication Specific Information @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Application Namespace", value->application_namespace);
        kmip_print_text_string(f, indent + 2, "Application Data", value->application_data);
    }
}

void
kmip_print_cryptographic_parameters(FILE *f, int indent, CryptographicParameters *value)
{
    fprintf(f, "%*sCryptographic Parameters @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sBlock Cipher Mode: ", indent + 2, "");
        kmip_print_block_cipher_mode_enum(f, value->block_cipher_mode);
        fprintf(f, "\n");
        
        fprintf(f, "%*sPadding Method: ", indent + 2, "");
        kmip_print_padding_method_enum(f, value->padding_method);
        fprintf(f, "\n");
        
        fprintf(f, "%*sHashing Algorithm: ", indent + 2, "");
        kmip_print_hashing_algorithm_enum(f, value->hashing_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Role Type: ", indent + 2, "");
        kmip_print_key_role_type_enum(f, value->key_role_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sDigital Signature Algorithm: ", indent + 2, "");
        kmip_print_digital_signature_algorithm_enum(f, value->digital_signature_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sCryptographic Algorithm: ", indent + 2, "");
        kmip_print_cryptographic_algorithm_enum(f, value->cryptographic_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sRandom IV: ", indent + 2, "");
        kmip_print_bool(f, value->random_iv);
        fprintf(f, "\n");
        
        fprintf(f, "%*sIV Length: ", indent + 2, "");
        kmip_print_integer(f, value->iv_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sTag Length: ", indent + 2, "");
        kmip_print_integer(f, value->tag_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sFixed Field Length: ", indent + 2, "");
        kmip_print_integer(f, value->fixed_field_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sInvocation Field Length: ", indent + 2, "");
        kmip_print_integer(f, value->invocation_field_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sCounter Length: ", indent + 2, "");
        kmip_print_integer(f, value->counter_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sInitial Counter Value: ", indent + 2, "");
        kmip_print_integer(f, value->initial_counter_value);
        fprintf(f, "\n");
        
        fprintf(f, "%*sSalt Length: ", indent + 2, "");
        kmip_print_integer(f, value->salt_length);
        fprintf(f, "\n");
        
        fprintf(f, "%*sMask Generator: ", indent + 2, "");
        kmip_print_mask_generator_enum(f, value->mask_generator);
        fprintf(f, "\n");
        
        fprintf(f, "%*sMask Generator Hashing Algorithm: ", indent + 2, "");
        kmip_print_hashing_algorithm_enum(f, value->mask_generator_hashing_algorithm);
        fprintf(f, "\n");
        
        kmip_print_byte_string(f, indent + 2, "P Source", value->p_source);
        
        fprintf(f, "%*sTrailer Field: ", indent + 2, "");
        kmip_print_integer(f, value->trailer_field);
        fprintf(f, "\n");
    }
}

void
kmip_print_encryption_key_information(FILE *f, int indent, EncryptionKeyInformation *value)
{
    fprintf(f, "%*sEncryption Key Information @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        
        kmip_print_cryptographic_parameters(f, indent + 2, value->cryptographic_parameters);
    }
}

void
kmip_print_mac_signature_key_information(FILE *f, int indent, MACSignatureKeyInformation *value)
{
    fprintf(f, "%*sMAC/Signature Key Information @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        
        kmip_print_cryptographic_parameters(f, indent + 2, value->cryptographic_parameters);
    }
}

void
kmip_print_key_wrapping_data(FILE *f, int indent, KeyWrappingData *value)
{
    fprintf(f, "%*sKey Wrapping Data @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sWrapping Method: ", indent + 2, "");
        kmip_print_wrapping_method_enum(f, value->wrapping_method);
        fprintf(f, "\n");
        
        kmip_print_encryption_key_information(f, indent + 2, value->encryption_key_info);
        
        kmip_print_mac_signature_key_information(f, indent + 2, value->mac_signature_key_info);
        
        kmip_print_byte_string(f, indent + 2, "MAC/Signature", value->mac_signature);
        
        kmip_print_byte_string(f, indent + 2, "IV/Counter/Nonce", value->iv_counter_nonce);
        
        fprintf(f, "%*sEncoding Option: ", indent + 2, "");
        kmip_print_encoding_option_enum(f, value->encoding_option);
        fprintf(f, "\n");
    }
    
    return;
}

void
kmip_print_attribute_value(FILE *f, int indent, enum attribute_type type, void *value)
{
    fprintf(f, "%*sAttribute Value: ", indent, "");
    
    switch(type)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            fprintf(f, "\n");
            kmip_print_application_specific_information(f, indent + 2, value);
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        fprintf(f, "\n");
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value);
        break;
        
        case KMIP_ATTR_NAME:
        fprintf(f, "\n");
        kmip_print_name(f, indent + 2, value);
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        kmip_print_object_type_enum(f, *(enum object_type *)value);
        fprintf(f, "\n");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        kmip_print_cryptographic_algorithm_enum(f, *(enum cryptographic_algorithm *)value);
        fprintf(f, "\n");
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        fprintf(f, "%d\n", *(int32 *)value);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        fprintf(f, "\n");
        kmip_print_text_string(f, indent + 2, "Operation Policy Name", value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        kmip_print_cryptographic_usage_mask_enums(f, indent + 2, *(int32 *)value);
        break;
        
        case KMIP_ATTR_STATE:
        kmip_print_state_enum(f, *(enum state *)value);
        fprintf(f, "\n");
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            fprintf(f, "\n");
            kmip_print_text_string(f, indent + 2, "Object Group", value);
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        case KMIP_ATTR_DEACTIVATION_DATE:
        case KMIP_ATTR_PROCESS_START_DATE:
        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            fprintf(f, "\n");
            kmip_print_date_time(f, *(int64 *)value);
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            fprintf(f, "\n");
            kmip_print_cryptographic_parameters(f, indent + 2, value);
        } break;

        default:
        fprintf(f, "Unknown\n");
        break;
    };
}

void
kmip_print_attribute(FILE *f, int indent, Attribute *value)
{
    fprintf(f, "%*sAttribute @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sAttribute Name: ", indent + 2, "");
        kmip_print_attribute_type_enum(f, value->type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sAttribute Index: ", indent + 2, "");
        kmip_print_integer(f, value->index);
        fprintf(f, "\n");
        
        kmip_print_attribute_value(f, indent + 2, value->type, value->value);
    }
    
    return;
}

void
kmip_print_key_material(FILE *f, int indent, enum key_format_type format, void *value)
{
    switch(format)
    {
        case KMIP_KEYFORMAT_RAW:
        case KMIP_KEYFORMAT_OPAQUE:
        case KMIP_KEYFORMAT_PKCS1:
        case KMIP_KEYFORMAT_PKCS8:
        case KMIP_KEYFORMAT_X509:
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        kmip_print_byte_string(f, indent, "Key Material", (ByteString *)value);
        break;
        
        default:
        fprintf(f, "%*sUnknown Key Material @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_key_value(FILE *f, int indent, enum type type, enum key_format_type format, void *value)
{
    switch(type)
    {
        case KMIP_TYPE_BYTE_STRING:
        kmip_print_byte_string(f, indent, "Key Value", (ByteString *)value);
        break;
        
        case KMIP_TYPE_STRUCTURE:
        fprintf(f, "%*sKey Value @ %p\n", indent, "", value);
        
        if(value != NULL)
        {
            KeyValue key_value = *(KeyValue *)value;
            kmip_print_key_material(f, indent + 2, format, key_value.key_material);
            fprintf(f, "%*sAttributes: %zu\n", indent + 2, "", key_value.attribute_count);
            for(size_t i = 0; i < key_value.attribute_count; i++)
            {
                kmip_print_attribute(f, indent + 2, &key_value.attributes[i]);
            }
        }
        break;
        
        default:
        fprintf(f, "%*sUnknown Key Value @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_key_block(FILE *f, int indent, KeyBlock *value)
{
    fprintf(f, "%*sKey Block @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sKey Format Type: ", indent + 2, "");
        kmip_print_key_format_type_enum(f, value->key_format_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Compression Type: ", indent + 2, "");
        kmip_print_key_compression_type_enum(f, value->key_compression_type);
        fprintf(f, "\n");
        
        kmip_print_key_value(f, indent + 2, value->key_value_type, value->key_format_type, value->key_value);
        
        fprintf(f, "%*sCryptographic Algorithm: ", indent + 2, "");
        kmip_print_cryptographic_algorithm_enum(f, value->cryptographic_algorithm);
        fprintf(f, "\n");
        
        fprintf(f, "%*sCryptographic Length: %d\n", indent + 2, "", value->cryptographic_length);
        
        kmip_print_key_wrapping_data(f, indent + 2, value->key_wrapping_data);
    }
    
    return;
}

void
kmip_print_symmetric_key(FILE *f, int indent, SymmetricKey *value)
{
    fprintf(f, "%*sSymmetric Key @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_key_block(f, indent + 2, value->key_block);
    }
    
    return;
}

void
kmip_print_object(FILE *f, int indent, enum object_type type, void *value)
{
    switch(type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        kmip_print_symmetric_key(f, indent, (SymmetricKey *)value);
        break;
        
        default:
        fprintf(f, "%*sUnknown Object @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_key_wrapping_specification(FILE *f, int indent, KeyWrappingSpecification *value)
{
    fprintf(f, "%*sKey Wrapping Specification @ %p\n", indent, "", (void *)value);
}

void
kmip_print_attributes(FILE *f, int indent, Attributes *value)
{
    fprintf(f, "%*sAttributes @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->attribute_list != NULL)
    {
        fprintf(f, "%*sAttributes: %zu\n", indent + 2, "", value->attribute_list->size);
        LinkedListItem *curr = value->attribute_list->head;
        while(curr != NULL)
        {
            Attribute *attribute = (Attribute *)curr->data;
            kmip_print_attribute(f, indent + 4, attribute);

            curr = curr->next;
        }
    }
}

void
kmip_print_template_attribute(FILE *f, int indent, TemplateAttribute *value)
{
    fprintf(f, "%*sTemplate Attribute @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sNames: %zu\n", indent + 2, "", value->name_count);
        for(size_t i = 0; i < value->name_count; i++)
        {
            kmip_print_name(f, indent + 4, &value->names[i]);
        }
        
        fprintf(f, "%*sAttributes: %zu\n", indent + 2, "", value->attribute_count);
        for(size_t i = 0; i< value->attribute_count; i++)
        {
            kmip_print_attribute(f, indent + 4, &value->attributes[i]);
        }
    }
}

void
kmip_print_create_request_payload(FILE *f, int indent, CreateRequestPayload *value)
{
    fprintf(f, "%*sCreate Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_template_attribute(f, indent + 2, value->template_attribute);
        kmip_print_attributes(f, indent + 2, value->attributes);
        kmip_print_protection_storage_masks(f, indent + 2, value->protection_storage_masks);
    }
}

void
kmip_print_create_response_payload(FILE *f, int indent, CreateResponsePayload *value)
{
    fprintf(f, "%*sCreate Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_template_attribute(f, indent + 2, value->template_attribute);
    }
}

void
kmip_print_register_request_payload(FILE *f, int indent, RegisterRequestPayload *value)
{
    fprintf(f, "%*sCreate Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_template_attribute(f, indent + 2, value->template_attribute);
        kmip_print_attributes(f, indent + 2, value->attributes);
        kmip_print_protection_storage_masks(f, indent + 2, value->protection_storage_masks);

        kmip_print_symmetric_key(f, indent + 2, &value->object);
    }
}

void
kmip_print_register_response_payload(FILE *f, int indent, RegisterResponsePayload *value)
{
    fprintf(f, "%*sCreate Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_template_attribute(f, indent + 2, value->template_attribute);
    }
}

void
kmip_print_get_request_payload(FILE *f, int indent, GetRequestPayload *value)
{
    fprintf(f, "%*sGet Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        
        fprintf(f, "%*sKey Format Type: ", indent + 2, "");
        kmip_print_key_format_type_enum(f, value->key_format_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Wrap Type: ", indent + 2, "");
        kmip_print_key_wrap_type_enum(f, value->key_wrap_type);
        fprintf(f, "\n");
        
        fprintf(f, "%*sKey Compression Type: ", indent + 2, "");
        kmip_print_key_compression_type_enum(f, value->key_compression_type);
        fprintf(f, "\n");
        
        kmip_print_key_wrapping_specification(f, indent + 2, value->key_wrapping_spec);
    }
}

void
kmip_print_get_response_payload(FILE *f, int indent, GetResponsePayload *value)
{
    fprintf(f, "%*sGet Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sObject Type: ", indent + 2, "");
        kmip_print_object_type_enum(f, value->object_type);
        fprintf(f, "\n");
        
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_object(f, indent + 2, value->object_type, value->object);
    }
    
    return;
}

void
kmip_print_get_attribute_request_payload(FILE *f, int indent, GetAttributeRequestPayload *value)
{
    fprintf(f, "%*sGet Attribute Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->attribute_name);
    }
}

void
kmip_print_get_attribute_response_payload(FILE *f, int indent, GetAttributeResponsePayload *value)
{
    fprintf(f, "%*sGet Response Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
        kmip_print_attribute(f, indent + 2, value->attribute);
    }
    
    return;
}

void
kmip_print_destroy_request_payload(FILE *f, int indent, DestroyRequestPayload *value)
{
    fprintf(f, "%*sDestroy Request Payload @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
    }
}

void
kmip_print_destroy_response_payload(FILE *f, int indent, DestroyResponsePayload *value)
{
    fprintf(f, "%*sDestroy Response Payload @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Unique Identifier", value->unique_identifier);
    }
}

void
kmip_print_request_payload(FILE *f, int indent, enum operation type, void *value)
{
    switch(type)
    {
        case KMIP_OP_CREATE:
        kmip_print_create_request_payload(f, indent, value);
        break;

        case KMIP_OP_REGISTER:
        kmip_print_register_request_payload(f, indent, value);
        break;
        
        case KMIP_OP_GET:
        kmip_print_get_request_payload(f, indent, (GetRequestPayload *)value);
        break;

        case KMIP_OP_GET_ATTRIBUTES:
        kmip_print_get_attribute_request_payload(f, indent, (GetAttributeRequestPayload *)value);
        break;
        
        case KMIP_OP_DESTROY:
        kmip_print_destroy_request_payload(f, indent, value);
        break;
        
        case KMIP_OP_QUERY:
        kmip_print_query_request_payload(f, indent, value);
        break;

        case KMIP_OP_LOCATE:
        kmip_print_locate_request_payload(f, indent, value);
        break;

        default:
        fprintf(f, "%*sUnknown Payload @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_response_payload(FILE *f, int indent, enum operation type, void *value)
{
    switch(type)
    {
        case KMIP_OP_CREATE:
        kmip_print_create_response_payload(f, indent, value);
        break;

        case KMIP_OP_REGISTER:
        kmip_print_register_response_payload(f, indent, value);
        break;
        
        case KMIP_OP_GET:
        kmip_print_get_response_payload(f, indent, (GetResponsePayload *)value);
        break;

        case KMIP_OP_GET_ATTRIBUTES:
        kmip_print_get_attribute_response_payload(f, indent, (GetAttributeResponsePayload *)value);
        break;
        
        case KMIP_OP_DESTROY:
        kmip_print_destroy_response_payload(f, indent, value);
        break;
        
        case KMIP_OP_QUERY:
        kmip_print_query_response_payload(f, indent, value);
        break;

        case KMIP_OP_LOCATE:
        kmip_print_locate_response_payload(f, indent, value);
        break;

        default:
        fprintf(f, "%*sUnknown Payload @ %p\n", indent, "", value);
        break;
    };
}

void
kmip_print_username_password_credential(FILE *f, int indent, UsernamePasswordCredential *value)
{
    fprintf(f, "%*sUsername/Password Credential @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Username", value->username);
        kmip_print_text_string(f, indent + 2, "Password", value->password);
    }
}

void
kmip_print_device_credential(FILE *f, int indent, DeviceCredential *value)
{
    fprintf(f, "%*sDevice Credential @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f, indent + 2, "Device Serial Number", value->device_serial_number);
        kmip_print_text_string(f, indent + 2, "Password", value->password);
        kmip_print_text_string(f, indent + 2, "Device Identifier", value->device_identifier);
        kmip_print_text_string(f, indent + 2, "Network Identifier", value->network_identifier);
        kmip_print_text_string(f, indent + 2, "Machine Identifier", value->machine_identifier);
        kmip_print_text_string(f, indent + 2, "Media Identifier", value->media_identifier);
    }
}

void
kmip_print_attestation_credential(FILE *f, int indent, AttestationCredential *value)
{
    fprintf(f, "%*sAttestation Credential @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_nonce(f, indent + 2, value->nonce);
        fprintf(f, "%*sAttestation Type: ", indent + 2, "");
        kmip_print_attestation_type_enum(f, value->attestation_type);
        fprintf(f, "\n");
        kmip_print_byte_string(f, indent + 2, "Attestation Measurement", value->attestation_measurement);
        kmip_print_byte_string(f, indent + 2, "Attestation Assertion", value->attestation_assertion);
    }
}

void
kmip_print_credential_value(FILE *f, int indent, enum credential_type type, void *value)
{
    fprintf(f, "%*sCredential Value @ %p\n", indent, "", value);
    
    if(value != NULL)
    {
        switch(type)
        {
            case KMIP_CRED_USERNAME_AND_PASSWORD:
            kmip_print_username_password_credential(f, indent + 2, value);
            break;
            
            case KMIP_CRED_DEVICE:
            kmip_print_device_credential(f, indent + 2, value);
            break;
            
            case KMIP_CRED_ATTESTATION:
            kmip_print_attestation_credential(f, indent + 2, value);
            break;
            
            default:
            fprintf(f, "%*sUnknown Credential @ %p\n", indent + 2, "", value);
            break;
        };
    }
}

void
kmip_print_credential(FILE *f, int indent, Credential *value)
{
    fprintf(f, "%*sCredential @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sCredential Type: ", indent + 2, "");
        kmip_print_credential_type_enum(f, value->credential_type);
        fprintf(f, "\n");
        
        kmip_print_credential_value(f, indent + 2, value->credential_type, value->credential_value);
    }
}

void
kmip_print_authentication(FILE *f, int indent, Authentication *value)
{
    fprintf(f, "%*sAuthentication @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_credential(f, indent + 2, value->credential);
    }
}

void
kmip_print_request_batch_item(FILE *f, int indent, RequestBatchItem *value)
{
    fprintf(f, "%*sRequest Batch Item @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sOperation: ", indent + 2, "");
        kmip_print_operation_enum(f, value->operation);
        fprintf(f, "\n");

        fprintf(f, "%*sEphemeral: ", indent + 2, "");
        kmip_print_bool(f, value->ephemeral);
        fprintf(f, "\n");

        kmip_print_byte_string(f, indent + 2, "Unique Batch Item ID", value->unique_batch_item_id);
        kmip_print_request_payload(f, indent + 2, value->operation, value->request_payload);
    }
}

void
kmip_print_response_batch_item(FILE *f, int indent, ResponseBatchItem *value)
{
    fprintf(f, "%*sResponse Batch Item @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        fprintf(f, "%*sOperation: ", indent + 2, "");
        kmip_print_operation_enum(f, value->operation);
        fprintf(f, "\n");
        
        kmip_print_byte_string(f, indent + 2, "Unique Batch Item ID", value->unique_batch_item_id);
        
        fprintf(f, "%*sResult Status: ", indent + 2, "");
        kmip_print_result_status_enum(f, value->result_status);
        fprintf(f, "\n");
        
        fprintf(f, "%*sResult Reason: ", indent + 2, "");
        kmip_print_result_reason_enum(f, value->result_reason);
        fprintf(f, "\n");
        
        kmip_print_text_string(f, indent + 2, "Result Message", value->result_message);
        kmip_print_byte_string(f, indent + 2, "Asynchronous Correlation Value", value->asynchronous_correlation_value);
        
        kmip_print_response_payload(f, indent + 2, value->operation, value->response_payload);
    }
    
    return;
}

void
kmip_print_request_header(FILE *f, int indent, RequestHeader *value)
{
    fprintf(f, "%*sRequest Header @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_protocol_version(f, indent + 2, value->protocol_version);

        fprintf(f, "%*sMaximum Response Size: ", indent + 2, "");
        kmip_print_integer(f, value->maximum_response_size);
        fprintf(f, "\n");

        kmip_print_text_string(f, indent + 2, "Client Correlation Value", value->client_correlation_value);
        kmip_print_text_string(f, indent + 2, "Server Correlation Value", value->server_correlation_value);
        fprintf(f, "%*sAsynchronous Indicator: ", indent + 2, "");
        kmip_print_bool(f, value->asynchronous_indicator);
        fprintf(f, "\n");
        fprintf(f, "%*sAttestation Capable Indicator: ", indent + 2, "");
        kmip_print_bool(f, value->attestation_capable_indicator);
        fprintf(f, "\n");
        fprintf(f, "%*sAttestation Types: %zu\n", indent + 2, "", value->attestation_type_count);
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            /* TODO (ph) Add enum value -> string functionality. */
            fprintf(f, "%*sAttestation Type: %s\n", indent + 4, "", "???");
        }
        kmip_print_authentication(f, indent + 2, value->authentication);
        fprintf(f, "%*sBatch Error Continuation Option: ", indent + 2, "");
        kmip_print_batch_error_continuation_option(f, value->batch_error_continuation_option);
        fprintf(f, "\n");
        fprintf(f, "%*sBatch Order Option: ", indent + 2, "");
        kmip_print_bool(f, value->batch_order_option);
        fprintf(f, "\n");
        fprintf(f, "%*sTime Stamp: ", indent + 2, "");
        kmip_print_date_time(f, value->time_stamp);
        fprintf(f, "\n");
        fprintf(f, "%*sBatch Count: %d\n", indent + 2, "", value->batch_count);
    }
}

void
kmip_print_response_header(FILE *f, int indent, ResponseHeader *value)
{
    fprintf(f, "%*sResponse Header @ %p\n", indent, "", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_protocol_version(f, indent + 2, value->protocol_version);
        fprintf(f, "%*sTime Stamp: ", indent + 2, "");
        kmip_print_date_time(f, value->time_stamp);
        fprintf(f, "\n");
        kmip_print_nonce(f, indent + 2, value->nonce);

        kmip_print_byte_string(f, indent + 2, "Server Hashed Password", value->server_hashed_password);

        fprintf(f, "%*sAttestation Types: %zu\n", indent + 2, "", value->attestation_type_count);
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            /* TODO (ph) Add enum value -> string functionality. */
            fprintf(f, "%*sAttestation Type: %s\n", indent + 4, "", "???");
        }
        kmip_print_text_string(f, indent + 2, "Client Correlation Value", value->client_correlation_value);
        kmip_print_text_string(f, indent + 2, "Server Correlation Value", value->server_correlation_value);
        fprintf(f, "%*sBatch Count: %d\n", indent + 2, "", value->batch_count);
    }
}

void
kmip_print_request_message(FILE *f, RequestMessage *value)
{
    fprintf(f, "Request Message @ %p\n", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_request_header(f, 2, value->request_header);
        fprintf(f, "%*sBatch Items: %zu\n", 2, "", value->batch_count);
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            kmip_print_request_batch_item(f, 4, &value->batch_items[i]);
        }
    }
    
    return;
}

void
kmip_print_response_message(FILE *f, ResponseMessage *value)
{
    fprintf(f, "Response Message @ %p\n", (void *)value);
    
    if(value != NULL)
    {
        kmip_print_response_header(f, 2, value->response_header);
        fprintf(f, "  Batch Items: %zu\n", value->batch_count);
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            kmip_print_response_batch_item(f, 4, &value->batch_items[i]);
        }
    }
    
    return;
}

void
kmip_print_query_function_enum(FILE* f, int indent, enum query_function value)
{
    if(value == 0)
    {
        fprintf(f, "%*s-", indent, "");
        return;
    }

    switch(value)
    {
        /* KMIP 1.0 */
        case KMIP_QUERY_OPERATIONS:
            fprintf(f, "%*sOperations", indent, "");
            break;
        case KMIP_QUERY_OBJECTS:
            fprintf(f, "%*sObjects", indent, "");
            break;
        case KMIP_QUERY_SERVER_INFORMATION:
            fprintf(f, "%*sServer Information", indent, "");
            break;
        case KMIP_QUERY_APPLICATION_NAMESPACES:
            fprintf(f, "%*sApplication namespaces", indent, "");
            break;
        /* KMIP 1.1 */
        case KMIP_QUERY_EXTENSION_LIST:
            fprintf(f, "%*sExtension list", indent, "");
            break;
        case KMIP_QUERY_EXTENSION_MAP:
            fprintf(f, "%*sExtension Map", indent, "");
            break;
        /* KMIP 1.2 */
        case KMIP_QUERY_ATTESTATION_TYPES:
            fprintf(f, "%*sAttestation Types", indent, "");
            break;
        /* KMIP 1.3 */
        case KMIP_QUERY_RNGS:
            fprintf(f, "%*sRNGS", indent, "");
            break;
        case KMIP_QUERY_VALIDATIONS:
            fprintf(f, "%*sValidations", indent, "");
            break;
        case KMIP_QUERY_PROFILES:
            fprintf(f, "%*sProfiles", indent, "");
            break;
        case KMIP_QUERY_CAPABILITIES:
            fprintf(f, "%*sCapabilities", indent, "");
            break;
        case KMIP_QUERY_CLIENT_REGISTRATION_METHODS:
            fprintf(f, "%*sRegistration Methods", indent, "");
            break;
        /* KMIP 2.0 */
        case KMIP_QUERY_DEFAULTS_INFORMATION:
            fprintf(f, "%*sDefaults Information", indent, "");
            break;
        case KMIP_QUERY_STORAGE_PROTECTION_MASKS:
            fprintf(f, "%*sStorage Protection Masks", indent, "");
            break;

        default:
        fprintf(f, "%*sUnknown", indent, "");
        break;
    };
}

void
kmip_print_query_functions(FILE* f, int indent, Functions* value)
{
    fprintf(f, "%*sQuery Functions @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->function_list != NULL)
    {
        fprintf(f, "%*sFunctions: %zu\n", indent + 2, "", value->function_list->size);
        LinkedListItem *curr = value->function_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sFunction: %zu: ", indent + 4, "", count);
            int32 func = *(int32 *)curr->data;
            kmip_print_query_function_enum(f, indent + 6, func);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}


void
kmip_print_operations(FILE* f, int indent, Operations *value)
{
    fprintf(f, "%*sOperations @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->operation_list != NULL)
    {
        fprintf(f, "%*sOperations: %zu\n", indent + 2, "", value->operation_list->size);
        LinkedListItem *curr = value->operation_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sOperation: %zu: ", indent + 4, "", count);
            int32 oper = *(int32 *)curr->data;
            kmip_print_operation_enum(f, oper);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_object_types(FILE* f, int indent, ObjectTypes* value)
{
    fprintf(f, "%*sObjects @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->object_list != NULL )
    {
        fprintf(f, "%*sObjects: %zu\n", indent + 2, "", value->object_list->size);
        LinkedListItem *curr = value->object_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sObject: %zu: ", indent + 4, "", count);
            int32 obj = *(int32 *)curr->data;
            kmip_print_object_type_enum(f, obj);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_alternative_endpoints(FILE* f, int indent, AltEndpoints* value)
{
    fprintf(f, "%*sAlt Endpointss @ %p\n", indent, "", (void *)value);

    if(value != NULL &&
       value->endpoint_list != NULL )
    {
        fprintf(f, "%*sAlt Endpoints: %zu\n", indent + 2, "", value->endpoint_list->size);
        LinkedListItem *curr = value->endpoint_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sEndpoint: %zu: ", indent + 4, "", count);
            TextString* endpoint = (TextString*)curr->data;
            kmip_print_text_string(f, indent + 2, "Endpoint", endpoint);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_print_server_information(FILE* f, int indent, ServerInformation* value)
{
    fprintf(f,"%*sServer Information @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_text_string(f,indent + 2, "Server Name", value->server_name);
        kmip_print_text_string(f,indent + 2, "Server Serial Number", value->server_serial_number);
        kmip_print_text_string(f,indent + 2, "Server Version", value->server_version);
        kmip_print_text_string(f,indent + 2, "Server Load", value->server_load);
        kmip_print_text_string(f,indent + 2, "Product Name", value->product_name);
        kmip_print_text_string(f,indent + 2, "Build Level", value->build_level);
        kmip_print_text_string(f,indent + 2, "Build Date", value->build_date);
        kmip_print_text_string(f,indent + 2, "Cluster info", value->cluster_info);

        kmip_print_alternative_endpoints(f,indent+2, value->alternative_failover_endpoints);
    }
}


void
kmip_print_query_response_payload(FILE* f, int indent, QueryResponsePayload *value)
{
    fprintf(f,"%*sQuery response @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        kmip_print_operations(f,indent, value->operations);
        kmip_print_object_types(f,indent, value->objects);
        kmip_print_text_string(f,indent, "Vendor ID", value->vendor_identification);
        kmip_print_server_information(f,indent, value->server_information);
    }
}

void
kmip_print_query_request_payload(FILE* f, int indent, QueryRequestPayload *value)
{
    fprintf(f,"%*sQuery request @ %p\n", indent, "", (void *)value);

    if(value != NULL)
        kmip_print_query_functions(f, indent, value->functions);
}


/*
Freeing Functions
*/

void
kmip_free_buffer(KMIP *ctx, void *buffer, size_t size)
{
    if(ctx == NULL)
    {
        return;
    }
    
    ctx->memset_func(buffer, 0, size);
    ctx->free_func(ctx->state, buffer);
}

void
kmip_free_text_string(KMIP *ctx, TextString *value)
{
    if(ctx == NULL)
    {
        return;
    }
    
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            ctx->memset_func(value->value, 0, value->size);
            ctx->free_func(ctx->state, value->value);
            
            value->value = NULL;
        }
        
        value->size = 0;
    }
    
    return;
}

void
kmip_free_byte_string(KMIP *ctx, ByteString *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            ctx->memset_func(value->value, 0, value->size);
            ctx->free_func(ctx->state, value->value);
            
            value->value = NULL;
        }
        
        value->size = 0;
    }
    
    return;
}

void
kmip_free_name(KMIP *ctx, Name *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            kmip_free_text_string(ctx, value->value);
            ctx->free_func(ctx->state, value->value);
            
            value->value = NULL;
        }
        
        value->type = 0;
    }
    
    return;
}

void
kmip_free_protection_storage_masks(KMIP *ctx, ProtectionStorageMasks *value)
{
    if(value != NULL)
    {
        if(value->masks != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->masks);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->masks);
            }
            ctx->free_func(ctx->state, value->masks);
            value->masks = NULL;
        }
    }

    return;
}

void
kmip_free_attribute(KMIP *ctx, Attribute *value)
{
    if(value != NULL)
    {
        if(value->value != NULL)
        {
            switch(value->type)
            {
                case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
                {
                    kmip_free_application_specific_information(ctx, value->value);
                }
                break;

                case KMIP_ATTR_UNIQUE_IDENTIFIER:
                kmip_free_text_string(ctx, value->value);
                break;
                
                case KMIP_ATTR_NAME:
                kmip_free_name(ctx, value->value);
                break;
                
                case KMIP_ATTR_OBJECT_TYPE:
                *(int32*)value->value = 0;
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
                *(int32*)value->value = 0;
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
                *(int32*)value->value = KMIP_UNSET;
                break;
                
                case KMIP_ATTR_OPERATION_POLICY_NAME:
                kmip_free_text_string(ctx, value->value);
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
                *(int32*)value->value = KMIP_UNSET;
                break;
                
                case KMIP_ATTR_STATE:
                *(int32*)value->value = 0;
                break;

                case KMIP_ATTR_OBJECT_GROUP:
                {
                    kmip_free_text_string(ctx, value->value);
                }
                break;

                case KMIP_ATTR_ACTIVATION_DATE:
                case KMIP_ATTR_DEACTIVATION_DATE:
                case KMIP_ATTR_PROCESS_START_DATE:
                case KMIP_ATTR_PROTECT_STOP_DATE:
                {
                    *(int64*)value->value = KMIP_UNSET;
                } break;

                case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
                {
                    kmip_free_cryptographic_parameters(ctx, value->value);
                } break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know what the */
                /*      actual type, size, or value of value->value is. We can   */
                /*      still free it but we cannot securely zero the memory. We */
                /*      also do not know how to free any possible substructures  */
                /*      pointed to within value->value.                          */
                /*                                                               */
                /*      Avoid hitting this case at all costs.                    */
                break;
            };
            
            ctx->free_func(ctx->state, value->value);
            value->value = NULL;
        }
        
        value->type = 0;
        value->index = KMIP_UNSET;
    }
    
    return;
}

void
kmip_free_attributes(KMIP *ctx, Attributes *value)
{
    if(value != NULL)
    {
        if(value->attribute_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->attribute_list);
            while(curr != NULL)
            {
                Attribute *attribute = (Attribute *)curr->data;
                kmip_free_attribute(ctx, attribute);
                ctx->free_func(ctx->state, attribute);
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->attribute_list);
            }
            ctx->free_func(ctx->state, value->attribute_list);

            value->attribute_list = NULL;
        }
    }

    return;
}

void
kmip_free_template_attribute(KMIP *ctx, TemplateAttribute *value)
{
    if(value != NULL)
    {
        if(value->names != NULL)
        {
            for(size_t i = 0; i < value->name_count; i++)
            {
                kmip_free_name(ctx, &value->names[i]);
            }
            ctx->free_func(ctx->state, value->names);
            
            value->names = NULL;
        }
        
        value->name_count = 0;
        
        if(value->attributes != NULL)
        {
            for(size_t i = 0; i < value->attribute_count; i++)
            {
                kmip_free_attribute(ctx, &value->attributes[i]);
            }
            ctx->free_func(ctx->state, value->attributes);
            
            value->attributes = NULL;
        }
        
        value->attribute_count = 0;
    }
    
    return;
}

void
kmip_free_transparent_symmetric_key(KMIP *ctx, TransparentSymmetricKey *value)
{
    if(value != NULL)
    {
        if(value->key != NULL)
        {
            kmip_free_byte_string(ctx, value->key);
            
            ctx->free_func(ctx->state, value->key);
            value->key = NULL;
        }
    }
    
    return;
}

void
kmip_free_key_material(KMIP *ctx, enum key_format_type format, void **value)
{
    if(value != NULL)
    {
        if(*value != NULL)
        {
            switch(format)
            {
                case KMIP_KEYFORMAT_RAW:
                case KMIP_KEYFORMAT_OPAQUE:
                case KMIP_KEYFORMAT_PKCS1:
                case KMIP_KEYFORMAT_PKCS8:
                case KMIP_KEYFORMAT_X509:
                case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
                kmip_free_byte_string(ctx, *value);
                break;
                
                case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
                kmip_free_transparent_symmetric_key(ctx, *value);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know   */
                /*      what the actual type, size, or value of value is. */
                /*      We can still free it but we cannot securely zero  */
                /*      the memory. We also do not know how to free any   */
                /*      possible substructures pointed to within value.   */
                /*                                                        */
                /*      Avoid hitting this case at all costs.             */
                break;
            };
            
            ctx->free_func(ctx->state, *value);
            *value = NULL;
        }
    }
    
    return;
}

void
kmip_free_key_value(KMIP *ctx, enum key_format_type format, KeyValue *value)
{
    if(value != NULL)
    {
        if(value->key_material != NULL)
        {
            kmip_free_key_material(ctx, format, &value->key_material);
            value->key_material = NULL;
        }
        
        if(value->attributes != NULL)
        {
            for(size_t i = 0; i < value->attribute_count; i++)
            {
                kmip_free_attribute(ctx, &value->attributes[i]);
            }
            ctx->free_func(ctx->state, value->attributes);
            
            value->attributes = NULL;
        }
        
        value->attribute_count = 0;
    }
    
    return;
}

void
kmip_free_application_specific_information(KMIP *ctx, ApplicationSpecificInformation *value)
{
    if(value != NULL)
    {
        if(value->application_namespace != NULL)
        {
            kmip_free_text_string(ctx, value->application_namespace);

            ctx->free_func(ctx->state, value->application_namespace);
            value->application_namespace = NULL;
        }

        if(value->application_data != NULL)
        {
            kmip_free_text_string(ctx, value->application_data);

            ctx->free_func(ctx->state, value->application_data);
            value->application_data = NULL;
        }
    }

    return;
}

void
kmip_free_cryptographic_parameters(KMIP *ctx, CryptographicParameters *value)
{
    if(value != NULL)
    {
        if(value->p_source != NULL)
        {
            kmip_free_byte_string(ctx, value->p_source);
            
            ctx->free_func(ctx->state, value->p_source);
            value->p_source = NULL;
        }
        
        kmip_init_cryptographic_parameters(value);
    }
    
    return;
}

void
kmip_free_encryption_key_information(KMIP *ctx, EncryptionKeyInformation *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->cryptographic_parameters != NULL)
        {
            kmip_free_cryptographic_parameters(ctx, value->cryptographic_parameters);
            
            ctx->free_func(ctx->state, value->cryptographic_parameters);
            value->cryptographic_parameters = NULL;
        }
    }
    
    return;
}

void
kmip_free_mac_signature_key_information(KMIP *ctx, MACSignatureKeyInformation *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->cryptographic_parameters != NULL)
        {
            kmip_free_cryptographic_parameters(ctx, value->cryptographic_parameters);
            
            ctx->free_func(ctx->state, value->cryptographic_parameters);
            value->cryptographic_parameters = NULL;
        }
    }
    
    return;
}

void
kmip_free_key_wrapping_data(KMIP *ctx, KeyWrappingData *value)
{
    if(value != NULL)
    {
        if(value->encryption_key_info != NULL)
        {
            kmip_free_encryption_key_information(ctx, value->encryption_key_info);
            
            ctx->free_func(ctx->state, value->encryption_key_info);
            value->encryption_key_info = NULL;
        }
        
        if(value->mac_signature_key_info != NULL)
        {
            kmip_free_mac_signature_key_information(ctx, value->mac_signature_key_info);
            
            ctx->free_func(ctx->state, value->mac_signature_key_info);
            value->mac_signature_key_info = NULL;
        }
        
        if(value->mac_signature != NULL)
        {
            kmip_free_byte_string(ctx, value->mac_signature);
            
            ctx->free_func(ctx->state, value->mac_signature);
            value->mac_signature = NULL;
        }
        
        if(value->iv_counter_nonce != NULL)
        {
            kmip_free_byte_string(ctx, value->iv_counter_nonce);
            
            ctx->free_func(ctx->state, value->iv_counter_nonce);
            value->iv_counter_nonce = NULL;
        }
        
        value->wrapping_method = 0;
        value->encoding_option = 0;
    }
    
    return;
}

void
kmip_free_key_block(KMIP *ctx, KeyBlock *value)
{
    if(value != NULL)
    {
        if(value->key_value != NULL)
        {
            if(value->key_value_type == KMIP_TYPE_BYTE_STRING)
            {
                kmip_free_byte_string(ctx, value->key_value);
                ctx->free_func(ctx->state, value->key_value);
            }
            else
            {
                kmip_free_key_value(ctx, value->key_format_type, value->key_value);
                ctx->free_func(ctx->state, value->key_value);
            }
            value->key_value = NULL;
        }
        
        if(value->key_wrapping_data != NULL)
        {
            kmip_free_key_wrapping_data(ctx, value->key_wrapping_data);
            ctx->free_func(ctx->state, value->key_wrapping_data);
            value->key_wrapping_data = NULL;
        }
        
        kmip_init_key_block(value);
    }
    
    return;
}

void
kmip_free_symmetric_key(KMIP *ctx, SymmetricKey *value)
{
    if(value != NULL)
    {
        if(value->key_block != NULL)
        {
            kmip_free_key_block(ctx, value->key_block);
            ctx->free_func(ctx->state, value->key_block);
            value->key_block = NULL;
        }
    }
    
    return;
}

void
kmip_free_public_key(KMIP *ctx, PublicKey *value)
{
    if(value != NULL)
    {
        if(value->key_block != NULL)
        {
            kmip_free_key_block(ctx, value->key_block);
            ctx->free_func(ctx->state, value->key_block);
            value->key_block = NULL;
        }
    }
    
    return;
}

void
kmip_free_private_key(KMIP *ctx, PrivateKey *value)
{
    if(value != NULL)
    {
        if(value->key_block != NULL)
        {
            kmip_free_key_block(ctx, value->key_block);
            ctx->free_func(ctx->state, value->key_block);
            value->key_block = NULL;
        }
    }
    
    return;
}

void
kmip_free_key_wrapping_specification(KMIP *ctx, KeyWrappingSpecification *value)
{
    if(value != NULL)
    {
        if(value->encryption_key_info != NULL)
        {
            kmip_free_encryption_key_information(ctx, value->encryption_key_info);
            ctx->free_func(ctx->state, value->encryption_key_info);
            value->encryption_key_info = NULL;
        }
        
        if(value->mac_signature_key_info != NULL)
        {
            kmip_free_mac_signature_key_information(ctx, value->mac_signature_key_info);
            ctx->free_func(ctx->state, value->mac_signature_key_info);
            value->mac_signature_key_info = NULL;
        }
        
        if(value->attribute_names != NULL)
        {
            for(size_t i = 0; i < value->attribute_name_count; i++)
            {
                kmip_free_text_string(ctx, &value->attribute_names[i]);
            }
            ctx->free_func(ctx->state, value->attribute_names);
            value->attribute_names = NULL;
        }
        value->attribute_name_count = 0;
        
        value->wrapping_method = 0;
        value->encoding_option = 0;
    }
    
    return;
}

void
kmip_free_register_request_payload(KMIP *ctx, RegisterRequestPayload *value)
{
    if(value != NULL)
    {
        if(value->template_attribute != NULL)
        {
            kmip_free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx->state, value->template_attribute);
            value->template_attribute = NULL;
        }

        if(value->attributes != NULL)
        {
            kmip_free_attributes(ctx, value->attributes);
            ctx->free_func(ctx->state, value->attributes);
            value->attributes = NULL;
        }

        if(value->protection_storage_masks != NULL)
        {
            kmip_free_protection_storage_masks(ctx, value->protection_storage_masks);
            ctx->free_func(ctx->state, value->protection_storage_masks);
            value->protection_storage_masks = NULL;
        }

        value->object_type = 0;
    }
    
    return;
}

void
kmip_free_create_request_payload(KMIP *ctx, CreateRequestPayload *value)
{
    if(value != NULL)
    {
        if(value->template_attribute != NULL)
        {
            kmip_free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx->state, value->template_attribute);
            value->template_attribute = NULL;
        }

        if(value->attributes != NULL)
        {
            kmip_free_attributes(ctx, value->attributes);
            ctx->free_func(ctx->state, value->attributes);
            value->attributes = NULL;
        }

        if(value->protection_storage_masks != NULL)
        {
            kmip_free_protection_storage_masks(ctx, value->protection_storage_masks);
            ctx->free_func(ctx->state, value->protection_storage_masks);
            value->protection_storage_masks = NULL;
        }
        
        value->object_type = 0;
    }
    
    return;
}

void
kmip_free_create_response_payload(KMIP *ctx, CreateResponsePayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->template_attribute != NULL)
        {
            kmip_free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx->state, value->template_attribute);
            value->template_attribute = NULL;
        }
        
        value->object_type = 0;
    }
    
    return;
}

void
kmip_free_register_response_payload(KMIP *ctx, RegisterResponsePayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->template_attribute != NULL)
        {
            kmip_free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx->state, value->template_attribute);
            value->template_attribute = NULL;
        }
    }
    
    return;
}

void
kmip_free_get_request_payload(KMIP *ctx, GetRequestPayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->key_wrapping_spec != NULL)
        {
            kmip_free_key_wrapping_specification(ctx, value->key_wrapping_spec);
            ctx->free_func(ctx->state, value->key_wrapping_spec);
            value->key_wrapping_spec = NULL;
        }
        
        value->key_format_type = 0;
        value->key_compression_type = 0;
        value->key_wrap_type = 0;
    }
    
    return;
}

void
kmip_free_get_attribute_request_payload(KMIP *ctx, GetAttributeRequestPayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        if(value->attribute_name != NULL)
        {
            kmip_free_text_string(ctx, value->attribute_name);
            ctx->free_func(ctx->state, value->attribute_name);
            value->attribute_name = NULL;
        }
        
    }
    
    return;
}

void
kmip_free_get_response_payload(KMIP *ctx, GetResponsePayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
        
        if(value->object != NULL)
        {
            switch(value->object_type)
            {
                case KMIP_OBJTYPE_SYMMETRIC_KEY:
                kmip_free_symmetric_key(ctx, (SymmetricKey *)value->object);
                break;
                
                case KMIP_OBJTYPE_PUBLIC_KEY:
                kmip_free_public_key(ctx, (PublicKey *)value->object);
                break;
                
                case KMIP_OBJTYPE_PRIVATE_KEY:
                kmip_free_private_key(ctx, (PrivateKey *)value->object);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know */
                /*      what the actual type, size, or value of         */
                /*      value->object is. We can still free it but we   */
                /*      cannot securely zero the memory. We also do not */
                /*      know how to free any possible substructures     */
                /*      pointed to within value->object.                */
                /*                                                      */
                /*      Avoid hitting this case at all costs.           */
                break;
            };
            
            ctx->free_func(ctx->state, value->object);
            value->object = NULL;
        }
        
        value->object_type = 0;
    }
    
    return;
}

void
kmip_free_get_attribute_response_payload(KMIP *ctx, GetAttributeResponsePayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }

        if(value->attribute != NULL)
        {
            kmip_free_attribute(ctx, value->attribute);
            ctx->free_func(ctx->state, value->attribute);
            value->attribute = NULL;
        }
        
    }
    
    return;
}
void
kmip_free_destroy_request_payload(KMIP *ctx, DestroyRequestPayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
    }
    
    return;
}

void
kmip_free_destroy_response_payload(KMIP *ctx, DestroyResponsePayload *value)
{
    if(value != NULL)
    {
        if(value->unique_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->unique_identifier);
            ctx->free_func(ctx->state, value->unique_identifier);
            value->unique_identifier = NULL;
        }
    }
    
    return;
}

void
kmip_free_request_batch_item(KMIP *ctx, RequestBatchItem *value)
{
    if(value != NULL)
    {
        if(value->unique_batch_item_id != NULL)
        {
            kmip_free_byte_string(ctx, value->unique_batch_item_id);
            ctx->free_func(ctx->state, value->unique_batch_item_id);
            value->unique_batch_item_id = NULL;
        }
        
        if(value->request_payload != NULL)
        {
            switch(value->operation)
            {
                case KMIP_OP_CREATE:
                kmip_free_create_request_payload(ctx, (CreateRequestPayload *)value->request_payload);
                break;

                case KMIP_OP_REGISTER:
                kmip_free_register_request_payload(ctx, (RegisterRequestPayload *)value->request_payload);
                break;
                
                case KMIP_OP_GET:
                kmip_free_get_request_payload(ctx, (GetRequestPayload *)value->request_payload);
                break;

                case KMIP_OP_GET_ATTRIBUTES:
                kmip_free_get_attribute_request_payload(ctx, (GetAttributeRequestPayload *)value->request_payload);
                break;
                
                case KMIP_OP_DESTROY:
                kmip_free_destroy_request_payload(ctx, (DestroyRequestPayload *)value->request_payload);
                break;
                
                case KMIP_OP_QUERY:
                kmip_free_query_request_payload(ctx, (QueryRequestPayload *)value->request_payload);
                break;

                case KMIP_OP_LOCATE:
                kmip_free_locate_request_payload(ctx, (LocateRequestPayload *)value->request_payload);
                break;

                default:
                /* NOTE (ph) Hitting this case means that we don't know    */
                /*      what the actual type, size, or value of            */
                /*      value->request_payload is. We can still free it    */
                /*      but we cannot securely zero the memory. We also    */
                /*      do not know how to free any possible substructures */
                /*      pointed to within value->request_payload.          */
                /*                                                         */
                /*      Avoid hitting this case at all costs.              */
                break;
            };
            
            ctx->free_func(ctx->state, value->request_payload);
            value->request_payload = NULL;
        }
        
        value->operation = 0;
        value->ephemeral = 0;
    }
    
    return;
}

void
kmip_free_response_batch_item(KMIP *ctx, ResponseBatchItem *value)
{
    if(value != NULL)
    {
        if(value->unique_batch_item_id != NULL)
        {
            kmip_free_byte_string(ctx, value->unique_batch_item_id);
            ctx->free_func(ctx->state, value->unique_batch_item_id);
            value->unique_batch_item_id = NULL;
        }
        
        if(value->result_message != NULL)
        {
            kmip_free_text_string(ctx, value->result_message);
            ctx->free_func(ctx->state, value->result_message);
            value->result_message = NULL;
        }
        
        if(value->asynchronous_correlation_value != NULL)
        {
            kmip_free_byte_string(ctx, value->asynchronous_correlation_value);
            ctx->free_func(ctx->state, value->asynchronous_correlation_value);
            value->asynchronous_correlation_value = NULL;
        }
        
        if(value->response_payload != NULL)
        {
            switch(value->operation)
            {
                case KMIP_OP_CREATE:
                kmip_free_create_response_payload(ctx, (CreateResponsePayload *)value->response_payload);
                break;

                case KMIP_OP_REGISTER:
                kmip_free_register_response_payload(ctx, (RegisterResponsePayload *)value->response_payload);
                break;
                
                case KMIP_OP_GET:
                kmip_free_get_response_payload(ctx, (GetResponsePayload *)value->response_payload);
                break;

                case KMIP_OP_GET_ATTRIBUTES:
                kmip_free_get_attribute_response_payload(ctx, (GetAttributeResponsePayload *)value->response_payload);
                break;
                
                case KMIP_OP_DESTROY:
                kmip_free_destroy_response_payload(ctx, (DestroyResponsePayload *)value->response_payload);
                break;
                
                case KMIP_OP_QUERY:
                kmip_free_query_response_payload(ctx, (QueryResponsePayload *)value->response_payload);
                break;

                case KMIP_OP_LOCATE:
                kmip_free_locate_response_payload(ctx, (LocateResponsePayload *)value->response_payload);
                break;

                default:
                /* NOTE (ph) Hitting this case means that we don't know    */
                /*      what the actual type, size, or value of            */
                /*      value->response_payload is. We can still free it   */
                /*      but we cannot securely zero the memory. We also    */
                /*      do not know how to free any possible substructures */
                /*      pointed to within value->response_payload.         */
                /*                                                         */
                /*      Avoid hitting this case at all costs.              */
                break;
            };
            
            ctx->free_func(ctx->state, value->response_payload);
            value->response_payload = NULL;
        }
        
        value->operation = 0;
        value->result_status = 0;
        value->result_reason = 0;
    }
    
    return;
}

void
kmip_free_nonce(KMIP *ctx, Nonce *value)
{
    if(value != NULL)
    {
        if(value->nonce_id != NULL)
        {
            kmip_free_byte_string(ctx, value->nonce_id);
            ctx->free_func(ctx->state, value->nonce_id);
            value->nonce_id = NULL;
        }
        
        if(value->nonce_value != NULL)
        {
            kmip_free_byte_string(ctx, value->nonce_value);
            ctx->free_func(ctx->state, value->nonce_value);
            value->nonce_value = NULL;
        }
    }
    
    return;
}

void
kmip_free_username_password_credential(KMIP *ctx, UsernamePasswordCredential *value)
{
    if(value != NULL)
    {
        if(value->username != NULL)
        {
            kmip_free_text_string(ctx, value->username);
            ctx->free_func(ctx->state, value->username);
            value->username = NULL;
        }
        
        if(value->password != NULL)
        {
            kmip_free_text_string(ctx, value->password);
            ctx->free_func(ctx->state, value->password);
            value->password = NULL;
        }
    }
    
    return;
}

void
kmip_free_device_credential(KMIP *ctx, DeviceCredential *value)
{
    if(value != NULL)
    {
        if(value->device_serial_number != NULL)
        {
            kmip_free_text_string(ctx, value->device_serial_number);
            ctx->free_func(ctx->state, value->device_serial_number);
            value->device_serial_number = NULL;
        }
        
        if(value->password != NULL)
        {
            kmip_free_text_string(ctx, value->password);
            ctx->free_func(ctx->state, value->password);
            value->password = NULL;
        }
        
        if(value->device_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->device_identifier);
            ctx->free_func(ctx->state, value->device_identifier);
            value->device_identifier = NULL;
        }
        
        if(value->network_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->network_identifier);
            ctx->free_func(ctx->state, value->network_identifier);
            value->network_identifier = NULL;
        }
        
        if(value->machine_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->machine_identifier);
            ctx->free_func(ctx->state, value->machine_identifier);
            value->machine_identifier = NULL;
        }
        
        if(value->media_identifier != NULL)
        {
            kmip_free_text_string(ctx, value->media_identifier);
            ctx->free_func(ctx->state, value->media_identifier);
            value->media_identifier = NULL;
        }
    }
    
    return;
}

void
kmip_free_attestation_credential(KMIP *ctx, AttestationCredential *value)
{
    if(value != NULL)
    {
        if(value->nonce != NULL)
        {
            kmip_free_nonce(ctx, value->nonce);
            ctx->free_func(ctx->state, value->nonce);
            value->nonce = NULL;
        }
        
        if(value->attestation_measurement != NULL)
        {
            kmip_free_byte_string(ctx, value->attestation_measurement);
            ctx->free_func(ctx->state, value->attestation_measurement);
            value->attestation_measurement = NULL;
        }
        
        if(value->attestation_assertion != NULL)
        {
            kmip_free_byte_string(ctx, value->attestation_assertion);
            ctx->free_func(ctx->state, value->attestation_assertion);
            value->attestation_assertion = NULL;
        }
        
        value->attestation_type = 0;
    }
    
    return;
}

void
kmip_free_credential_value(KMIP *ctx, enum credential_type type, void **value)
{
    if(value != NULL)
    {
        if(*value != NULL)
        {
            switch(type)
            {
                case KMIP_CRED_USERNAME_AND_PASSWORD:
                kmip_free_username_password_credential(ctx, (UsernamePasswordCredential *)*value);
                break;
                
                case KMIP_CRED_DEVICE:
                kmip_free_device_credential(ctx, (DeviceCredential *)*value);
                break;
                
                case KMIP_CRED_ATTESTATION:
                kmip_free_attestation_credential(ctx, (AttestationCredential *)*value);
                break;
                
                default:
                /* NOTE (ph) Hitting this case means that we don't know   */
                /*      what the actual type, size, or value of value is. */
                /*      We can still free it but we cannot securely zero  */
                /*      the memory. We also do not know how to free any   */
                /*      possible substructures pointed to within value.   */
                /*                                                        */
                /*      Avoid hitting this case at all costs.             */
                break;
            };
        
            ctx->free_func(ctx->state, *value);
            *value = NULL;
        }    
    }
    
    return;
}

void
kmip_free_credential(KMIP *ctx, Credential *value)
{
    if(value != NULL)
    {
        if(value->credential_value != NULL)
        {
            kmip_free_credential_value(ctx, value->credential_type, &value->credential_value);
            value->credential_value = NULL;
        }
        
        value->credential_type = 0;
    }
    
    return;
}

void
kmip_free_authentication(KMIP *ctx, Authentication *value)
{
    if(value != NULL)
    {
        if(value->credential != NULL)
        {
            kmip_free_credential(ctx, value->credential);
            ctx->free_func(ctx->state, value->credential);
            value->credential = NULL;
        }
    }
    
    return;
}

void
kmip_free_request_header(KMIP *ctx, RequestHeader *value)
{
    if(value != NULL)
    {
        if(value->protocol_version != NULL)
        {
            ctx->memset_func(
                value->protocol_version,
                0,
                sizeof(ProtocolVersion));
            ctx->free_func(ctx->state, value->protocol_version);
            value->protocol_version = NULL;
        }
        
        if(value->authentication != NULL)
        {
            kmip_free_authentication(ctx, value->authentication);
            ctx->free_func(ctx->state, value->authentication);
            value->authentication = NULL;
        }
        
        if(value->attestation_types != NULL)
        {
            ctx->memset_func(
                value->attestation_types,
                0,
                value->attestation_type_count * sizeof(enum attestation_type));
            ctx->free_func(ctx->state, value->attestation_types);
            value->attestation_types = NULL;
            value->attestation_type_count = 0;
        }
        
        if(value->client_correlation_value != NULL)
        {
            kmip_free_text_string(ctx, value->client_correlation_value);
            ctx->free_func(ctx->state, value->client_correlation_value);
            value->client_correlation_value = NULL;
        }
        
        if(value->server_correlation_value != NULL)
        {
            kmip_free_text_string(ctx, value->server_correlation_value);
            ctx->free_func(ctx->state, value->server_correlation_value);
            value->server_correlation_value = NULL;
        }
        
        kmip_init_request_header(value);
    }
    
    return;
}

void
kmip_free_response_header(KMIP *ctx, ResponseHeader *value)
{
    if(value != NULL)
    {
        if(value->protocol_version != NULL)
        {
            ctx->memset_func(
                value->protocol_version,
                0,
                sizeof(ProtocolVersion));
            ctx->free_func(ctx->state, value->protocol_version);
            value->protocol_version = NULL;
        }
        
        if(value->nonce != NULL)
        {
            kmip_free_nonce(ctx, value->nonce);
            ctx->free_func(ctx->state, value->nonce);
            value->nonce = NULL;
        }

        if(value->server_hashed_password != NULL)
        {
            kmip_free_byte_string(ctx, value->server_hashed_password);
            ctx->free_func(ctx->state, value->server_hashed_password);
            value->server_hashed_password = NULL;
        }

        if(value->attestation_types != NULL)
        {
            ctx->memset_func(
                value->attestation_types,
                0,
                value->attestation_type_count * sizeof(enum attestation_type));
            ctx->free_func(ctx->state, value->attestation_types);
            value->attestation_types = NULL;
        }
        
        value->attestation_type_count = 0;
        
        if(value->client_correlation_value != NULL)
        {
            kmip_free_text_string(ctx, value->client_correlation_value);
            ctx->free_func(ctx->state, value->client_correlation_value);
            value->client_correlation_value = NULL;
        }
        
        if(value->server_correlation_value != NULL)
        {
            kmip_free_text_string(ctx, value->server_correlation_value);
            ctx->free_func(ctx->state, value->server_correlation_value);
            value->server_correlation_value = NULL;
        }
        
        kmip_init_response_header(value);
    }
    
    return;
}

void
kmip_free_request_message(KMIP *ctx, RequestMessage *value)
{
    if(value != NULL)
    {
        if(value->request_header != NULL)
        {
            kmip_free_request_header(ctx, value->request_header);
            ctx->free_func(ctx->state, value->request_header);
            value->request_header = NULL;
        }
        
        if(value->batch_items != NULL)
        {
            for(size_t i = 0; i < value->batch_count; i++)
            {
                kmip_free_request_batch_item(ctx, &value->batch_items[i]);
            }
            ctx->free_func(ctx, value->batch_items);
            value->batch_items = NULL;
        }
        
        value->batch_count = 0;
    }
    
    return;
}

void
kmip_free_response_message(KMIP *ctx, ResponseMessage *value)
{
    if(value != NULL)
    {
        if(value->response_header != NULL)
        {
            kmip_free_response_header(ctx, value->response_header);
            ctx->free_func(ctx->state, value->response_header);
            value->response_header = NULL;
        }
        
        if(value->batch_items != NULL)
        {
            for(size_t i = 0; i < value->batch_count; i++)
            {
                kmip_free_response_batch_item(ctx, &value->batch_items[i]);
            }
            ctx->free_func(ctx, value->batch_items);
            value->batch_items = NULL;
        }
        
        value->batch_count = 0;
    }
    
    return;
}

void
kmip_free_query_functions(KMIP *ctx, Functions* value)
{
    if (value != NULL)
    {
        if (value->function_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->function_list);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->function_list);
            }
            ctx->free_func(ctx->state, value->function_list);
            value->function_list = NULL;
        }
    }

    return;
}

void
kmip_free_query_response_payload(KMIP *ctx, QueryResponsePayload *value)
{
    if (value->operations)
    {
        kmip_free_operations(ctx, value->operations);
        ctx->free_func(ctx->state, value->operations);
        value->operations = NULL;
    }
    if (value->objects)
    {
        kmip_free_objects(ctx, value->objects);
        ctx->free_func(ctx->state, value->objects);
        value->objects = NULL;
    }

    if (value->vendor_identification)
    {
        kmip_free_text_string(ctx, value->vendor_identification);
        ctx->free_func(ctx->state, value->vendor_identification);
        value->vendor_identification = NULL;
    }

    if (value->server_information)
    {
        kmip_free_server_information(ctx, value->server_information);
        ctx->free_func(ctx->state, value->server_information);
        value->server_information = NULL;
    }
}


void
kmip_free_query_request_payload(KMIP *ctx, QueryRequestPayload *value)
{
    if(ctx == NULL || value == NULL)
    {
        return;
    }

    if (value->functions != NULL)
    {
        kmip_free_query_functions(ctx, value->functions);
        ctx->free_func(ctx->state, value->functions);
        value->functions = NULL;
    }
}

void
kmip_free_operations(KMIP *ctx, Operations *value)
{

    if(value != NULL)
    {
        if(value->operation_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->operation_list);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->operation_list);
            }
            ctx->free_func(ctx->state, value->operation_list);
            value->operation_list = NULL;
        }
    }

    return;
}
void
kmip_free_objects(KMIP *ctx, ObjectTypes* value)
{
    if(value != NULL)
    {
        if(value->object_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->object_list);
            while(curr != NULL)
            {
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->object_list);
            }
            ctx->free_func(ctx->state, value->object_list);
            value->object_list = NULL;
        }
    }

    return;
}


void
kmip_free_server_information(KMIP* ctx, ServerInformation* value)
{
    kmip_free_text_string(ctx, value->server_name);
    kmip_free_text_string(ctx, value->server_serial_number);
    kmip_free_text_string(ctx, value->server_version);
    kmip_free_text_string(ctx, value->server_load);
    kmip_free_text_string(ctx, value->product_name);
    kmip_free_text_string(ctx, value->build_level);
    kmip_free_text_string(ctx, value->build_date);
    kmip_free_text_string(ctx, value->cluster_info);
}

/*
Copying Functions
*/

int32 *
kmip_deep_copy_int32(KMIP *ctx, const int32 *value)
{
    if(ctx == NULL || value == NULL)
        return(NULL);

    int32 *copy = ctx->calloc_func(ctx, 1, sizeof(int32));
    if(copy == NULL)
        return(NULL);

    copy = ctx->memcpy_func(ctx->state, copy, value, sizeof(int32));
    return(copy);
}

int64 *
kmip_deep_copy_int64(KMIP *ctx, const int64 *value)
{
    if(ctx == NULL || value == NULL)
    {
        return(NULL);
    }

    int64 *copy = ctx->calloc_func(ctx->state, 1, sizeof(int64));
    if(copy == NULL)
    {
        return(NULL);
    }

    copy = ctx->memcpy_func(ctx->state, copy, value, sizeof(int64));
    return(copy);
}

TextString *
kmip_deep_copy_text_string(KMIP *ctx, const TextString *value)
{
    if(ctx == NULL || value == NULL)
        return(NULL);

    TextString *copy = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    if(copy == NULL)
        return(NULL);

    copy->size = value->size;
    if(value->value != NULL)
    {
        copy->value = ctx->calloc_func(ctx->state, 1, value->size);
        if(copy->value == NULL && value->value != NULL)
        {
            ctx->free_func(ctx->state, copy);
            return(NULL);
        }
        copy->value = ctx->memcpy_func(ctx->state, copy->value, value->value, value->size);
    }
    else
        copy->value = NULL;

    return(copy);
}

ByteString *
kmip_deep_copy_byte_string(KMIP *ctx, const ByteString *value)
{
    if(NULL == ctx || NULL == value)
    {
        return(NULL);
    }

    ByteString *copy = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
    if(NULL == copy)
    {
        return(NULL);
    }

    copy->size = value->size;
    if(NULL != value->value)
    {
        copy->value = ctx->calloc_func(ctx->state, 1, value->size);
        if(NULL == copy->value)
        {
            ctx->free_func(ctx->state, copy);
            return(NULL);
        }
        copy->value = ctx->memcpy_func(ctx->state, copy->value, value->value, value->size);
    }
    else
    {
        copy->value = NULL;
    }

    return(copy);
}

Name *
kmip_deep_copy_name(KMIP *ctx, const Name *value)
{
    if(ctx == NULL || value == NULL)
        return(NULL);

    Name *copy = ctx->calloc_func(ctx->state, 1, sizeof(Name));
    if(copy == NULL)
        return(NULL);

    copy->type = value->type;
    if(value->value != NULL)
    {
        copy->value = kmip_deep_copy_text_string(ctx, value->value);
        if(copy->value == NULL)
        {
            ctx->free_func(ctx->state, copy);
            return(NULL);
        }
    }
    else
        copy->value = NULL;

    return(copy);
}

CryptographicParameters *
kmip_deep_copy_cryptographic_parameters(KMIP *ctx, const CryptographicParameters *value)
{
    if(NULL == ctx || NULL == value)
    {
        return(NULL);
    }

    CryptographicParameters *copy = ctx->calloc_func(ctx->state, 1, sizeof(CryptographicParameters));
    if(NULL == copy)
    {
        return(NULL);
    }

    if(NULL != value->p_source)
    {
        copy->p_source = kmip_deep_copy_byte_string(ctx, value->p_source);
        if(NULL == copy->p_source)
        {
            kmip_free_cryptographic_parameters(ctx, copy);
            ctx->free_func(ctx->state, copy);
            return(NULL);
        }
    }
    else
    {
        copy->p_source = NULL;
    }

    copy->block_cipher_mode = value->block_cipher_mode;
    copy->padding_method = value->padding_method;
    copy->hashing_algorithm = value->hashing_algorithm;
    copy->key_role_type = value->key_role_type;

    copy->digital_signature_algorithm = value->digital_signature_algorithm;
    copy->cryptographic_algorithm = value->cryptographic_algorithm;
    copy->random_iv = value->random_iv;
    copy->iv_length = value->iv_length;
    copy->tag_length = value->tag_length;
    copy->fixed_field_length = value->fixed_field_length;
    copy->invocation_field_length = value->invocation_field_length;
    copy->counter_length = value->counter_length;
    copy->initial_counter_value = value->initial_counter_value;

    copy->salt_length = value->salt_length;
    copy->mask_generator = value->mask_generator;
    copy->mask_generator_hashing_algorithm = value->mask_generator_hashing_algorithm;
    copy->trailer_field = value->trailer_field;

    return(copy);
}

ApplicationSpecificInformation *
kmip_deep_copy_application_specific_information(KMIP *ctx, const ApplicationSpecificInformation *value)
{
    if(ctx == NULL || value == NULL)
    {
        return(NULL);
    }

    ApplicationSpecificInformation *copy = ctx->calloc_func(ctx->state, 1, sizeof(ApplicationSpecificInformation));
    if(copy == NULL)
    {
        return(NULL);
    }

    if(value->application_namespace != NULL)
    {
        copy->application_namespace = kmip_deep_copy_text_string(ctx, value->application_namespace);
        if(copy->application_namespace == NULL)
        {
            ctx->free_func(ctx->state, copy);
            return(NULL);
        }
    }
    else
    {
        copy->application_namespace = NULL;
    }

    if(value->application_data != NULL)
    {
        copy->application_data = kmip_deep_copy_text_string(ctx, value->application_data);
        if(copy->application_data == NULL)
        {
            kmip_free_application_specific_information(ctx, copy);
            ctx->free_func(ctx->state, copy);
            return(NULL);
        }
    }
    else
    {
        copy->application_data = NULL;
    }

    return(copy);
}

Attribute *
kmip_deep_copy_attribute(KMIP *ctx, const Attribute *value)
{
    if(ctx == NULL || value == NULL)
        return(NULL);

    Attribute *copy = ctx->calloc_func(ctx->state, 1, sizeof(Attribute));
    if(copy == NULL)
        return(NULL);

    copy->type = value->type;
    copy->index = value->index;

    if(value->value == NULL)
    {
        copy->value = NULL;
        return(copy);
    }

    switch(value->type)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        case KMIP_ATTR_OBJECT_GROUP:
        {
            copy->value = kmip_deep_copy_text_string(ctx, (TextString *)value->value);
            if(copy->value == NULL)
            {
                ctx->free_func(ctx->state, copy);
                return(NULL);
            }
        } break;

        case KMIP_ATTR_NAME:
        {
            copy->value = kmip_deep_copy_name(ctx, (Name *)value->value);
            if(copy->value == NULL)
            {
                ctx->free_func(ctx->state, copy);
                return(NULL);
            }
        } break;

        case KMIP_ATTR_OBJECT_TYPE:
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        case KMIP_ATTR_STATE:
        {
            copy->value = kmip_deep_copy_int32(ctx, (int32 *)value->value);
            if(copy->value == NULL)
            {
                ctx->free_func(ctx->state, copy);
                return(NULL);
            }
        } break;

        case KMIP_ATTR_ACTIVATION_DATE:
        case KMIP_ATTR_DEACTIVATION_DATE:
        case KMIP_ATTR_PROCESS_START_DATE:
        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            copy->value = kmip_deep_copy_int64(ctx, (int64 *)value->value);
            if(copy->value == NULL)
            {
                ctx->free_func(ctx->state, copy);
                return(NULL);
            }
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            copy->value = kmip_deep_copy_cryptographic_parameters(ctx, (CryptographicParameters*)value->value);
            if(NULL == copy->value)
            {
                ctx->free_func(ctx->state, copy);
                return(NULL);
            }
        } break;

        default:
        {
            ctx->free_func(ctx->state, copy);
            return(NULL);
        } break;
    };

    return(copy);
}

char*
kmip_copy_textstring(char* dest, TextString* src, size_t size)
{
    if(src && src->value != NULL)
    {
        size_t len = KMIP_MIN(size, src->size);
        memcpy(dest, src->value, len);
        dest[len] = 0;
    }
    else
        *dest = 0;

    return dest;
}

void
kmip_copy_operations(int ops[], size_t* ops_size, Operations *value, unsigned max_ops)
{
    if(value != NULL &&
       value->operation_list != NULL)
    {
        *ops_size = value->operation_list->size;

        LinkedListItem *curr = value->operation_list->head;
        size_t idx = 0;
        while(curr != NULL && idx < max_ops )
        {
            ops[idx] = *(int32 *)curr->data;
            curr = curr->next;
            idx++;
        }
    }
}

void
kmip_copy_objects(int objs[], size_t* objs_size, ObjectTypes *value, unsigned max_objs)
{
    if(value != NULL &&
       value->object_list != NULL)
    {
        *objs_size = value->object_list->size;

        LinkedListItem *curr = value->object_list->head;
        size_t idx = 0;
        while(curr != NULL && idx < max_objs )
        {
            objs[idx] = *(int32 *)curr->data;
            curr = curr->next;
            idx++;
        }
    }
}

void
kmip_copy_query_result(QueryResponse* query_result, QueryResponsePayload *pld)
{
    if(pld != NULL)
    {
        kmip_copy_operations(query_result->operations, &query_result->operations_size, pld->operations, MAX_QUERY_OPS);
        kmip_copy_objects(query_result->objects, &query_result->objects_size, pld->objects, MAX_QUERY_OBJS);

        if(pld->vendor_identification)
        {
            kmip_copy_textstring(query_result->vendor_identification, pld->vendor_identification, sizeof(query_result->vendor_identification)-1);
        }

        if(pld->server_information)
        {
            ServerInformation* srv = pld->server_information;
            query_result->server_information_valid = 1;
            kmip_copy_textstring(query_result->server_name, srv->server_name, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->server_serial_number, srv->server_serial_number, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->server_version, srv->server_version, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->server_load, srv->server_load, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->product_name, srv->product_name, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->build_level, srv->build_level, MAX_QUERY_LEN-1);
            kmip_copy_textstring(query_result->build_date, srv->build_date, MAX_QUERY_LEN-1);
        }
    }
}


/*
Comparison Functions
*/

int
kmip_compare_text_string(const TextString *a, const TextString *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->size != b->size)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->size; i++)
            {
                if(a->value[i] != b->value[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_byte_string(const ByteString *a, const ByteString *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->size != b->size)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->size; i++)
            {
                if(a->value[i] != b->value[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_name(const Name *a, const Name *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->type != b->type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->value, b->value) != KMIP_TRUE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_protection_storage_masks(const ProtectionStorageMasks *a, const ProtectionStorageMasks *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->masks != b->masks))
        {
            if((a->masks == NULL) || (b->masks == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->masks->size != b->masks->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->masks->head;
            LinkedListItem *b_item = b->masks->head;
            while((a_item != NULL) && (b_item != NULL))
            {
                if(a_item != b_item)
                {
                    int32 *a_data = (int32 *)a_item->data;
                    int32 *b_data = (int32 *)b_item->data;
                    if(a_data != b_data)
                    {
                        if((a_data == NULL) || (b_data == NULL))
                        {
                            return(KMIP_FALSE);
                        }
                        if(*a_data != *b_data)
                        {
                            return(KMIP_FALSE);
                        }
                    }
                }

                a_item = a_item->next;
                b_item = b_item->next;
            }

            if(a_item != b_item)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_attribute(const Attribute *a, const Attribute *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->type != b->type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->index != b->index)
        {
            return(KMIP_FALSE);
        }
        
        if(a->value != b->value)
        {
            if((a->value == NULL) || (b->value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(a->type)
            {
                case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
                {
                    return(
                        kmip_compare_application_specific_information(
                            (ApplicationSpecificInformation*)a->value,
                            (ApplicationSpecificInformation*)b->value
                        )
                    );
                }
                break;

                case KMIP_ATTR_UNIQUE_IDENTIFIER:
                return(kmip_compare_text_string((TextString *)a->value, (TextString *)b->value));
                break;
                
                case KMIP_ATTR_NAME:
                return(kmip_compare_name((Name *)a->value, (Name *)b->value));
                break;
                
                case KMIP_ATTR_OBJECT_TYPE:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_OPERATION_POLICY_NAME:
                return(kmip_compare_text_string((TextString *)a->value, (TextString *)b->value));
                break;
                
                case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_ATTR_STATE:
                if(*(int32*)a->value != *(int32*)b->value)
                {
                    return(KMIP_FALSE);
                }
                break;

                case KMIP_ATTR_OBJECT_GROUP:
                {
                    return(kmip_compare_text_string((TextString *)a->value, (TextString *)b->value));
                }
                break;

                case KMIP_ATTR_ACTIVATION_DATE:
                case KMIP_ATTR_DEACTIVATION_DATE:
                case KMIP_ATTR_PROCESS_START_DATE:
                case KMIP_ATTR_PROTECT_STOP_DATE:
                {
                    if(*(int64*)a->value != *(int64*)b->value)
                    {
                        return(KMIP_FALSE);
                    }
                } break;

                case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
                {
                    return(kmip_compare_cryptographic_parameters(
                        (CryptographicParameters*)a->value,
                        (CryptographicParameters*)b->value
                    ));
                } break;
                
                default:
                /* NOTE (ph) Unsupported types can't be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_attributes(const Attributes *a, const Attributes *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->attribute_list != b->attribute_list))
        {
            if((a->attribute_list == NULL) || (b->attribute_list == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->attribute_list->size != b->attribute_list->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->attribute_list->head;
            LinkedListItem *b_item = b->attribute_list->head;
            while((a_item != NULL) && (b_item != NULL))
            {
                if(a_item != b_item)
                {
                    Attribute *a_data = (Attribute *)a_item->data;
                    Attribute *b_data = (Attribute *)b_item->data;
                    if(kmip_compare_attribute(a_data, b_data) == KMIP_FALSE)
                    {
                        return(KMIP_FALSE);
                    }
                }

                a_item = a_item->next;
                b_item = b_item->next;
            }

            if(a_item != b_item)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_template_attribute(const TemplateAttribute *a, const TemplateAttribute *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->name_count != b->name_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attribute_count != b->attribute_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->names != b->names)
        {
            if((a->names == NULL) || (b->names == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->name_count; i++)
            {
                if(kmip_compare_name(&a->names[i], &b->names[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->attributes != b->attributes)
        {
            if((a->attributes == NULL) || (b->attributes == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attribute_count; i++)
            {
                if(kmip_compare_attribute(&a->attributes[i], &b->attributes[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_protocol_version(const ProtocolVersion *a, const ProtocolVersion *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->major != b->major)
        {
            return(KMIP_FALSE);
        }
        
        if(a->minor != b->minor)
        {
            return(KMIP_FALSE);
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_transparent_symmetric_key(const TransparentSymmetricKey *a, const TransparentSymmetricKey *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key != b->key)
        {
            if((a->key == NULL) || (b->key == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->key, b->key) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_key_material(enum key_format_type format, void **a, void **b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(*a != *b)
        {
            if((*a == NULL) || (*b == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(format)
            {
                case KMIP_KEYFORMAT_RAW:
                case KMIP_KEYFORMAT_OPAQUE:
                case KMIP_KEYFORMAT_PKCS1:
                case KMIP_KEYFORMAT_PKCS8:
                case KMIP_KEYFORMAT_X509:
                case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
                if(kmip_compare_byte_string(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
                if(kmip_compare_transparent_symmetric_key(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_key_value(enum key_format_type format, const KeyValue *a, const KeyValue *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_material != b->key_material)
        {
            if((a->key_material == NULL) || (b->key_material == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_key_material(format, (void**)&a->key_material, (void**)&b->key_material) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attributes != b->attributes)
        {
            if((a->attributes == NULL) || (b->attributes == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attribute_count; i++)
            {
                if(kmip_compare_attribute(&a->attributes[i], &b->attributes[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_application_specific_information(const ApplicationSpecificInformation *a, const ApplicationSpecificInformation *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if(a->application_namespace != b->application_namespace)
        {
            if((a->application_namespace == NULL) || (b->application_namespace == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_text_string(a->application_namespace, b->application_namespace) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->application_data != b->application_data)
        {
            if((a->application_data == NULL) || (b->application_data == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_text_string(a->application_data, b->application_data) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_cryptographic_parameters(const CryptographicParameters *a, const CryptographicParameters *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->block_cipher_mode != b->block_cipher_mode)
        {
            return(KMIP_FALSE);
        }
        
        if(a->padding_method != b->padding_method)
        {
            return(KMIP_FALSE);
        }
        
        if(a->hashing_algorithm != b->hashing_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_role_type != b->key_role_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->digital_signature_algorithm != b->digital_signature_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->cryptographic_algorithm != b->cryptographic_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->random_iv != b->random_iv)
        {
            return(KMIP_FALSE);
        }
        
        if(a->iv_length != b->iv_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->tag_length != b->tag_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->fixed_field_length != b->fixed_field_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->invocation_field_length != b->invocation_field_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->counter_length != b->counter_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->initial_counter_value != b->initial_counter_value)
        {
            return(KMIP_FALSE);
        }
        
        if(a->salt_length != b->salt_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->mask_generator != b->mask_generator)
        {
            return(KMIP_FALSE);
        }
        
        if(a->mask_generator_hashing_algorithm != 
           b->mask_generator_hashing_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->trailer_field != b->trailer_field)
        {
            return(KMIP_FALSE);
        }
        
        if(a->p_source != b->p_source)
        {
            if((a->p_source == NULL) || (b->p_source == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->p_source, b->p_source) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_encryption_key_information(const EncryptionKeyInformation *a, const EncryptionKeyInformation *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->cryptographic_parameters != b->cryptographic_parameters)
        {
            if((a->cryptographic_parameters == NULL) ||
               (b->cryptographic_parameters == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_cryptographic_parameters(a->cryptographic_parameters, b->cryptographic_parameters) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_mac_signature_key_information(const MACSignatureKeyInformation *a, const MACSignatureKeyInformation *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->cryptographic_parameters != b->cryptographic_parameters)
        {
            if((a->cryptographic_parameters == NULL) || (b->cryptographic_parameters == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_cryptographic_parameters(a->cryptographic_parameters, b->cryptographic_parameters) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_key_wrapping_data(const KeyWrappingData *a, const KeyWrappingData *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->wrapping_method != b->wrapping_method)
        {
            return(KMIP_FALSE);
        }
        
        if(a->encoding_option != b->encoding_option)
        {
            return(KMIP_FALSE);
        }
        
        if(a->mac_signature != b->mac_signature)
        {
            if((a->mac_signature == NULL) || (b->mac_signature == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->mac_signature, b->mac_signature) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->iv_counter_nonce != b->iv_counter_nonce)
        {
            if((a->iv_counter_nonce == NULL) || (b->iv_counter_nonce == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->iv_counter_nonce, b->iv_counter_nonce) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->encryption_key_info != b->encryption_key_info)
        {
            if((a->encryption_key_info == NULL) || (b->encryption_key_info == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_encryption_key_information(a->encryption_key_info, b->encryption_key_info) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->mac_signature_key_info != b->mac_signature_key_info)
        {
            if((a->mac_signature_key_info == NULL) || (b->mac_signature_key_info == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_mac_signature_key_information(a->mac_signature_key_info, b->mac_signature_key_info) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_key_block(const KeyBlock *a, const KeyBlock *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_format_type != b->key_format_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_compression_type != b->key_compression_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->cryptographic_algorithm != b->cryptographic_algorithm)
        {
            return(KMIP_FALSE);
        }
        
        if(a->cryptographic_length != b->cryptographic_length)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_value_type != b->key_value_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_value != b->key_value)
        {
            if((a->key_value == NULL) || (b->key_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(a->key_value_type == KMIP_TYPE_BYTE_STRING)
            {
                if(kmip_compare_byte_string((ByteString *)a->key_value, (ByteString *)b->key_value) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
            else
            {
                if(kmip_compare_key_value(a->key_format_type, (KeyValue *)a->key_value, (KeyValue *)b->key_value) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->key_wrapping_data != b->key_wrapping_data)
        {
            if((a->key_wrapping_data == NULL) || (b->key_wrapping_data == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_key_wrapping_data(a->key_wrapping_data, b->key_wrapping_data) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_symmetric_key(const SymmetricKey *a, const SymmetricKey *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_block != b->key_block)
        {
            if((a->key_block == NULL) || (b->key_block == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_key_block(a->key_block, b->key_block) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_public_key(const PublicKey *a, const PublicKey *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_block != b->key_block)
        {
            if((a->key_block == NULL) || (b->key_block == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_key_block(a->key_block, b->key_block) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_private_key(const PrivateKey *a, const PrivateKey *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_block != b->key_block)
        {
            if((a->key_block == NULL) || (b->key_block == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_key_block(a->key_block, b->key_block) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_key_wrapping_specification(const KeyWrappingSpecification *a, const KeyWrappingSpecification *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->wrapping_method != b->wrapping_method)
        {
            return(KMIP_FALSE);
        }
        
        if(a->encoding_option != b->encoding_option)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attribute_name_count != b->attribute_name_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->encryption_key_info != b->encryption_key_info)
        {
            if((a->encryption_key_info == NULL) || (b->encryption_key_info == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_encryption_key_information(a->encryption_key_info, b->encryption_key_info) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->mac_signature_key_info != b->mac_signature_key_info)
        {
            if((a->mac_signature_key_info == NULL) || (b->mac_signature_key_info == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_mac_signature_key_information(a->mac_signature_key_info, b->mac_signature_key_info) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attribute_names != b->attribute_names)
        {
            if((a->attribute_names == NULL) || (b->attribute_names == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attribute_name_count; i++)
            {
                if(kmip_compare_text_string(&a->attribute_names[i], &b->attribute_names[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_create_request_payload(const CreateRequestPayload *a, const CreateRequestPayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->object_type != b->object_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->template_attribute != b->template_attribute)
        {
            if((a->template_attribute == NULL) || (b->template_attribute == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_template_attribute(a->template_attribute, b->template_attribute) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->attributes != b->attributes)
        {
            if((a->attributes == NULL) || (b->attributes == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_attributes(a->attributes, b->attributes) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->protection_storage_masks != b->protection_storage_masks)
        {
            if((a->protection_storage_masks == NULL) || (b->protection_storage_masks == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_protection_storage_masks(a->protection_storage_masks, b->protection_storage_masks) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_create_response_payload(const CreateResponsePayload *a, const CreateResponsePayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->object_type != b->object_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->template_attribute != b->template_attribute)
        {
            if((a->template_attribute == NULL) || (b->template_attribute == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_template_attribute(a->template_attribute, b->template_attribute) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_register_request_payload(const RegisterRequestPayload *a, const RegisterRequestPayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->object_type != b->object_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->template_attribute != b->template_attribute)
        {
            if((a->template_attribute == NULL) || (b->template_attribute == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_template_attribute(a->template_attribute, b->template_attribute) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->attributes != b->attributes)
        {
            if((a->attributes == NULL) || (b->attributes == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_attributes(a->attributes, b->attributes) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->protection_storage_masks != b->protection_storage_masks)
        {
            if((a->protection_storage_masks == NULL) || (b->protection_storage_masks == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_protection_storage_masks(a->protection_storage_masks, b->protection_storage_masks) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        return kmip_compare_symmetric_key(&a->object, &b->object);
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_register_response_payload(const RegisterResponsePayload *a, const RegisterResponsePayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->template_attribute != b->template_attribute)
        {
            if((a->template_attribute == NULL) || (b->template_attribute == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_template_attribute(a->template_attribute, b->template_attribute) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_get_request_payload(const GetRequestPayload *a, const GetRequestPayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_format_type != b->key_format_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_compression_type != b->key_compression_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->key_wrap_type != b->key_wrap_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->key_wrapping_spec != b->key_wrapping_spec)
        {
            if((a->key_wrapping_spec == NULL) || (b->key_wrapping_spec == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_key_wrapping_specification(a->key_wrapping_spec, b->key_wrapping_spec) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_get_response_payload(const GetResponsePayload *a, const GetResponsePayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->object_type != b->object_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->object != b->object)
        {
            switch(a->object_type)
            {
                case KMIP_OBJTYPE_SYMMETRIC_KEY:
                if(kmip_compare_symmetric_key((SymmetricKey *)a->object, (SymmetricKey *)b->object) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OBJTYPE_PUBLIC_KEY:
                if(kmip_compare_public_key((PublicKey *)a->object, (PublicKey *)b->object) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OBJTYPE_PRIVATE_KEY:
                if(kmip_compare_private_key((PrivateKey *)a->object, (PrivateKey *)b->object) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_get_attribute_request_payload(const GetAttributeRequestPayload *a, const GetAttributeRequestPayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->attribute_name != b->attribute_name)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_get_attribute_response_payload(const GetAttributeResponsePayload *a, const GetAttributeResponsePayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        // TODO: attribute
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_destroy_request_payload(const DestroyRequestPayload *a, const DestroyRequestPayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_destroy_response_payload(const DestroyResponsePayload *a, const DestroyResponsePayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_identifier != b->unique_identifier)
        {
            if((a->unique_identifier == NULL) || (b->unique_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->unique_identifier, b->unique_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_request_batch_item(const RequestBatchItem *a, const RequestBatchItem *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->operation != b->operation)
        {
            return(KMIP_FALSE);
        }

        if(a->ephemeral != b->ephemeral)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_batch_item_id != b->unique_batch_item_id)
        {
            if((a->unique_batch_item_id == NULL) || (b->unique_batch_item_id == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->unique_batch_item_id, b->unique_batch_item_id) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->request_payload != b->request_payload)
        {
            if((a->request_payload == NULL) || (b->request_payload == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(a->operation)
            {
                case KMIP_OP_CREATE:
                if(kmip_compare_create_request_payload((CreateRequestPayload *)a->request_payload, (CreateRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;

                case KMIP_OP_REGISTER:
                if(kmip_compare_register_request_payload((RegisterRequestPayload *)a->request_payload, (RegisterRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_GET:
                if(kmip_compare_get_request_payload((GetRequestPayload *)a->request_payload, (GetRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;

                case KMIP_OP_GET_ATTRIBUTES:
                if(kmip_compare_get_attribute_request_payload((GetAttributeRequestPayload *)a->request_payload, (GetAttributeRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_DESTROY:
                if(kmip_compare_destroy_request_payload((DestroyRequestPayload *)a->request_payload, (DestroyRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_QUERY:
                if(kmip_compare_query_request_payload((QueryRequestPayload *)a->request_payload, (QueryRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;

                case KMIP_OP_LOCATE:
                if(kmip_compare_locate_request_payload((LocateRequestPayload *)a->request_payload, (LocateRequestPayload *)b->request_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported payloads cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_response_batch_item(const ResponseBatchItem *a, const ResponseBatchItem *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->operation != b->operation)
        {
            return(KMIP_FALSE);
        }
        
        if(a->result_status != b->result_status)
        {
            return(KMIP_FALSE);
        }
        
        if(a->result_reason != b->result_reason)
        {
            return(KMIP_FALSE);
        }
        
        if(a->unique_batch_item_id != b->unique_batch_item_id)
        {
            if((a->unique_batch_item_id == NULL) || (b->unique_batch_item_id == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->unique_batch_item_id, b->unique_batch_item_id) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->result_message != b->result_message)
        {
            if((a->result_message == NULL) || (b->result_message == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->result_message, b->result_message) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->asynchronous_correlation_value != b->asynchronous_correlation_value)
        {
            if((a->asynchronous_correlation_value == NULL) || (b->asynchronous_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->asynchronous_correlation_value, b->asynchronous_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->response_payload != b->response_payload)
        {
            if((a->response_payload == NULL) || (b->response_payload == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(a->operation)
            {
                case KMIP_OP_CREATE:
                if(kmip_compare_create_response_payload((CreateResponsePayload *)a->response_payload, (CreateResponsePayload *)b->response_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_GET:
                if(kmip_compare_get_response_payload((GetResponsePayload *)a->response_payload, (GetResponsePayload *)b->response_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;

                case KMIP_OP_GET_ATTRIBUTES:
                if(kmip_compare_get_attribute_response_payload((GetAttributeResponsePayload *)a->response_payload, (GetAttributeResponsePayload *)b->response_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_DESTROY:
                if(kmip_compare_destroy_response_payload((DestroyResponsePayload *)a->response_payload, (DestroyResponsePayload *)b->response_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_OP_QUERY:
                if(kmip_compare_query_response_payload((QueryResponsePayload *)a->response_payload, (QueryResponsePayload *)b->response_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;

                case KMIP_OP_LOCATE:
                if(kmip_compare_locate_response_payload((LocateResponsePayload *)a->response_payload, (LocateResponsePayload *)b->response_payload) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;

                default:
                /* NOTE (ph) Unsupported payloads cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_nonce(const Nonce *a, const Nonce *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->nonce_id != b->nonce_id)
        {
            if((a->nonce_id == NULL) || (b->nonce_id == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->nonce_id, b->nonce_id) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->nonce_value != b->nonce_value)
        {
            if((a->nonce_value == NULL) || (b->nonce_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->nonce_value, b->nonce_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_username_password_credential(const UsernamePasswordCredential *a, const UsernamePasswordCredential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->username != b->username)
        {
            if((a->username == NULL) || (b->username == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->username, b->username) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->password != b->password)
        {
            if((a->password == NULL) || (b->password == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->password, b->password) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_device_credential(const DeviceCredential *a, const DeviceCredential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->device_serial_number != b->device_serial_number)
        {
            if((a->device_serial_number == NULL) || (b->device_serial_number == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->device_serial_number, b->device_serial_number) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->password != b->password)
        {
            if((a->password == NULL) || (b->password == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->password, b->password) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->device_identifier != b->device_identifier)
        {
            if((a->device_identifier == NULL) || (b->device_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->device_identifier, b->device_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->network_identifier != b->network_identifier)
        {
            if((a->network_identifier == NULL) || (b->network_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->network_identifier, b->network_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->machine_identifier != b->machine_identifier)
        {
            if((a->machine_identifier == NULL) || (b->machine_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->machine_identifier, b->machine_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->media_identifier != b->media_identifier)
        {
            if((a->media_identifier == NULL) || (b->media_identifier == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->media_identifier, b->media_identifier) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_attestation_credential(const AttestationCredential *a, const AttestationCredential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->attestation_type != b->attestation_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->nonce != b->nonce)
        {
            if((a->nonce == NULL) || (b->nonce == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_nonce(a->nonce, b->nonce) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attestation_measurement != b->attestation_measurement)
        {
            if((a->attestation_measurement == NULL) || (b->attestation_measurement == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->attestation_measurement, b->attestation_measurement) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attestation_assertion != b->attestation_assertion)
        {
            if((a->attestation_assertion == NULL) || (b->attestation_assertion == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_byte_string(a->attestation_assertion, b->attestation_assertion) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_credential_value(enum credential_type type, void **a, void **b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(*a != *b)
        {
            if((*a == NULL) || (*b == NULL))
            {
                return(KMIP_FALSE);
            }
            
            switch(type)
            {
                case KMIP_CRED_USERNAME_AND_PASSWORD:
                if(kmip_compare_username_password_credential(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_CRED_DEVICE:
                if(kmip_compare_device_credential(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                case KMIP_CRED_ATTESTATION:
                if(kmip_compare_attestation_credential(*a, *b) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
                break;
                
                default:
                /* NOTE (ph) Unsupported types cannot be compared. */
                return(KMIP_FALSE);
                break;
            };
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_credential(const Credential *a, const Credential *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->credential_type != b->credential_type)
        {
            return(KMIP_FALSE);
        }
        
        if(a->credential_value != b->credential_value)
        {
            if((a->credential_value == NULL) || (b->credential_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_credential_value(a->credential_type, (void**)&a->credential_value, (void**)&b->credential_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_authentication(const Authentication *a, const Authentication *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->credential != b->credential)
        {
            if((a->credential == NULL) || (b->credential == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_credential(a->credential, b->credential) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_request_header(const RequestHeader *a, const RequestHeader *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->maximum_response_size != b->maximum_response_size)
        {
            return(KMIP_FALSE);
        }
        
        if(a->asynchronous_indicator != b->asynchronous_indicator)
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_error_continuation_option != b->batch_error_continuation_option)
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_order_option != b->batch_order_option)
        {
            return(KMIP_FALSE);
        }
        
        if(a->time_stamp != b->time_stamp)
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_count != b->batch_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attestation_capable_indicator != b->attestation_capable_indicator)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attestation_type_count != b->attestation_type_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->protocol_version != b->protocol_version)
        {
            if((a->protocol_version == NULL) || (b->protocol_version == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_protocol_version(a->protocol_version, b->protocol_version) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->authentication != b->authentication)
        {
            if((a->authentication == NULL) || (b->authentication == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_authentication(a->authentication, b->authentication) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->attestation_types != b->attestation_types)
        {
            if((a->attestation_types == NULL) || (b->attestation_types == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attestation_type_count; i++)
            {
                if(a->attestation_types[i] != b->attestation_types[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->client_correlation_value != b->client_correlation_value)
        {
            if((a->client_correlation_value == NULL) || (b->client_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->client_correlation_value, b->client_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->server_correlation_value != b->server_correlation_value)
        {
            if((a->server_correlation_value == NULL) || (b->server_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->server_correlation_value, b->server_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_response_header(const ResponseHeader *a, const ResponseHeader *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->time_stamp != b->time_stamp)
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_count != b->batch_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->attestation_type_count != b->attestation_type_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->protocol_version != b->protocol_version)
        {
            if((a->protocol_version == NULL) || (b->protocol_version == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_protocol_version(a->protocol_version, b->protocol_version) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->nonce != b->nonce)
        {
            if((a->nonce == NULL) || (b->nonce == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_nonce(a->nonce, b->nonce) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->server_hashed_password != b->server_hashed_password)
        {
            if((a->server_hashed_password == NULL) || (b->server_hashed_password == NULL))
                return(KMIP_FALSE);

            if(kmip_compare_byte_string(a->server_hashed_password, b->server_hashed_password) == KMIP_FALSE)
                return(KMIP_FALSE);
        }

        if(a->attestation_types != b->attestation_types)
        {
            if((a->attestation_types == NULL) || (b->attestation_types == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->attestation_type_count; i++)
            {
                if(a->attestation_types[i] != b->attestation_types[i])
                {
                    return(KMIP_FALSE);
                }
            }
        }
        
        if(a->client_correlation_value != b->client_correlation_value)
        {
            if((a->client_correlation_value == NULL) || (b->client_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->client_correlation_value, b->client_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->server_correlation_value != b->server_correlation_value)
        {
            if((a->server_correlation_value == NULL) || (b->server_correlation_value == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_text_string(a->server_correlation_value, b->server_correlation_value) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_request_message(const RequestMessage *a, const RequestMessage *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_count != b->batch_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->request_header != b->request_header)
        {
            if((a->request_header == NULL) || (b->request_header == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_request_header(a->request_header, b->request_header) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->batch_items != b->batch_items)
        {
            if((a->batch_items == NULL) || (b->batch_items == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->batch_count; i++)
            {
                if(kmip_compare_request_batch_item(&a->batch_items[i], &b->batch_items[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_response_message(const ResponseMessage *a, const ResponseMessage *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }
        
        if(a->batch_count != b->batch_count)
        {
            return(KMIP_FALSE);
        }
        
        if(a->response_header != b->response_header)
        {
            if((a->response_header == NULL) || (b->response_header == NULL))
            {
                return(KMIP_FALSE);
            }
            
            if(kmip_compare_response_header(a->response_header, b->response_header) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
        
        if(a->batch_items != b->batch_items)
        {
            if((a->batch_items == NULL) || (b->batch_items == NULL))
            {
                return(KMIP_FALSE);
            }
            
            for(size_t i = 0; i < a->batch_count; i++)
            {
                if(kmip_compare_response_batch_item(&a->batch_items[i], &b->batch_items[i]) == KMIP_FALSE)
                {
                    return(KMIP_FALSE);
                }
            }
        }
    }
    
    return(KMIP_TRUE);
}

int
kmip_compare_linklist_items_int32(const LinkedListItem *a_item, const LinkedListItem *b_item)
{
    while((a_item != NULL) && (b_item != NULL))
    {
        if(a_item != b_item)
        {
            int32 *a_data = (int32 *)a_item->data;
            int32 *b_data = (int32 *)b_item->data;
            if(a_data != b_data)
            {
                if((a_data == NULL) || (b_data == NULL))
                {
                    return(KMIP_FALSE);
                }
                if(*a_data != *b_data)
                {
                    return(KMIP_FALSE);
                }
            }
        }

        a_item = a_item->next;
        b_item = b_item->next;
    }

    if(a_item != b_item)
    {
        return(KMIP_FALSE);
    }

    return(KMIP_TRUE);
}

int
kmip_compare_linklist_items_textstring(const LinkedListItem *a_item, const LinkedListItem *b_item)
{
    while((a_item != NULL) && (b_item != NULL))
    {
        if(a_item != b_item)
        {
            TextString *a_data = (TextString *)a_item->data;
            TextString *b_data = (TextString *)b_item->data;
            if(kmip_compare_text_string(a_data, b_data) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        a_item = a_item->next;
        b_item = b_item->next;
    }

    if(a_item != b_item)
    {
        return(KMIP_FALSE);
    }

    return(KMIP_TRUE);
}

int
kmip_compare_query_functions(const Functions* a, const Functions* b)
{
    if(a != b )
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->function_list != b->function_list))
        {
            if((a->function_list == NULL) || (b->function_list == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->function_list->size != b->function_list->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->function_list->head;
            LinkedListItem *b_item = b->function_list->head;

            if (kmip_compare_linklist_items_int32(a_item, b_item) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_operations(const Operations *a, const Operations *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->operation_list != b->operation_list))
        {
            if((a->operation_list == NULL) || (b->operation_list == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->operation_list->size != b->operation_list->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->operation_list->head;
            LinkedListItem *b_item = b->operation_list->head;
            if (kmip_compare_linklist_items_int32(a_item, b_item) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_objects(const ObjectTypes *a, const ObjectTypes *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->object_list != b->object_list))
        {
            if((a->object_list == NULL) || (b->object_list == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->object_list->size != b->object_list->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->object_list->head;
            LinkedListItem *b_item = b->object_list->head;
            if (kmip_compare_linklist_items_int32(a_item, b_item) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_alternative_endpoints(const AltEndpoints* a, const AltEndpoints* b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if((a->endpoint_list != b->endpoint_list))
        {
            if((a->endpoint_list == NULL) || (b->endpoint_list == NULL))
            {
                return(KMIP_FALSE);
            }

            if((a->endpoint_list->size != b->endpoint_list->size))
            {
                return(KMIP_FALSE);
            }

            LinkedListItem *a_item = a->endpoint_list->head;
            LinkedListItem *b_item = b->endpoint_list->head;
            if (kmip_compare_linklist_items_textstring(a_item, b_item) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_server_information(const ServerInformation* a, const ServerInformation* b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if(kmip_compare_text_string(a->server_name, b->server_name) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }

        if(kmip_compare_text_string(a->server_serial_number, b->server_serial_number) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }

        if(kmip_compare_text_string(a->server_version, b->server_version) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }

        if(kmip_compare_text_string(a->server_load, b->server_load) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }
        if(kmip_compare_text_string(a->product_name, b->product_name) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }
        if(kmip_compare_text_string(a->build_level, b->build_level) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }
        if(kmip_compare_text_string(a->build_date, b->build_date) == KMIP_FALSE)
        {
            return(KMIP_FALSE);
        }

        if(a->alternative_failover_endpoints != b->alternative_failover_endpoints )
        {
            if(kmip_compare_alternative_endpoints(a->alternative_failover_endpoints, b->alternative_failover_endpoints) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

//      if(a->vendor_specific != b->vendor_specific )
//      {
//          if(kmip_compare_vendor_specifi(a->vendor_specific, b->vendor_specific) == KMIP_FALSE)
//          {
//              return(KMIP_FALSE);
//          }
//      }

    }

    return(KMIP_TRUE);
}

int
kmip_compare_query_request_payload(const QueryRequestPayload *a, const QueryRequestPayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if(a->functions != b->functions)
        {
            if((a->functions == NULL) || (b->functions == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_query_functions(a->functions, b->functions) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}

int
kmip_compare_query_response_payload(const QueryResponsePayload *a, const QueryResponsePayload *b)
{
    if(a != b)
    {
        if((a == NULL) || (b == NULL))
        {
            return(KMIP_FALSE);
        }

        if(a->operations != b->operations)
        {
            if((a->operations == NULL) || (b->operations == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_operations(a->operations, b->operations) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->objects != b->objects)
        {
            if((a->objects == NULL) || (b->objects == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_objects(a->objects, b->objects) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->vendor_identification != b->vendor_identification)
        {
            if((a->vendor_identification == NULL) || (b->vendor_identification == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_text_string(a->vendor_identification, b->vendor_identification) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }

        if(a->server_information != b->server_information)
        {
            if((a->server_information == NULL) || (b->server_information == NULL))
            {
                return(KMIP_FALSE);
            }

            if(kmip_compare_server_information(a->server_information, b->server_information) == KMIP_FALSE)
            {
                return(KMIP_FALSE);
            }
        }
    }

    return(KMIP_TRUE);
}


/*
Encoding Functions
*/

int
kmip_encode_int8_be(KMIP *ctx, int8 value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int8));

    uint8 v = *(uint8 *)((void *)(&value));

    *ctx->index++ = v;
    
    return(KMIP_OK);
}

int
kmip_encode_int32_be(KMIP *ctx, int32 value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int32));

    uint32 v = *(uint32 *)((void *)(&value));

    *ctx->index++ = (uint8)((v & 0xFF000000) >> 24);
    *ctx->index++ = (uint8)((v & 0x00FF0000) >> 16);
    *ctx->index++ = (uint8)((v & 0x0000FF00) >> 8);
    *ctx->index++ = (uint8)((v & 0x000000FF) >> 0);

    return(KMIP_OK);
}

int
kmip_encode_int64_be(KMIP *ctx, int64 value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int64));

    uint64 v = *(uint64 *)((void *)(&value));

    *ctx->index++ = (uint8)((v & 0xFF00000000000000) >> 56);
    *ctx->index++ = (uint8)((v & 0x00FF000000000000) >> 48);
    *ctx->index++ = (uint8)((v & 0x0000FF0000000000) >> 40);
    *ctx->index++ = (uint8)((v & 0x000000FF00000000) >> 32);
    *ctx->index++ = (uint8)((v & 0x00000000FF000000) >> 24);
    *ctx->index++ = (uint8)((v & 0x0000000000FF0000) >> 16);
    *ctx->index++ = (uint8)((v & 0x000000000000FF00) >> 8);
    *ctx->index++ = (uint8)((v & 0x00000000000000FF) >> 0);
    
    return(KMIP_OK);
}

int
kmip_encode_integer(KMIP *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_INTEGER));
    kmip_encode_int32_be(ctx, 4);
    kmip_encode_int32_be(ctx, value);
    kmip_encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
kmip_encode_long(KMIP *ctx, enum tag t, int64 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_LONG_INTEGER));
    kmip_encode_int32_be(ctx, 8);
    kmip_encode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
kmip_encode_enum(KMIP *ctx, enum tag t, int32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_ENUMERATION));
    kmip_encode_int32_be(ctx, 4);
    kmip_encode_int32_be(ctx, value);
    kmip_encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
kmip_encode_bool(KMIP *ctx, enum tag t, bool32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_BOOLEAN));
    kmip_encode_int32_be(ctx, 8);
    kmip_encode_int32_be(ctx, 0);
    kmip_encode_int32_be(ctx, value);
    
    return(KMIP_OK);
}

int
kmip_encode_text_string(KMIP *ctx, enum tag t, const TextString *value)
{
    /* TODO (ph) What if value is NULL? */
    uint8 padding = CALCULATE_PADDING(value->size);
    CHECK_BUFFER_FULL(ctx, 8 + value->size + padding);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_TEXT_STRING));
    kmip_encode_int32_be(ctx, value->size);
    
    for(uint32 i = 0; i < value->size; i++)
    {
        kmip_encode_int8_be(ctx, value->value[i]);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        kmip_encode_int8_be(ctx, 0);
    }
    
    return(KMIP_OK);
}

int
kmip_encode_byte_string(KMIP *ctx, enum tag t, const ByteString *value)
{
    uint8 padding = CALCULATE_PADDING(value->size);
    CHECK_BUFFER_FULL(ctx, 8 + value->size + padding);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_BYTE_STRING));
    kmip_encode_int32_be(ctx, value->size);
    
    for(uint32 i = 0; i < value->size; i++)
    {
        kmip_encode_int8_be(ctx, value->value[i]);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        kmip_encode_int8_be(ctx, 0);
    }
    
    return(KMIP_OK);
}

int
kmip_encode_date_time(KMIP *ctx, enum tag t, int64 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_DATE_TIME));
    kmip_encode_int32_be(ctx, 8);
    kmip_encode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
kmip_encode_interval(KMIP *ctx, enum tag t, uint32 value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(t, KMIP_TYPE_INTERVAL));
    kmip_encode_int32_be(ctx, 4);
    kmip_encode_int32_be(ctx, value);
    kmip_encode_int32_be(ctx, 0);
    
    return(KMIP_OK);
}

int
kmip_encode_length(KMIP *ctx, intptr length)
{
    // NOTE: Length is encoded as a signed 32-bit integer but the usage of this
    // function uses the difference between two buffer pointers to determine
    // the length in bytes that should be encoded. See the intptr typedef in
    // the header for type details.
    int result = 0;

    if((length > INT_MAX) || (length < 0))
    {
        HANDLE_FAILURE(ctx, KMIP_INVALID_LENGTH);
    }
    else
    {
        result = kmip_encode_int32_be(ctx, (int32)length);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}

int
kmip_encode_name(KMIP *ctx, const Name *value)
{
    /* TODO (ph) Check for value == NULL? */
    
    int result = 0;
    
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_NAME_VALUE, value->value);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_enum(ctx, KMIP_TAG_NAME_TYPE, value->type);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_protection_storage_masks(KMIP *ctx, const ProtectionStorageMasks *value)
{
    CHECK_ENCODE_ARGS(ctx, value);
    CHECK_KMIP_VERSION(ctx, KMIP_2_0);

    int result = 0;

    result = kmip_encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_PROTECTION_STORAGE_MASKS, KMIP_TYPE_STRUCTURE)
    );
    CHECK_RESULT(ctx, result);

    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;

    if(value->masks != NULL)
    {
        LinkedListItem *curr = value->masks->head;
        while(curr != NULL)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_PROTECTION_STORAGE_MASK, *(int32 *)curr->data);
            CHECK_RESULT(ctx, result);

            curr = curr->next;
        }
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;

    return(KMIP_OK);
}

int
kmip_encode_attribute_name(KMIP *ctx, enum attribute_type value)
{
    int result = 0;
    enum tag t = KMIP_TAG_ATTRIBUTE_NAME;
    TextString attribute_name = {0};
    
    switch(value)
    {
        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        attribute_name.value = "Unique Identifier";
        attribute_name.size = 17;
        break;
        
        case KMIP_ATTR_NAME:
        attribute_name.value = "Name";
        attribute_name.size = 4;
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        attribute_name.value = "Object Type";
        attribute_name.size = 11;
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        attribute_name.value = "Cryptographic Algorithm";
        attribute_name.size = 23;
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        attribute_name.value = "Cryptographic Length";
        attribute_name.size = 20;
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        attribute_name.value = "Operation Policy Name";
        attribute_name.size = 21;
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        attribute_name.value = "Cryptographic Usage Mask";
        attribute_name.size = 24;
        break;
        
        case KMIP_ATTR_STATE:
        attribute_name.value = "State";
        attribute_name.size = 5;
        break;

        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            attribute_name.value = "Application Specific Information";
            attribute_name.size = 32;
        }
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            attribute_name.value = "Object Group";
            attribute_name.size = 12;
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        {
            attribute_name.value = "Activation Date";
            attribute_name.size = 15;
        } break;

        case KMIP_ATTR_DEACTIVATION_DATE:
        {
            attribute_name.value = "Deactivation Date";
            attribute_name.size = 17;
        } break;

        case KMIP_ATTR_PROCESS_START_DATE:
        {
            attribute_name.value = "Process Start Date";
            attribute_name.size = 18;
        } break;

        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            attribute_name.value = "Protect Stop Date";
            attribute_name.size = 17;
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            attribute_name.value = "Cryptographic Parameters";
            attribute_name.size = 24;
        } break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
        break;
    };
    
    result = kmip_encode_text_string(ctx, t, &attribute_name);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_encode_attribute_v1(KMIP *ctx, const Attribute *value)
{
    /* TODO (ph) Add CryptographicParameters support? */
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;
    
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_attribute_name(ctx, value->type);
    CHECK_RESULT(ctx, result);
    
    if(value->index != KMIP_UNSET)
    {
        result = kmip_encode_integer(ctx, KMIP_TAG_ATTRIBUTE_INDEX, value->index);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = 0;
    uint8 *tag_index = ctx->index;
    enum tag t = KMIP_TAG_ATTRIBUTE_VALUE;
    
    switch(value->type)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            result = kmip_encode_application_specific_information(ctx, (ApplicationSpecificInformation*)value->value);
            CHECK_RESULT(ctx, result);

            curr_index = ctx->index;
            ctx->index = tag_index;

            result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));

            ctx->index = curr_index;
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        result = kmip_encode_text_string(ctx, t, (TextString*)value->value);
        break;
        
        case KMIP_ATTR_NAME:
        /* TODO (ph) This is messy. Clean it up? */
        result = kmip_encode_name(ctx, (Name*)value->value);
        CHECK_RESULT(ctx, result);
        
        curr_index = ctx->index;
        ctx->index = tag_index;
        
        result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
        
        ctx->index = curr_index;
        break;
        
        case KMIP_ATTR_OBJECT_TYPE:
        result = kmip_encode_enum(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        result = kmip_encode_enum(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        result = kmip_encode_integer(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        result = kmip_encode_text_string(ctx, t, (TextString*)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        result = kmip_encode_integer(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_STATE:
        result = kmip_encode_enum(ctx, t, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_OBJECT_GROUP:
        {
            result = kmip_encode_text_string(ctx, t, (TextString*)value->value);
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        case KMIP_ATTR_DEACTIVATION_DATE:
        case KMIP_ATTR_PROCESS_START_DATE:
        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            result = kmip_encode_date_time(ctx, t, *(int64 *)value->value);
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            result = kmip_encode_cryptographic_parameters(ctx, (CryptographicParameters*)value->value);
            CHECK_RESULT(ctx, result);

            curr_index = ctx->index;
            ctx->index = tag_index;

            result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));

            ctx->index = curr_index;
        } break;

        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_attribute_v2(KMIP *ctx, const Attribute *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;

    switch(value->type)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            result = kmip_encode_application_specific_information(
                ctx,
                (ApplicationSpecificInformation*)value->value
            );
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        {
            result = kmip_encode_text_string(
                ctx,
                KMIP_TAG_UNIQUE_IDENTIFIER,
                (TextString*)value->value
            );
        }
        break;

        case KMIP_ATTR_NAME:
        {
            result = kmip_encode_name(ctx, (Name*)value->value);
        }
        break;

        case KMIP_ATTR_OBJECT_TYPE:
        {
            result = kmip_encode_enum(
                ctx,
                KMIP_TAG_OBJECT_TYPE,
                *(int32 *)value->value
            );
        }
        break;

        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        {
            result = kmip_encode_enum(
                ctx,
                KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM,
                *(int32 *)value->value
            );
        }
        break;

        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        {
            result = kmip_encode_integer(
                ctx,
                KMIP_TAG_CRYPTOGRAPHIC_LENGTH,
                *(int32 *)value->value
            );
        }
        break;

        case KMIP_ATTR_OPERATION_POLICY_NAME:
        {
            result = kmip_encode_text_string(
                ctx,
                KMIP_TAG_OPERATION_POLICY_NAME,
                (TextString*)value->value
            );
        }
        break;

        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        {
            result = kmip_encode_integer(
                ctx,
                KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK,
                *(int32 *)value->value)
            ;
        }
        break;

        case KMIP_ATTR_STATE:
        {
            result = kmip_encode_enum(
                ctx,
                KMIP_TAG_STATE,
                *(int32 *)value->value
            );
        }
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            result = kmip_encode_text_string(
                ctx,
                KMIP_TAG_OBJECT_GROUP,
                (TextString*)value->value
            );
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        {
            result = kmip_encode_date_time(
                ctx,
                KMIP_TAG_ACTIVATION_DATE,
                *(int64 *)value->value
            );
        } break;

        case KMIP_ATTR_DEACTIVATION_DATE:
        {
            result = kmip_encode_date_time(
                ctx,
                KMIP_TAG_DEACTIVATION_DATE,
                *(int64 *)value->value
            );
        } break;

        case KMIP_ATTR_PROCESS_START_DATE:
        {
            result = kmip_encode_date_time(
                ctx,
                KMIP_TAG_PROCESS_START_DATE,
                *(int64 *)value->value
            );
        } break;

        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            result = kmip_encode_date_time(
                ctx,
                KMIP_TAG_PROTECT_STOP_DATE,
                *(int64 *)value->value
            );
        } break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            result = kmip_encode_cryptographic_parameters(
                ctx,
                (CryptographicParameters*)value->value
            );
        } break;

        default:
        {
            kmip_push_error_frame(ctx, __func__, __LINE__);
            return(KMIP_ERROR_ATTR_UNSUPPORTED);
        }
        break;
    };
    CHECK_RESULT(ctx, result);

    return(KMIP_OK);
}

int
kmip_encode_attribute(KMIP *ctx, const Attribute *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    if(ctx->version < KMIP_2_0)
    {
        return(kmip_encode_attribute_v1(ctx, value));
    }
    else
    {
        return(kmip_encode_attribute_v2(ctx, value));
    }
}

int
kmip_encode_attributes(KMIP *ctx, const Attributes *value)
{
    CHECK_ENCODE_ARGS(ctx, value);
    CHECK_KMIP_VERSION(ctx, KMIP_2_0);

    int result = 0;

    result = kmip_encode_int32_be(
        ctx,
        TAG_TYPE(KMIP_TAG_ATTRIBUTES, KMIP_TYPE_STRUCTURE)
    );
    CHECK_RESULT(ctx, result);

    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;

    if(value->attribute_list != NULL)
    {
        LinkedListItem *curr = value->attribute_list->head;
        while(curr != NULL)
        {
            Attribute *attribute = (Attribute *)curr->data;
            result = kmip_encode_attribute(ctx, attribute);
            CHECK_RESULT(ctx, result);

            curr = curr->next;
        }
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;

    return(KMIP_OK);
}

int
kmip_encode_template_attribute(KMIP *ctx, const TemplateAttribute *value)
{
    int result = 0;
    
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_TEMPLATE_ATTRIBUTE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    for(size_t i = 0; i < value->name_count; i++)
    {
        result = kmip_encode_name(ctx, &value->names[i]);
        CHECK_RESULT(ctx, result);
    }
    
    for(size_t i = 0; i <value->attribute_count; i++)
    {
        result = kmip_encode_attribute(ctx, &value->attributes[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);
    
    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_protocol_version(KMIP *ctx, const ProtocolVersion *value)
{
    CHECK_BUFFER_FULL(ctx, 40);
    
    kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_PROTOCOL_VERSION, KMIP_TYPE_STRUCTURE));
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    kmip_encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MAJOR, value->major);
    kmip_encode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MINOR, value->minor);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    kmip_encode_length(ctx, curr_index - value_index);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_application_specific_information(KMIP *ctx, const ApplicationSpecificInformation *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);

    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;

    if(value->application_namespace != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_APPLICATION_NAMESPACE, value->application_namespace);
        CHECK_RESULT(ctx, result);
    }
    else
    {
        kmip_set_error_message(ctx, "The ApplicationSpecificInformation structure is missing the application name field.");
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_INVALID_FIELD);
    }

    if(value->application_data != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_APPLICATION_DATA, value->application_data);
        CHECK_RESULT(ctx, result);
    }
    else
    {
        if(ctx->version < KMIP_1_3)
        {
            kmip_set_error_message(ctx, "The ApplicationSpecificInformation structure is missing the application data field.");
            kmip_push_error_frame(ctx, __func__, __LINE__);
            return(KMIP_INVALID_FIELD);
        }
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;

    return(KMIP_OK);
}

int
kmip_encode_cryptographic_parameters(KMIP *ctx, const CryptographicParameters *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->block_cipher_mode != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_BLOCK_CIPHER_MODE, value->block_cipher_mode);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->padding_method != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_PADDING_METHOD, value->padding_method);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->hashing_algorithm != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_HASHING_ALGORITHM, value->hashing_algorithm);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_role_type != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_KEY_ROLE_TYPE, value->key_role_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(value->digital_signature_algorithm != 0)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM, value->digital_signature_algorithm);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->cryptographic_algorithm != 0)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, value->cryptographic_algorithm);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->random_iv != KMIP_UNSET)
        {
            result = kmip_encode_bool(ctx, KMIP_TAG_RANDOM_IV, value->random_iv);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->iv_length != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_IV_LENGTH, value->iv_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->tag_length != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_TAG_LENGTH, value->tag_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->fixed_field_length != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_FIXED_FIELD_LENGTH, value->fixed_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->invocation_field_length != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_INVOCATION_FIELD_LENGTH, value->invocation_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->counter_length != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_COUNTER_LENGTH, value->counter_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->initial_counter_value != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_INITIAL_COUNTER_VALUE, value->initial_counter_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->salt_length != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_SALT_LENGTH, value->salt_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->mask_generator != 0)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_MASK_GENERATOR, value->mask_generator);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->mask_generator_hashing_algorithm != 0)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM, value->mask_generator_hashing_algorithm);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->p_source != NULL)
        {
            result = kmip_encode_byte_string(ctx, KMIP_TAG_P_SOURCE, value->p_source);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->trailer_field != KMIP_UNSET)
        {
            result = kmip_encode_integer(ctx, KMIP_TAG_TRAILER_FIELD, value->trailer_field);
            CHECK_RESULT(ctx, result);
        }
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_encryption_key_information(KMIP *ctx, const EncryptionKeyInformation *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ENCRYPTION_KEY_INFORMATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(value->cryptographic_parameters != 0)
    {
        result = kmip_encode_cryptographic_parameters(ctx, value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_mac_signature_key_information(KMIP *ctx, const MACSignatureKeyInformation *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(value->cryptographic_parameters != 0)
    {
        result = kmip_encode_cryptographic_parameters(ctx, value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_key_wrapping_data(KMIP *ctx, const KeyWrappingData *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_KEY_WRAPPING_DATA, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    CHECK_RESULT(ctx, result);
    
    if(value->encryption_key_info != NULL)
    {
        result = kmip_encode_encryption_key_information(ctx, value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->mac_signature_key_info != NULL)
    {
        result = kmip_encode_mac_signature_key_information(ctx, value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->mac_signature != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_MAC_SIGNATURE, value->mac_signature);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->iv_counter_nonce != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_IV_COUNTER_NONCE, value->iv_counter_nonce);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_ENCODING_OPTION, value->encoding_option);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_transparent_symmetric_key(KMIP *ctx, const TransparentSymmetricKey *value)
{
    int result = 0;
    
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_KEY_MATERIAL, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_byte_string(ctx, KMIP_TAG_KEY, value->key);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_key_material(KMIP *ctx, enum key_format_type format, const void *value)
{
    int result = 0;
    
    switch(format)
    {
        case KMIP_KEYFORMAT_RAW:
        case KMIP_KEYFORMAT_OPAQUE:
        case KMIP_KEYFORMAT_PKCS1:
        case KMIP_KEYFORMAT_PKCS8:
        case KMIP_KEYFORMAT_X509:
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        result = kmip_encode_byte_string(ctx, KMIP_TAG_KEY_MATERIAL, (ByteString*)value);
        CHECK_RESULT(ctx, result);
        return(KMIP_OK);
        break;
        
        default:
        break;
    };
    
    switch(format)
    {
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        result = kmip_encode_transparent_symmetric_key(ctx, (TransparentSymmetricKey*)value);
        CHECK_RESULT(ctx, result);
        break;
        
        /* TODO (ph) The rest require BigInteger support. */
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    return(KMIP_OK);
}

int
kmip_encode_key_value(KMIP *ctx, enum key_format_type format, const KeyValue *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_KEY_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_key_material(ctx, format, value->key_material);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < value->attribute_count; i++)
    {
        result = kmip_encode_attribute(ctx, &value->attributes[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_key_block(KMIP *ctx, const KeyBlock *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_KEY_BLOCK, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, value->key_format_type);
    CHECK_RESULT(ctx, result);
    
    if(value->key_compression_type != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, value->key_compression_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_wrapping_data != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_KEY_VALUE, (ByteString*)value->key_value);
    }
    else
    {
        result = kmip_encode_key_value(ctx, value->key_format_type, (KeyValue*)value->key_value);
    }
    CHECK_RESULT(ctx, result);
    
    if(value->cryptographic_algorithm != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, value->cryptographic_algorithm);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->cryptographic_length != KMIP_UNSET)
    {
        result = kmip_encode_integer(ctx, KMIP_TAG_CRYPTOGRAPHIC_LENGTH, value->cryptographic_length);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_wrapping_data != NULL)
    {
        result = kmip_encode_key_wrapping_data(ctx, value->key_wrapping_data);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_symmetric_key(KMIP *ctx, const SymmetricKey *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_SYMMETRIC_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_public_key(KMIP *ctx, const PublicKey *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_PUBLIC_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_private_key(KMIP *ctx, const PrivateKey *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_PRIVATE_KEY, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_key_wrapping_specification(KMIP *ctx, const KeyWrappingSpecification *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_KEY_WRAPPING_SPECIFICATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    CHECK_RESULT(ctx, result);
    
    if(value->encryption_key_info != NULL)
    {
        result = kmip_encode_encryption_key_information(ctx, value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->mac_signature_key_info != NULL)
    {
        result = kmip_encode_mac_signature_key_information(ctx, value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    for(size_t i = 0; i < value->attribute_name_count; i++)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_ATTRIBUTE_NAME, &value->attribute_names[i]);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_ENCODING_OPTION, value->encoding_option);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_create_request_payload(KMIP *ctx, const CreateRequestPayload *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);

    if(ctx->version < KMIP_2_0)
    {
        result = kmip_encode_template_attribute(ctx, value->template_attribute);
        CHECK_RESULT(ctx, result);
    }
    else
    {
        if(value->attributes)
        {
            result = kmip_encode_attributes(ctx, value->attributes);
            CHECK_RESULT(ctx, result);
        }
        else if(value->template_attribute)
        {
            Attributes *attributes = ctx->calloc_func(ctx->state, 1, sizeof(Attributes));
            LinkedList *list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
            attributes->attribute_list = list;
            for(size_t i = 0; i < value->template_attribute->attribute_count; i++)
            {
                LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
                item->data = kmip_deep_copy_attribute(ctx, &value->template_attribute->attributes[i]);
                kmip_linked_list_enqueue(list, item);
            }

            result = kmip_encode_attributes(ctx, attributes);

            kmip_free_attributes(ctx, attributes);
            ctx->free_func(ctx->state, attributes);

            CHECK_RESULT(ctx, result);
        }

        if(value->protection_storage_masks != NULL)
        {
            result = kmip_encode_protection_storage_masks(ctx, value->protection_storage_masks);
            CHECK_RESULT(ctx, result);
        }
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_create_response_payload(KMIP *ctx, const CreateResponsePayload *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);

    if(ctx->version < KMIP_2_0)
    {
        if(value->template_attribute != NULL)
        {
            result = kmip_encode_template_attribute(ctx, value->template_attribute);
            CHECK_RESULT(ctx, result);
        }
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_register_request_payload(KMIP *ctx, const RegisterRequestPayload *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);

    if(ctx->version < KMIP_2_0)
    {
        result = kmip_encode_template_attribute(ctx, value->template_attribute);
        CHECK_RESULT(ctx, result);
    }
    else
    {
        if(value->attributes)
        {
            result = kmip_encode_attributes(ctx, value->attributes);
            CHECK_RESULT(ctx, result);
        }
        else if(value->template_attribute)
        {
            Attributes *attributes = ctx->calloc_func(ctx->state, 1, sizeof(Attributes));
            LinkedList *list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
            attributes->attribute_list = list;
            for(size_t i = 0; i < value->template_attribute->attribute_count; i++)
            {
                LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
                item->data = kmip_deep_copy_attribute(ctx, &value->template_attribute->attributes[i]);
                kmip_linked_list_enqueue(list, item);
            }

            result = kmip_encode_attributes(ctx, attributes);

            kmip_free_attributes(ctx, attributes);
            ctx->free_func(ctx->state, attributes);

            CHECK_RESULT(ctx, result);
        }

        if(value->protection_storage_masks != NULL)
        {
            result = kmip_encode_protection_storage_masks(ctx, value->protection_storage_masks);
            CHECK_RESULT(ctx, result);
        }
    }

    // TODO: this currently onlyhandles symmetric keys, but in theory the protocol also supports other types
    result = kmip_encode_symmetric_key(ctx, &value->object);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_register_response_payload(KMIP *ctx, const RegisterResponsePayload *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);

    if(ctx->version < KMIP_2_0)
    {
        if(value->template_attribute != NULL)
        {
            result = kmip_encode_template_attribute(ctx, value->template_attribute);
            CHECK_RESULT(ctx, result);
        }
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_get_request_payload(KMIP *ctx, const GetRequestPayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->unique_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_format_type != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, value->key_format_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->key_wrap_type != 0)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_KEY_WRAP_TYPE, value->key_wrap_type);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(value->key_compression_type != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, value->key_compression_type);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->key_wrapping_spec != NULL)
    {
        result = kmip_encode_key_wrapping_specification(ctx, value->key_wrapping_spec);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_get_response_payload(KMIP *ctx, const GetResponsePayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    switch(value->object_type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        result = kmip_encode_symmetric_key(ctx, (const SymmetricKey*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        result = kmip_encode_public_key(ctx, (const PublicKey*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        result = kmip_encode_private_key(ctx, (const PrivateKey*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_get_attribute_request_payload(KMIP *ctx, const GetAttributeRequestPayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->unique_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }

    if(value->attribute_name != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_ATTRIBUTE_NAME, value->attribute_name);
        CHECK_RESULT(ctx, result);
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_get_attribute_response_payload(KMIP *ctx, const GetAttributeResponsePayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);

    result = kmip_decode_attribute(ctx, value->attribute);
    CHECK_RESULT(ctx, result);

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_destroy_request_payload(KMIP *ctx, const DestroyRequestPayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->unique_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_destroy_response_payload(KMIP *ctx, const DestroyResponsePayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_nonce(KMIP *ctx, const Nonce *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_NONCE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_byte_string(ctx, KMIP_TAG_NONCE_ID, value->nonce_id);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_byte_string(ctx, KMIP_TAG_NONCE_VALUE, value->nonce_value);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_username_password_credential(KMIP *ctx, const UsernamePasswordCredential *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_text_string(ctx, KMIP_TAG_USERNAME, value->username);
    CHECK_RESULT(ctx, result);
    
    if(value->password != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_PASSWORD, value->password);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_device_credential(KMIP *ctx, const DeviceCredential *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    if(value->device_serial_number != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_DEVICE_SERIAL_NUMBER, value->device_serial_number);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->password != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_PASSWORD, value->password);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->device_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_DEVICE_IDENTIFIER, value->device_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->network_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_NETWORK_IDENTIFIER, value->network_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->machine_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_MACHINE_IDENTIFIER, value->machine_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->media_identifier != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_MEDIA_IDENTIFIER, value->media_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_attestation_credential(KMIP *ctx, const AttestationCredential *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_nonce(ctx, value->nonce);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_enum(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_type);
    CHECK_RESULT(ctx, result);
    
    if(value->attestation_measurement != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_ATTESTATION_MEASUREMENT, value->attestation_measurement);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->attestation_assertion != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_ATTESTATION_ASSERTION, value->attestation_assertion);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_credential_value(KMIP *ctx, enum credential_type type, void *value)
{
    int result = 0;
    
    switch(type)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        result = kmip_encode_username_password_credential(ctx, (UsernamePasswordCredential*)value);
        break;
        
        case KMIP_CRED_DEVICE:
        result = kmip_encode_device_credential(ctx, (DeviceCredential*)value);
        break;
        
        case KMIP_CRED_ATTESTATION:
        result = kmip_encode_attestation_credential(ctx, (AttestationCredential*)value);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    }
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_encode_credential(KMIP *ctx, const Credential *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_CREDENTIAL, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_CREDENTIAL_TYPE, value->credential_type);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_credential_value(ctx, value->credential_type, value->credential_value);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_authentication(KMIP *ctx, const Authentication *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_AUTHENTICATION, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_credential(ctx, value->credential);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_request_header(KMIP *ctx, const RequestHeader *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_HEADER, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    /* HERE (ph) Stopped working here after bug with 0 vs KMIP_UNSET */
    if(value->maximum_response_size != KMIP_UNSET)
    {
        result = kmip_encode_integer(ctx, KMIP_TAG_MAXIMUM_RESPONSE_SIZE, value->maximum_response_size);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->client_correlation_value != NULL)
        {
            result = kmip_encode_text_string(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE, value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->server_correlation_value != NULL)
        {
            result = kmip_encode_text_string(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE, value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(value->asynchronous_indicator != KMIP_UNSET)
    {
        result = kmip_encode_bool(ctx, KMIP_TAG_ASYNCHRONOUS_INDICATOR, value->asynchronous_indicator);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(value->attestation_capable_indicator != KMIP_UNSET)
        {
            result = kmip_encode_bool(ctx, KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR, value->attestation_capable_indicator);
            CHECK_RESULT(ctx, result);
        }
        
        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_types[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(value->authentication != NULL)
    {
        result = kmip_encode_authentication(ctx, value->authentication);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->batch_error_continuation_option != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION, value->batch_error_continuation_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->batch_order_option != KMIP_UNSET)
    {
        result = kmip_encode_bool(ctx, KMIP_TAG_BATCH_ORDER_OPTION, value->batch_order_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->time_stamp != 0)
    {
        result = kmip_encode_date_time(ctx, KMIP_TAG_TIME_STAMP, value->time_stamp);
        CHECK_RESULT(ctx, result);
    }
    
    result = kmip_encode_integer(ctx, KMIP_TAG_BATCH_COUNT, value->batch_count);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_response_header(KMIP *ctx, const ResponseHeader *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_HEADER, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    result = kmip_encode_date_time(ctx, KMIP_TAG_TIME_STAMP, value->time_stamp);
    CHECK_RESULT(ctx, result);
    
    if(ctx->version >= KMIP_1_2)
    {
        if(value->nonce != NULL)
        {
            result = kmip_encode_nonce(ctx, value->nonce);
            CHECK_RESULT(ctx, result);
        }

        if(ctx->version >= KMIP_2_0)
        {
            if(value->server_hashed_password != NULL)
            {
                result = kmip_encode_byte_string(ctx, KMIP_TAG_SERVER_HASHED_PASSWORD, value->server_hashed_password);
                CHECK_RESULT(ctx, result);
            }
        }

        for(size_t i = 0; i < value->attestation_type_count; i++)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_types[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(value->client_correlation_value != NULL)
        {
            result = kmip_encode_text_string(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE, value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(value->server_correlation_value != NULL)
        {
            result = kmip_encode_text_string(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE, value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    result = kmip_encode_integer(ctx, KMIP_TAG_BATCH_COUNT, value->batch_count);
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_request_batch_item(KMIP *ctx, const RequestBatchItem *value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_OPERATION, value->operation);
    CHECK_RESULT(ctx, result);

    if(ctx->version >= KMIP_2_0)
    {
        if(value->ephemeral != KMIP_UNSET)
        {
            result=kmip_encode_bool(ctx, KMIP_TAG_EPHEMERAL, value->ephemeral);
            CHECK_RESULT(ctx, result);
        }
    }

    if(value->unique_batch_item_id != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID, value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    switch(value->operation)
    {
        case KMIP_OP_CREATE:
        result = kmip_encode_create_request_payload(ctx, (CreateRequestPayload*)value->request_payload);
        break;

        case KMIP_OP_REGISTER:
        result = kmip_encode_register_request_payload(ctx, (RegisterRequestPayload*)value->request_payload);
        break;
        
        case KMIP_OP_GET:
        result = kmip_encode_get_request_payload(ctx, (GetRequestPayload*)value->request_payload);
        break;

        case KMIP_OP_GET_ATTRIBUTES:
        result = kmip_encode_get_attribute_request_payload(ctx, (GetAttributeRequestPayload*)value->request_payload);
        break;
        
        case KMIP_OP_DESTROY:
        result = kmip_encode_destroy_request_payload(ctx, (DestroyRequestPayload*)value->request_payload);
        break;
        
        case KMIP_OP_QUERY:
        result = kmip_encode_query_request_payload(ctx, (QueryRequestPayload*)value->request_payload);
        break;

        case KMIP_OP_LOCATE:
        result = kmip_encode_locate_request_payload(ctx, (LocateRequestPayload*)value->request_payload);
        break;

        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_response_batch_item(KMIP *ctx, const ResponseBatchItem *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_enum(ctx, KMIP_TAG_OPERATION, value->operation);
    CHECK_RESULT(ctx, result);
    
    if(value->unique_batch_item_id != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID, value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    result = kmip_encode_enum(ctx, KMIP_TAG_RESULT_STATUS, value->result_status);
    CHECK_RESULT(ctx, result);
    
    if(value->result_reason != 0)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_RESULT_REASON, value->result_reason);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->result_message != NULL)
    {
        result = kmip_encode_text_string(ctx, KMIP_TAG_RESULT_MESSAGE, value->result_message);
        CHECK_RESULT(ctx, result);
    }
    
    if(value->asynchronous_correlation_value != NULL)
    {
        result = kmip_encode_byte_string(ctx, KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE, value->asynchronous_correlation_value);
        CHECK_RESULT(ctx, result);
    }
    
    switch(value->operation)
    {
        case KMIP_OP_CREATE:
        result = kmip_encode_create_response_payload(ctx, (CreateResponsePayload*)value->response_payload);
        break;

        case KMIP_OP_REGISTER:
        result = kmip_encode_register_response_payload(ctx, (RegisterResponsePayload*)value->response_payload);
        break;
        
        case KMIP_OP_GET_ATTRIBUTES:
        result = kmip_encode_get_attribute_response_payload(ctx, (GetAttributeResponsePayload*)value->response_payload);
        break;
        
        case KMIP_OP_DESTROY:
        result = kmip_encode_destroy_response_payload(ctx, (DestroyResponsePayload*)value->response_payload);
        break;
        
        case KMIP_OP_QUERY:
        result = kmip_encode_query_response_payload(ctx, (QueryResponsePayload*)value->response_payload);
        break;

        case KMIP_OP_LOCATE:
        result = kmip_encode_locate_response_payload(ctx, (LocateResponsePayload*)value->response_payload);
        break;

        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_request_message(KMIP *ctx, const RequestMessage *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_MESSAGE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_request_header(ctx, value->request_header);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < value->batch_count; i++)
    {
        result = kmip_encode_request_batch_item(ctx, &value->batch_items[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_response_message(KMIP *ctx, const ResponseMessage *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_RESPONSE_MESSAGE, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);
    
    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;
    
    result = kmip_encode_response_header(ctx, value->response_header);
    CHECK_RESULT(ctx, result);
    
    for(size_t i = 0; i < value->batch_count; i++)
    {
        result = kmip_encode_response_batch_item(ctx, &value->batch_items[i]);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = ctx->index;
    ctx->index = length_index;
    
    result = kmip_encode_length(ctx, curr_index - value_index);
    CHECK_RESULT(ctx, result);

    ctx->index = curr_index;
    
    return(KMIP_OK);
}

int
kmip_encode_query_functions(KMIP *ctx, const Functions* value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;

    if(value->function_list != NULL)
    {
        LinkedListItem *curr = value->function_list->head;
        while(curr != NULL)
        {
            result = kmip_encode_enum(ctx, KMIP_TAG_QUERY_FUNCTION, *(int32 *)curr->data);
            CHECK_RESULT(ctx, result);

            curr = curr->next;
        }
    }

    return(KMIP_OK);
}
int
kmip_encode_query_request_payload(KMIP *ctx, const QueryRequestPayload *value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);

    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;

    if(value->functions != NULL)
    {
        result = kmip_encode_query_functions(ctx, value->functions);
        CHECK_RESULT(ctx, result);
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    kmip_encode_int32_be(ctx, curr_index - value_index);

    ctx->index = curr_index;

    return(KMIP_OK);
}


int
kmip_encode_query_response_payload(KMIP *ctx, const QueryResponsePayload *value)
{
    //TODO
    (void) ctx;
    (void) value;
    return(KMIP_NOT_IMPLEMENTED);
}

/*
Decoding Functions
*/

int
kmip_decode_int8_be(KMIP *ctx, void *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int8));
    
    int8 *i = (int8*)value;
    
    *i = 0;
    *i = *ctx->index++;
    
    return(KMIP_OK);
}

int
kmip_decode_int32_be(KMIP *ctx, void *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int32));
    
    int32 *i = (int32*)value;
    
    *i = 0;
    *i |= ((int32)*ctx->index++ << 24);
    *i |= ((int32)*ctx->index++ << 16);
    *i |= ((int32)*ctx->index++ << 8);
    *i |= ((int32)*ctx->index++ << 0);
    
    return(KMIP_OK);
}

int
kmip_decode_int64_be(KMIP *ctx, void *value)
{
    CHECK_BUFFER_FULL(ctx, sizeof(int64));
    
    int64 *i = (int64*)value;
    
    *i = 0;
    *i |= ((int64)*ctx->index++ << 56);
    *i |= ((int64)*ctx->index++ << 48);
    *i |= ((int64)*ctx->index++ << 40);
    *i |= ((int64)*ctx->index++ << 32);
    *i |= ((int64)*ctx->index++ << 24);
    *i |= ((int64)*ctx->index++ << 16);
    *i |= ((int64)*ctx->index++ << 8);
    *i |= ((int64)*ctx->index++ << 0);
    
    return(KMIP_OK);
}

int
kmip_decode_length(KMIP *ctx, uint32 *value)
{
    CHECK_BUFFER_FULL(ctx, 4);

    kmip_decode_int32_be(ctx, value);

    if(*value > INT_MAX)
    {
        HANDLE_FAILURE(ctx, KMIP_INVALID_LENGTH);
    }

    return(KMIP_OK);
}

int
kmip_decode_integer(KMIP *ctx, enum tag t, int32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    uint32 length = 0;
    int32 padding = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_INTEGER);

    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    kmip_decode_int32_be(ctx, value);
    
    kmip_decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
kmip_decode_long(KMIP *ctx, enum tag t, int64 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_LONG_INTEGER);

    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    kmip_decode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
kmip_decode_enum(KMIP *ctx, enum tag t, void *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    uint32 length = 0;
    int32 *v = (int32*)value;
    int32 padding = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_ENUMERATION);
    
    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    kmip_decode_int32_be(ctx, v);
    
    kmip_decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
kmip_decode_bool(KMIP *ctx, enum tag t, bool32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    uint32 length = 0;
    int32 padding = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_BOOLEAN);
    
    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    kmip_decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    kmip_decode_int32_be(ctx, value);
    CHECK_BOOLEAN(ctx, *value);
    
    return(KMIP_OK);
}

int
kmip_decode_text_string(KMIP *ctx, enum tag t, TextString *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int32 tag_type = 0;
    uint32 length = 0;
    uint8 padding = 0;
    int8 spacer = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_TEXT_STRING);
    
    kmip_decode_length(ctx, &length);
    padding = CALCULATE_PADDING(length);
    CHECK_BUFFER_FULL(ctx, length + padding);
    
    value->value = ctx->calloc_func(ctx->state, 1, length);
    value->size = length;
    
    char *index = value->value;
    
    for(uint32 i = 0; i < length; i++)
    {
        kmip_decode_int8_be(ctx, (int8*)index++);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        kmip_decode_int8_be(ctx, &spacer);
        CHECK_PADDING(ctx, spacer);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_byte_string(KMIP *ctx, enum tag t, ByteString *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int32 tag_type = 0;
    uint32 length = 0;
    uint8 padding = 0;
    int8 spacer = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_BYTE_STRING);

    kmip_decode_length(ctx, &length);
    padding = CALCULATE_PADDING(length);
    CHECK_BUFFER_FULL(ctx, length + padding);
    
    value->value = ctx->calloc_func(ctx->state, 1, length);
    value->size = length;
    
    uint8 *index = value->value;
    
    for(uint32 i = 0; i < length; i++)
    {
        kmip_decode_int8_be(ctx, index++);
    }
    for(uint8 i = 0; i < padding; i++)
    {
        kmip_decode_int8_be(ctx, &spacer);
        CHECK_PADDING(ctx, spacer);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_date_time(KMIP *ctx, enum tag t, int64 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_DATE_TIME);
    
    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 8);
    
    kmip_decode_int64_be(ctx, value);
    
    return(KMIP_OK);
}

int
kmip_decode_interval(KMIP *ctx, enum tag t, uint32 *value)
{
    CHECK_BUFFER_FULL(ctx, 16);
    
    int32 tag_type = 0;
    uint32 length = 0;
    int32 padding = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, t, KMIP_TYPE_INTERVAL);
    
    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 4);
    
    kmip_decode_int32_be(ctx, value);
    
    kmip_decode_int32_be(ctx, &padding);
    CHECK_PADDING(ctx, padding);
    
    return(KMIP_OK);
}

int
kmip_decode_name(KMIP *ctx, Name *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_NAME_VALUE, value->value);
    CHECK_RESULT(ctx, result);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_NAME_TYPE, (int32*)&value->type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_NAME_TYPE, value->type);
    
    return(KMIP_OK);
}

int
kmip_decode_attribute_name(KMIP *ctx, enum attribute_type *value)
{
    int result = 0;
    enum tag t = KMIP_TAG_ATTRIBUTE_NAME;
    TextString n = {0};
    
    result = kmip_decode_text_string(ctx, t, &n);
    CHECK_RESULT(ctx, result);
    
    if((n.size == 32) && (strncmp(n.value, "Application Specific Information", 32) == 0))
    {
        *value = KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION;
    }
    else if((n.size == 17) && (strncmp(n.value, "Unique Identifier", 17) == 0))
    {
        *value = KMIP_ATTR_UNIQUE_IDENTIFIER;
    }
    else if((n.size == 4) && (strncmp(n.value, "Name", 4) == 0))
    {
        *value = KMIP_ATTR_NAME;
    }
    else if((n.size == 11) && (strncmp(n.value, "Object Type", 11) == 0))
    {
        *value = KMIP_ATTR_OBJECT_TYPE;
    }
    else if((n.size == 23) && (strncmp(n.value, "Cryptographic Algorithm", 23) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
    }
    else if((n.size == 20) && (strncmp(n.value, "Cryptographic Length", 20) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
    }
    else if((n.size == 21) && (strncmp(n.value, "Operation Policy Name", 21) == 0))
    {
        *value = KMIP_ATTR_OPERATION_POLICY_NAME;
    }
    else if((n.size == 24) && (strncmp(n.value, "Cryptographic Usage Mask", 24) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
    }
    else if((n.size == 5) && (strncmp(n.value, "State", 5) == 0))
    {
        *value = KMIP_ATTR_STATE;
    }
    else if((n.size == 12) && (strncmp(n.value, "Object Group", 12) == 0))
    {
        *value = KMIP_ATTR_OBJECT_GROUP;
    }
    else if((n.size == 15) && (strncmp(n.value, "Activation Date", 15) == 0))
    {
        *value = KMIP_ATTR_ACTIVATION_DATE;
    }
    else if((n.size == 17) && (strncmp(n.value, "Deactivation Date", 17) == 0))
    {
        *value = KMIP_ATTR_DEACTIVATION_DATE;
    }
    else if((18 == n.size) && (strncmp(n.value, "Process Start Date", 18) == 0))
    {
        *value = KMIP_ATTR_PROCESS_START_DATE;
    }
    else if((17 == n.size) && (strncmp(n.value, "Protect Stop Date", 17) == 0))
    {
        *value = KMIP_ATTR_PROTECT_STOP_DATE;
    }
    else if((24 == n.size) && (strncmp(n.value, "Cryptographic Parameters", 24) == 0))
    {
        *value = KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS;
    }
    /* TODO (ph) Add all remaining attributes here. */
    else
    {
        kmip_push_error_frame(ctx, __func__, __LINE__);
        kmip_free_text_string(ctx, &n);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
    }
    
    kmip_free_text_string(ctx, &n);
    return(KMIP_OK);
}

int
kmip_decode_protection_storage_masks(KMIP *ctx, ProtectionStorageMasks *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_KMIP_VERSION(ctx, KMIP_2_0);
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    result = kmip_decode_int32_be(ctx, &tag_type);
    CHECK_RESULT(ctx, result);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_PROTECTION_STORAGE_MASKS, KMIP_TYPE_STRUCTURE);

    result = kmip_decode_length(ctx, &length);
    CHECK_RESULT(ctx, result);
    CHECK_BUFFER_FULL(ctx, length);

    value->masks = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->masks, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_PROTECTION_STORAGE_MASK)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->masks, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Protection Storage Mask");

        result = kmip_decode_integer(ctx, KMIP_TAG_PROTECTION_STORAGE_MASK, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

int
kmip_decode_attribute_v1(KMIP *ctx, Attribute *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    kmip_init_attribute(value);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_ATTRIBUTE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_attribute_name(ctx, &value->type);
    CHECK_RESULT(ctx, result);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ATTRIBUTE_INDEX))
    {
        result = kmip_decode_integer(ctx, KMIP_TAG_ATTRIBUTE_INDEX, &value->index);
        CHECK_RESULT(ctx, result);
    }
    
    uint8 *curr_index = 0;
    uint8 *tag_index = ctx->index;
    enum tag t = KMIP_TAG_ATTRIBUTE_VALUE;
    
    switch(value->type)
    {
        case KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION:
        {
            /* TODO (ph) Like encoding, this is messy. Better solution? */
            if(kmip_is_tag_type_next(ctx, KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE))
            {
                /* NOTE (ph) Decoding structures will fail if the structure tag */
                /* is not present in the encoding. Temporarily swap the tags, */
                /* decode the structure, and then swap the tags back to */
                /* preserve the encoding. The tag/type check above guarantees */
                /* space exists for this to succeed. */
                kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION, KMIP_TYPE_STRUCTURE));
                ctx->index = tag_index;
                value->value = ctx->calloc_func(ctx->state, 1, sizeof(ApplicationSpecificInformation));
                CHECK_NEW_MEMORY(ctx, value->value, sizeof(ApplicationSpecificInformation), "ApplicationSpecificInformation structure");
                result = kmip_decode_application_specific_information(ctx, (ApplicationSpecificInformation*)value->value);

                curr_index = ctx->index;
                ctx->index = tag_index;

                kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
                ctx->index = curr_index;
            }
            else
            {
                result = KMIP_TAG_MISMATCH;
            }

            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_ATTR_UNIQUE_IDENTIFIER:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(TextString), "UniqueIdentifier text string");
        result = kmip_decode_text_string(ctx, t, (TextString*)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_NAME:
        {
            /* TODO (ph) Like encoding, this is messy. Better solution? */
            if(kmip_is_tag_type_next(ctx, KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE))
            {
                /* NOTE (ph) Decoding structures will fail if the structure tag */
                /* is not present in the encoding. Temporarily swap the tags, */
                /* decode the structure, and then swap the tags back to */
                /* preserve the encoding. The tag/type check above guarantees */
                /* space exists for this to succeed. */
                kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_NAME, KMIP_TYPE_STRUCTURE));
                ctx->index = tag_index;
                value->value = ctx->calloc_func(ctx->state, 1, sizeof(Name));
                CHECK_NEW_MEMORY(ctx, value->value, sizeof(Name), "Name structure");
                result = kmip_decode_name(ctx, (Name*)value->value);

                curr_index = ctx->index;
                ctx->index = tag_index;

                kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
                ctx->index = curr_index;
            }
            else
            {
                result = KMIP_TAG_MISMATCH;
            }

            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS:
        {
            /* TODO (ph) Like encoding, this is messy. Better solution? */
            if(kmip_is_tag_type_next(ctx, KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE))
            {
                /* NOTE (ph) Decoding structures will fail if the structure tag */
                /* is not present in the encoding. Temporarily swap the tags, */
                /* decode the structure, and then swap the tags back to */
                /* preserve the encoding. The tag/type check above guarantees */
                /* space exists for this to succeed. */
                kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS, KMIP_TYPE_STRUCTURE));
                ctx->index = tag_index;
                value->value = ctx->calloc_func(ctx->state, 1, sizeof(CryptographicParameters));
                CHECK_NEW_MEMORY(ctx, value->value, sizeof(CryptographicParameters), "CryptographicParameters structure");
                kmip_init_cryptographic_parameters((CryptographicParameters*)value->value);
                result = kmip_decode_cryptographic_parameters(ctx, (CryptographicParameters*)value->value);

                curr_index = ctx->index;
                ctx->index = tag_index;

                kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_ATTRIBUTE_VALUE, KMIP_TYPE_STRUCTURE));
                ctx->index = curr_index;
            }
            else
            {
                result = KMIP_TAG_MISMATCH;
            }

            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_ATTR_OBJECT_TYPE:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "ObjectType enumeration");
        result = kmip_decode_enum(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "CryptographicAlgorithm enumeration");
        result = kmip_decode_enum(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, *(int32 *)value->value);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "CryptographicLength integer");
        result = kmip_decode_integer(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_OPERATION_POLICY_NAME:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(TextString), "OperationPolicyName text string");
        result = kmip_decode_text_string(ctx, t, (TextString*)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "CryptographicUsageMask integer");
        result = kmip_decode_integer(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_ATTR_STATE:
        value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "State enumeration");
        result = kmip_decode_enum(ctx, t, (int32 *)value->value);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_STATE, *(int32 *)value->value);
        break;

        case KMIP_ATTR_OBJECT_GROUP:
        {
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(TextString), "ObjectGroup text string");
            result = kmip_decode_text_string(ctx, t, (TextString*)value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_ATTR_ACTIVATION_DATE:
        {
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "ActivationDate date time");

            result = kmip_decode_date_time(ctx, t, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_ATTR_DEACTIVATION_DATE:
        {
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "DeactivationDate date time");

            result = kmip_decode_date_time(ctx, t, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_ATTR_PROCESS_START_DATE:
        {
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "ProcessStartDate date time");

            result = kmip_decode_date_time(ctx, t, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_ATTR_PROTECT_STOP_DATE:
        {
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "ProtectStopDate date time");

            result = kmip_decode_date_time(ctx, t, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_ERROR_ATTR_UNSUPPORTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_attribute_v2(KMIP *ctx, Attribute *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_KMIP_VERSION(ctx, KMIP_2_0);

    kmip_init_attribute(value);

    int result = 0;
    uint32 tag = kmip_peek_tag(ctx);
    if(tag == 0)
    {
        /* Record an error for an underfull buffer here and return. */
    }

    CHECK_RESULT(ctx, result);

    switch(tag)
    {
        case KMIP_TAG_UNIQUE_IDENTIFIER:
        {
            value->type = KMIP_ATTR_UNIQUE_IDENTIFIER;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(TextString), "UniqueIdentifier text string");

            result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, (TextString *)value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_TAG_NAME:
        {
            value->type = KMIP_ATTR_NAME;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(Name));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(Name), "Name structure");

            result = kmip_decode_name(ctx, (Name *)value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_TAG_OBJECT_TYPE:
        {
            value->type = KMIP_ATTR_OBJECT_TYPE;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "ObjectType enumeration");

            result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, (int32 *)value->value);
            CHECK_RESULT(ctx, result);

            CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, *(int32 *)value->value);
        }
        break;

        case KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM:
        {
            value->type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "CrypographicAlgorithm enumeration");

            result = kmip_decode_enum(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, (int32 *)value->value);
            CHECK_RESULT(ctx, result);

            CHECK_ENUM(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, *(int32 *)value->value);
        }
        break;

        case KMIP_TAG_CRYPTOGRAPHIC_LENGTH:
        {
            value->type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "CryptographicLength integer");

            result = kmip_decode_integer(ctx, KMIP_TAG_CRYPTOGRAPHIC_LENGTH, (int32 *)value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK:
        {
            value->type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "CryptographicUsageMask integer");

            result = kmip_decode_integer(ctx, KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK, (int32 *)value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_TAG_STATE:
        {
            value->type = KMIP_ATTR_STATE;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int32));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int32), "State enumeration");

            result = kmip_decode_enum(ctx, KMIP_TAG_STATE, (int32 *)value->value);
            CHECK_RESULT(ctx, result);

            CHECK_ENUM(ctx, KMIP_TAG_STATE, *(int32 *)value->value);
        }
        break;

        case KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION:
        {
            value->type = KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(ApplicationSpecificInformation));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(ApplicationSpecificInformation), "ApplicationSpecificInformation structure");

            result = kmip_decode_application_specific_information(ctx, value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_TAG_OBJECT_GROUP:
        {
            value->type = KMIP_ATTR_OBJECT_GROUP;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(TextString), "ObjectGroup text string");

            result = kmip_decode_text_string(ctx, KMIP_TAG_OBJECT_GROUP, (TextString*)value->value);
            CHECK_RESULT(ctx, result);
        }
        break;

        case KMIP_TAG_ACTIVATION_DATE:
        {
            value->type = KMIP_ATTR_ACTIVATION_DATE;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "ActivationDate date time");

            result = kmip_decode_date_time(ctx, KMIP_TAG_ACTIVATION_DATE, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_TAG_DEACTIVATION_DATE:
        {
            value->type = KMIP_ATTR_DEACTIVATION_DATE;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "DeactivationDate date time");

            result = kmip_decode_date_time(ctx, KMIP_TAG_DEACTIVATION_DATE, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_TAG_PROCESS_START_DATE:
        {
            value->type = KMIP_ATTR_PROCESS_START_DATE;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "ProcessStartDate date time");

            result = kmip_decode_date_time(ctx, tag, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_TAG_PROTECT_STOP_DATE:
        {
            value->type = KMIP_ATTR_PROTECT_STOP_DATE;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(int64));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(int64), "ProtectStopDate date time");

            result = kmip_decode_date_time(ctx, tag, (int64*)value->value);
            CHECK_RESULT(ctx, result);
        } break;

        case KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS:
        {
            value->type = KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS;
            value->value = ctx->calloc_func(ctx->state, 1, sizeof(CryptographicParameters));
            CHECK_NEW_MEMORY(ctx, value->value, sizeof(CryptographicParameters), "CryptographicParameters structure");

            result = kmip_decode_cryptographic_parameters(ctx, value->value);
            CHECK_RESULT(ctx, result);
        } break;

        default:
        {
            kmip_push_error_frame(ctx, __func__, __LINE__);
            return(KMIP_ERROR_ATTR_UNSUPPORTED);
        }
        break;
    };

    return(KMIP_OK);
}

int
kmip_decode_attribute(KMIP *ctx, Attribute *value)
{
    CHECK_DECODE_ARGS(ctx, value);

    if(ctx->version < KMIP_2_0)
    {
        return(kmip_decode_attribute_v1(ctx, value));
    }
    else
    {
        return(kmip_decode_attribute_v2(ctx, value));
    }
}

int
kmip_decode_attributes(KMIP *ctx, Attributes *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_KMIP_VERSION(ctx, KMIP_2_0);
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    result = kmip_decode_int32_be(ctx, &tag_type);
    CHECK_RESULT(ctx, result);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_ATTRIBUTES, KMIP_TYPE_STRUCTURE);

    result = kmip_decode_length(ctx, &length);
    CHECK_RESULT(ctx, result);
    CHECK_BUFFER_FULL(ctx, length);

    value->attribute_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->attribute_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag != 0 && kmip_is_attribute_tag(tag))
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->attribute_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(Attribute));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(Attribute), "Attribute");

        result = kmip_decode_attribute(ctx, (Attribute *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

int
kmip_decode_template_attribute(KMIP *ctx, TemplateAttribute *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_TEMPLATE_ATTRIBUTE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->name_count = kmip_get_num_items_next(ctx, KMIP_TAG_NAME);
    if(value->name_count > 0)
    {
        value->names = ctx->calloc_func(ctx->state, value->name_count, sizeof(Name));
        CHECK_NEW_MEMORY(ctx, value->names, value->name_count * sizeof(Name), "sequence of Name structures");
        
        for(size_t i = 0; i < value->name_count; i++)
        {
            result = kmip_decode_name(ctx, &value->names[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    value->attribute_count = kmip_get_num_items_next(ctx, KMIP_TAG_ATTRIBUTE);
    if(value->attribute_count > 0)
    {
        value->attributes = ctx->calloc_func(ctx->state, value->attribute_count, sizeof(Attribute));
        CHECK_NEW_MEMORY(ctx, value->attributes, value->attribute_count * sizeof(Attribute), "sequence of Attribute structures");
        
        for(size_t i = 0; i < value->attribute_count; i++)
        {
            result = kmip_decode_attribute(ctx, &value->attributes[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_protocol_version(KMIP *ctx, ProtocolVersion *value)
{
    CHECK_BUFFER_FULL(ctx, 40);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_PROTOCOL_VERSION, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_LENGTH(ctx, length, 32);
    
    result = kmip_decode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MAJOR, &value->major);
    CHECK_RESULT(ctx, result);
    
    result = kmip_decode_integer(ctx, KMIP_TAG_PROTOCOL_VERSION_MINOR, &value->minor);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_transparent_symmetric_key(KMIP *ctx, TransparentSymmetricKey *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_KEY_MATERIAL, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
    CHECK_NEW_MEMORY(ctx, value->key, sizeof(ByteString), "Key byte string");
    
    result = kmip_decode_byte_string(ctx, KMIP_TAG_KEY, value->key);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_key_material(KMIP *ctx, enum key_format_type format, void **value)
{
    int result = 0;
    
    switch(format)
    {
        case KMIP_KEYFORMAT_RAW:
        case KMIP_KEYFORMAT_OPAQUE:
        case KMIP_KEYFORMAT_PKCS1:
        case KMIP_KEYFORMAT_PKCS8:
        case KMIP_KEYFORMAT_X509:
        case KMIP_KEYFORMAT_EC_PRIVATE_KEY:
        *value = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, *value, sizeof(ByteString), "KeyMaterial byte string");
        result = kmip_decode_byte_string(ctx, KMIP_TAG_KEY_MATERIAL, (ByteString*)*value);
        CHECK_RESULT(ctx, result);
        return(KMIP_OK);
        break;
        
        default:
        break;
    };
    
    switch(format)
    {
        case KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY:
        *value = ctx->calloc_func(ctx->state, 1, sizeof(TransparentSymmetricKey));
        CHECK_NEW_MEMORY(ctx, *value, sizeof(TransparentSymmetricKey), "TransparentSymmetricKey structure");
        result = kmip_decode_transparent_symmetric_key(ctx, (TransparentSymmetricKey*)*value);
        CHECK_RESULT(ctx, result);
        break;
        
        /* TODO (ph) The rest require BigInteger support. */
        
        case KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY:
        case KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY:
        case KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY:
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    return(KMIP_OK);
}

int
kmip_decode_key_value(KMIP *ctx, enum key_format_type format, KeyValue *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_KEY_VALUE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_key_material(ctx, format, &value->key_material);
    CHECK_RESULT(ctx, result);
    
    value->attribute_count = kmip_get_num_items_next(ctx, KMIP_TAG_ATTRIBUTE);
    if(value->attribute_count > 0)
    {
        value->attributes = ctx->calloc_func(ctx->state, value->attribute_count, sizeof(Attribute));
        CHECK_NEW_MEMORY(ctx, value->attributes, value->attribute_count * sizeof(Attribute), "sequence of Attribute structures");
        
        for(size_t i = 0; i < value->attribute_count; i++)
        {
            result = kmip_decode_attribute(ctx, &value->attributes[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_application_specific_information(KMIP *ctx, ApplicationSpecificInformation *value)
{
    CHECK_BUFFER_FULL(ctx, 8);

    kmip_init_application_specific_information(value);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION, KMIP_TYPE_STRUCTURE);

    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_APPLICATION_NAMESPACE))
    {
        value->application_namespace = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->application_namespace, sizeof(TextString), "Application Namespace text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_APPLICATION_NAMESPACE, value->application_namespace);
        CHECK_RESULT(ctx, result);
    }
    else
    {
        kmip_set_error_message(ctx, "The ApplicationSpecificInformation encoding is missing the application name field.");
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_INVALID_ENCODING);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_APPLICATION_DATA))
    {
        value->application_data = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->application_data, sizeof(TextString), "Application Data text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_APPLICATION_DATA, value->application_data);
        CHECK_RESULT(ctx, result);
    }
    else
    {
        if(ctx->version < KMIP_1_3)
        {
            kmip_set_error_message(ctx, "The ApplicationSpecificInformation encoding is missing the application data field.");
            kmip_push_error_frame(ctx, __func__, __LINE__);
            return(KMIP_INVALID_ENCODING);
        }
    }

    return(KMIP_OK);
}

int
kmip_decode_cryptographic_parameters(KMIP *ctx, CryptographicParameters *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    kmip_init_cryptographic_parameters(value);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_BLOCK_CIPHER_MODE))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_BLOCK_CIPHER_MODE, &value->block_cipher_mode);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_BLOCK_CIPHER_MODE, value->block_cipher_mode);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_PADDING_METHOD))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_PADDING_METHOD, &value->padding_method);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_PADDING_METHOD, value->padding_method);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_HASHING_ALGORITHM))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_HASHING_ALGORITHM, &value->hashing_algorithm);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_HASHING_ALGORITHM, value->hashing_algorithm);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_ROLE_TYPE))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_KEY_ROLE_TYPE, &value->key_role_type);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_KEY_ROLE_TYPE, value->key_role_type);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM))
        {
            result = kmip_decode_enum(ctx, KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM, &value->digital_signature_algorithm);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM, value->digital_signature_algorithm);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM))
        {
            result = kmip_decode_enum(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, &value->cryptographic_algorithm);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, value->cryptographic_algorithm);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_RANDOM_IV))
        {
            result = kmip_decode_bool(ctx, KMIP_TAG_RANDOM_IV, &value->random_iv);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_IV_LENGTH))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_IV_LENGTH, &value->iv_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_TAG_LENGTH))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_TAG_LENGTH, &value->tag_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_FIXED_FIELD_LENGTH))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_FIXED_FIELD_LENGTH, &value->fixed_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_INVOCATION_FIELD_LENGTH))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_INVOCATION_FIELD_LENGTH, &value->invocation_field_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_COUNTER_LENGTH))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_COUNTER_LENGTH, &value->counter_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_INITIAL_COUNTER_VALUE))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_INITIAL_COUNTER_VALUE, &value->initial_counter_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_SALT_LENGTH))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_SALT_LENGTH, &value->salt_length);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_MASK_GENERATOR))
        {
            result = kmip_decode_enum(ctx, KMIP_TAG_MASK_GENERATOR, &value->mask_generator);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_MASK_GENERATOR, value->mask_generator);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM))
        {
            result = kmip_decode_enum(ctx, KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM, &value->mask_generator_hashing_algorithm);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_HASHING_ALGORITHM, value->mask_generator_hashing_algorithm);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_P_SOURCE))
        {
            value->p_source = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
            CHECK_NEW_MEMORY(ctx, value->p_source, sizeof(ByteString), "P Source byte string");
            
            result = kmip_decode_byte_string(ctx, KMIP_TAG_P_SOURCE, value->p_source);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_TRAILER_FIELD))
        {
            result = kmip_decode_integer(ctx, KMIP_TAG_TRAILER_FIELD, &value->trailer_field);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_encryption_key_information(KMIP *ctx, EncryptionKeyInformation *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_ENCRYPTION_KEY_INFORMATION, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS))
    {
        value->cryptographic_parameters = ctx->calloc_func(ctx->state, 1, sizeof(CryptographicParameters));
        CHECK_NEW_MEMORY(ctx, value->cryptographic_parameters, sizeof(CryptographicParameters), "CryptographicParameters structure");
        
        result = kmip_decode_cryptographic_parameters(ctx, value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_mac_signature_key_information(KMIP *ctx, MACSignatureKeyInformation *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS))
    {
        value->cryptographic_parameters = ctx->calloc_func(ctx->state, 1, sizeof(CryptographicParameters));
        CHECK_NEW_MEMORY(ctx, value->cryptographic_parameters, sizeof(CryptographicParameters), "CryptographicParameters structure");
        
        result = kmip_decode_cryptographic_parameters(ctx, value->cryptographic_parameters);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}


int
kmip_decode_key_wrapping_data(KMIP *ctx, KeyWrappingData *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_KEY_WRAPPING_DATA, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, &value->wrapping_method);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ENCRYPTION_KEY_INFORMATION))
    {
        value->encryption_key_info = ctx->calloc_func(ctx->state, 1, sizeof(EncryptionKeyInformation));
        CHECK_NEW_MEMORY(ctx, value->encryption_key_info, sizeof(EncryptionKeyInformation), "EncryptionKeyInformation structure");
        
        result = kmip_decode_encryption_key_information(ctx, value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION))
    {
        value->mac_signature_key_info = ctx->calloc_func(ctx->state, 1, sizeof(MACSignatureKeyInformation));
        CHECK_NEW_MEMORY(ctx, value->mac_signature_key_info, sizeof(MACSignatureKeyInformation), "MAC/SignatureKeyInformation structure");
        
        result = kmip_decode_mac_signature_key_information(ctx, value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_MAC_SIGNATURE))
    {
        value->mac_signature = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->mac_signature, sizeof(ByteString), "MAC/Signature byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_MAC_SIGNATURE, value->mac_signature);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_IV_COUNTER_NONCE))
    {
        value->iv_counter_nonce = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->iv_counter_nonce, sizeof(ByteString), "IV/Counter/Nonce byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_IV_COUNTER_NONCE, value->iv_counter_nonce);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_ENCODING_OPTION))
        {
            result = kmip_decode_enum(ctx, KMIP_TAG_ENCODING_OPTION, &value->encoding_option);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_ENCODING_OPTION, value->encoding_option);
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_key_block(KMIP *ctx, KeyBlock *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_KEY_BLOCK, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, &value->key_format_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_KEY_FORMAT_TYPE, value->key_format_type);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, &value->key_compression_type);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, value->key_compression_type);
    }
    
    if(kmip_is_tag_type_next(ctx, KMIP_TAG_KEY_VALUE, KMIP_TYPE_BYTE_STRING))
    {
        value->key_value_type = KMIP_TYPE_BYTE_STRING;
        value->key_value = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->key_value, sizeof(ByteString), "KeyValue byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_KEY_VALUE, (ByteString *)value->key_value);
    }
    else
    {
        value->key_value_type = KMIP_TYPE_STRUCTURE;
        value->key_value = ctx->calloc_func(ctx->state, 1, sizeof(KeyValue));
        CHECK_NEW_MEMORY(ctx, value->key_value, sizeof(KeyValue), "KeyValue structure");
        
        result = kmip_decode_key_value(ctx, value->key_format_type, (KeyValue *)value->key_value);
    }
    CHECK_RESULT(ctx, result);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, &value->cryptographic_algorithm);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM, value->cryptographic_algorithm);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_CRYPTOGRAPHIC_LENGTH))
    {
        result = kmip_decode_integer(ctx, KMIP_TAG_CRYPTOGRAPHIC_LENGTH, &value->cryptographic_length);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_WRAPPING_DATA))
    {
        value->key_wrapping_data = ctx->calloc_func(ctx->state, 1, sizeof(KeyWrappingData));
        CHECK_NEW_MEMORY(ctx, value->key_wrapping_data, sizeof(KeyWrappingData), "KeyWrappingData structure");
        
        result = kmip_decode_key_wrapping_data(ctx, value->key_wrapping_data);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_symmetric_key(KMIP *ctx, SymmetricKey *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_SYMMETRIC_KEY, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key_block = ctx->calloc_func(ctx->state, 1, sizeof(KeyBlock));
    CHECK_NEW_MEMORY(ctx, value->key_block, sizeof(KeyBlock), "KeyBlock structure");
    
    result = kmip_decode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_public_key(KMIP *ctx, PublicKey *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_PUBLIC_KEY, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key_block = ctx->calloc_func(ctx->state, 1, sizeof(KeyBlock));
    CHECK_NEW_MEMORY(ctx, value->key_block, sizeof(KeyBlock), "KeyBlock structure");
    
    result = kmip_decode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_private_key(KMIP *ctx, PrivateKey *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_PRIVATE_KEY, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->key_block = ctx->calloc_func(ctx->state, 1, sizeof(KeyBlock));
    CHECK_NEW_MEMORY(ctx, value->key_block, sizeof(KeyBlock), "KeyBlock structure");
    
    result = kmip_decode_key_block(ctx, value->key_block);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_key_wrapping_specification(KMIP *ctx, KeyWrappingSpecification *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_KEY_WRAPPING_SPECIFICATION, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_WRAPPING_METHOD, &value->wrapping_method);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_WRAPPING_METHOD, value->wrapping_method);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ENCRYPTION_KEY_INFORMATION))
    {
        value->encryption_key_info = ctx->calloc_func(ctx->state, 1, sizeof(EncryptionKeyInformation));
        CHECK_NEW_MEMORY(ctx, value->encryption_key_info, sizeof(EncryptionKeyInformation), "EncryptionKeyInformation structure");
        result = kmip_decode_encryption_key_information(ctx, value->encryption_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION))
    {
        value->mac_signature_key_info = ctx->calloc_func(ctx->state, 1, sizeof(MACSignatureKeyInformation));
        CHECK_NEW_MEMORY(ctx, value->mac_signature_key_info, sizeof(MACSignatureKeyInformation), "MACSignatureKeyInformation structure");
        result = kmip_decode_mac_signature_key_information(ctx, value->mac_signature_key_info);
        CHECK_RESULT(ctx, result);
    }
    
    value->attribute_name_count = kmip_get_num_items_next(ctx, KMIP_TAG_ATTRIBUTE_NAME);
    if(value->attribute_name_count > 0)
    {
        value->attribute_names = ctx->calloc_func(ctx->state, value->attribute_name_count, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->attribute_names, value->attribute_name_count * sizeof(TextString), "sequence of AttributeName text strings");
        
        for(size_t i = 0; i < value->attribute_name_count; i++)
        {
            result = kmip_decode_text_string(ctx, KMIP_TAG_ATTRIBUTE_NAME, &value->attribute_names[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(ctx->version >= KMIP_1_1)
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_ENCODING_OPTION, &value->encoding_option);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_ENCODING_OPTION, value->encoding_option);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_create_request_payload(KMIP *ctx, CreateRequestPayload *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, &value->object_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);

    if(ctx->version < KMIP_2_0)
    {
        value->template_attribute = ctx->calloc_func(ctx->state, 1, sizeof(TemplateAttribute));
        if(value->template_attribute == NULL)
        {
            HANDLE_FAILED_ALLOC(ctx, sizeof(TemplateAttribute), "TemplateAttribute");
        }
        result = kmip_decode_template_attribute(ctx, value->template_attribute);
        if(result != KMIP_OK)
        {
            kmip_free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx, value->template_attribute);
            value->template_attribute = NULL;
            HANDLE_FAILURE(ctx, result);
        }
    }
    else
    {
        value->attributes = ctx->calloc_func(ctx->state, 1, sizeof(Attributes));
        if(value->attributes == NULL)
        {
            HANDLE_FAILED_ALLOC(ctx, sizeof(Attributes), "Attributes");
        }
        result = kmip_decode_attributes(ctx, value->attributes);
        if(result != KMIP_OK)
        {
            kmip_free_attributes(ctx, value->attributes);
            ctx->free_func(ctx, value->attributes);
            value->attributes = NULL;

            HANDLE_FAILURE(ctx, result);
        }

        if(kmip_is_tag_next(ctx, KMIP_TAG_PROTECTION_STORAGE_MASKS))
        {
            value->protection_storage_masks = ctx->calloc_func(ctx->state, 1, sizeof(ProtectionStorageMasks));
            if(value->protection_storage_masks == NULL)
            {
                kmip_free_attributes(ctx, value->attributes);
                ctx->free_func(ctx, value->attributes);
                value->attributes = NULL;

                HANDLE_FAILED_ALLOC(ctx, sizeof(ProtectionStorageMasks), "ProtectionStorageMasks");
            }
            result = kmip_decode_protection_storage_masks(ctx, value->protection_storage_masks);
            if(result != KMIP_OK)
            {
                kmip_free_attributes(ctx, value->attributes);
                kmip_free_protection_storage_masks(ctx, value->protection_storage_masks);
                ctx->free_func(ctx, value->attributes);
                ctx->free_func(ctx, value->protection_storage_masks);
                value->attributes = NULL;
                value->protection_storage_masks = NULL;

                HANDLE_FAILURE(ctx, result);
            }
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_create_response_payload(KMIP *ctx, CreateResponsePayload *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, &value->object_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(ctx->version < KMIP_2_0)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_TEMPLATE_ATTRIBUTE))
        {
            value->template_attribute = ctx->calloc_func(ctx->state, 1, sizeof(TemplateAttribute));
            CHECK_NEW_MEMORY(ctx, value->template_attribute, sizeof(TemplateAttribute), "TemplateAttribute structure");
            
            result = kmip_decode_template_attribute(ctx, value->template_attribute);
            CHECK_RESULT(ctx, result);
        }
    }

    return(KMIP_OK);
}

int
kmip_decode_register_request_payload(KMIP *ctx, RegisterRequestPayload *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, &value->object_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);

    if(ctx->version < KMIP_2_0)
    {
        value->template_attribute = ctx->calloc_func(ctx->state, 1, sizeof(TemplateAttribute));
        if(value->template_attribute == NULL)
        {
            HANDLE_FAILED_ALLOC(ctx, sizeof(TemplateAttribute), "TemplateAttribute");
        }
        result = kmip_decode_template_attribute(ctx, value->template_attribute);
        if(result != KMIP_OK)
        {
            kmip_free_template_attribute(ctx, value->template_attribute);
            ctx->free_func(ctx, value->template_attribute);
            value->template_attribute = NULL;
            HANDLE_FAILURE(ctx, result);
        }
    }
    else
    {
        value->attributes = ctx->calloc_func(ctx->state, 1, sizeof(Attributes));
        if(value->attributes == NULL)
        {
            HANDLE_FAILED_ALLOC(ctx, sizeof(Attributes), "Attributes");
        }
        result = kmip_decode_attributes(ctx, value->attributes);
        if(result != KMIP_OK)
        {
            kmip_free_attributes(ctx, value->attributes);
            ctx->free_func(ctx, value->attributes);
            value->attributes = NULL;

            HANDLE_FAILURE(ctx, result);
        }

        if(kmip_is_tag_next(ctx, KMIP_TAG_PROTECTION_STORAGE_MASKS))
        {
            value->protection_storage_masks = ctx->calloc_func(ctx->state, 1, sizeof(ProtectionStorageMasks));
            if(value->protection_storage_masks == NULL)
            {
                kmip_free_attributes(ctx, value->attributes);
                ctx->free_func(ctx, value->attributes);
                value->attributes = NULL;

                HANDLE_FAILED_ALLOC(ctx, sizeof(ProtectionStorageMasks), "ProtectionStorageMasks");
            }
            result = kmip_decode_protection_storage_masks(ctx, value->protection_storage_masks);
            if(result != KMIP_OK)
            {
                kmip_free_attributes(ctx, value->attributes);
                kmip_free_protection_storage_masks(ctx, value->protection_storage_masks);
                ctx->free_func(ctx, value->attributes);
                ctx->free_func(ctx, value->protection_storage_masks);
                value->attributes = NULL;
                value->protection_storage_masks = NULL;

                HANDLE_FAILURE(ctx, result);
            }
        }
    }

    result = kmip_decode_symmetric_key(ctx, &value->object);
    if (result != KMIP_OK) 
    {
        kmip_free_attributes(ctx, value->attributes);
        kmip_free_protection_storage_masks(ctx, value->protection_storage_masks);
        ctx->free_func(ctx, value->attributes);
        ctx->free_func(ctx, value->protection_storage_masks);
        value->attributes = NULL;
        value->protection_storage_masks = NULL;

        HANDLE_FAILURE(ctx, result);
    }
    //value->object = ctx->calloc_func(ctx->state, 1, sizeof(SymmetricKey));
    //CHECK_NEW_MEMORY(ctx, value->object, sizeof(SymmetricKey), "SymmetricKey structure");
    result = kmip_decode_symmetric_key(ctx, &value->object);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_register_response_payload(KMIP *ctx, RegisterResponsePayload *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    if(ctx->version < KMIP_2_0)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_TEMPLATE_ATTRIBUTE))
        {
            value->template_attribute = ctx->calloc_func(ctx->state, 1, sizeof(TemplateAttribute));
            CHECK_NEW_MEMORY(ctx, value->template_attribute, sizeof(TemplateAttribute), "TemplateAttribute structure");
            
            result = kmip_decode_template_attribute(ctx, value->template_attribute);
            CHECK_RESULT(ctx, result);
        }
    }

    return(KMIP_OK);
}

int
kmip_decode_get_request_payload(KMIP *ctx, GetRequestPayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_UNIQUE_IDENTIFIER))
    {
        value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
        result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_FORMAT_TYPE))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_KEY_FORMAT_TYPE, &value->key_format_type);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_KEY_FORMAT_TYPE, value->key_format_type);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_WRAP_TYPE))
        {
            result = kmip_decode_enum(ctx, KMIP_TAG_KEY_WRAP_TYPE, &value->key_wrap_type);
            CHECK_RESULT(ctx, result);
            CHECK_ENUM(ctx, KMIP_TAG_KEY_WRAP_TYPE, value->key_wrap_type);
        }
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, &value->key_compression_type);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_KEY_COMPRESSION_TYPE, value->key_compression_type);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_KEY_WRAPPING_SPECIFICATION))
    {
        value->key_wrapping_spec = ctx->calloc_func(ctx->state, 1, sizeof(KeyWrappingSpecification));
        CHECK_NEW_MEMORY(ctx, value->key_wrapping_spec, sizeof(KeyWrappingSpecification), "KeyWrappingSpecification structure");
        result = kmip_decode_key_wrapping_specification(ctx, value->key_wrapping_spec);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_get_response_payload(KMIP *ctx, GetResponsePayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, &value->object_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OBJECT_TYPE, value->object_type);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    switch(value->object_type)
    {
        case KMIP_OBJTYPE_SYMMETRIC_KEY:
        value->object = ctx->calloc_func(ctx->state, 1, sizeof(SymmetricKey));
        CHECK_NEW_MEMORY(ctx, value->object, sizeof(SymmetricKey), "SymmetricKey structure");
        result = kmip_decode_symmetric_key(ctx, (SymmetricKey*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PUBLIC_KEY:
        value->object = ctx->calloc_func(ctx->state, 1, sizeof(PublicKey));
        CHECK_NEW_MEMORY(ctx, value->object, sizeof(PublicKey), "PublicKey structure");
        result = kmip_decode_public_key(ctx, (PublicKey*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        case KMIP_OBJTYPE_PRIVATE_KEY:
        value->object = ctx->calloc_func(ctx->state, 1, sizeof(PrivateKey));
        CHECK_NEW_MEMORY(ctx, value->object, sizeof(PrivateKey), "PrivateKey structure");
        result = kmip_decode_private_key(ctx, (PrivateKey*)value->object);
        CHECK_RESULT(ctx, result);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    
    return(KMIP_OK);
}

int
kmip_decode_get_attribute_request_payload(KMIP *ctx, GetAttributeRequestPayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_UNIQUE_IDENTIFIER))
    {
        value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
        result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ATTRIBUTE_NAME))
    {
        value->attribute_name = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->attribute_name, sizeof(TextString), "AttributeName text string");
        result = kmip_decode_text_string(ctx, KMIP_TAG_ATTRIBUTE_NAME, value->attribute_name);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_get_attribute_response_payload(KMIP *ctx, GetAttributeResponsePayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);

    value->attribute = ctx->calloc_func(ctx->state, 1, sizeof(Attribute));
    CHECK_NEW_MEMORY(ctx, value->attribute, sizeof(Attribute), "Attribute");

    result = kmip_decode_attribute(ctx, value->attribute);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}
int
kmip_decode_destroy_request_payload(KMIP *ctx, DestroyRequestPayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_UNIQUE_IDENTIFIER))
    {
        value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
        result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_destroy_response_payload(KMIP *ctx, DestroyResponsePayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->unique_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier, sizeof(TextString), "UniqueIdentifier text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, value->unique_identifier);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_request_batch_item(KMIP *ctx, RequestBatchItem *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_OPERATION, &value->operation);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_OPERATION, value->operation);

    if(ctx->version >= KMIP_2_0)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_EPHEMERAL))
        {
            result = kmip_decode_bool(ctx, KMIP_TAG_EPHEMERAL, &value->ephemeral);
            CHECK_RESULT(ctx, result);
        }
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID))
    {
        value->unique_batch_item_id = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->unique_batch_item_id, sizeof(ByteString), "UniqueBatchItemID byte string");
        result = kmip_decode_byte_string(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID, value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    switch(value->operation)
    {
        case KMIP_OP_CREATE:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(CreateRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(CreateRequestPayload), "CreateRequestPayload structure");
        result = kmip_decode_create_request_payload(ctx, (CreateRequestPayload *)value->request_payload);
        break;

        case KMIP_OP_REGISTER:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(RegisterRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(RegisterRequestPayload), "RegisterRequestPayload structure");
        result = kmip_decode_register_request_payload(ctx, (RegisterRequestPayload *)value->request_payload);
        break;
        
        case KMIP_OP_GET:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(GetRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(GetRequestPayload), "GetRequestPayload structure");
        result = kmip_decode_get_request_payload(ctx, (GetRequestPayload*)value->request_payload);
        break;

        case KMIP_OP_GET_ATTRIBUTES:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(GetRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(GetAttributeRequestPayload), "GetAttributeRequestPayload structure");
        result = kmip_decode_get_attribute_request_payload(ctx, (GetAttributeRequestPayload*)value->request_payload);
        break;
        
        case KMIP_OP_DESTROY:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(DestroyRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(DestroyRequestPayload), "DestroyRequestPayload structure");
        result = kmip_decode_destroy_request_payload(ctx, (DestroyRequestPayload*)value->request_payload);
        break;
        
        case KMIP_OP_QUERY:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(QueryRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(QueryRequestPayload), "QueryRequestPayload structure");
        result = kmip_decode_query_request_payload(ctx, (QueryRequestPayload*)value->request_payload);
        break;

        case KMIP_OP_LOCATE:
        value->request_payload = ctx->calloc_func(ctx->state, 1, sizeof(LocateRequestPayload));
        CHECK_NEW_MEMORY(ctx, value->request_payload, sizeof(LocateRequestPayload), "LocateRequestPayload structure");
        result = kmip_decode_locate_request_payload(ctx, (LocateRequestPayload*)value->request_payload);
        break;

        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    };
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_response_batch_item(KMIP *ctx, ResponseBatchItem *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_BATCH_ITEM, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_OPERATION))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_OPERATION, &value->operation);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_OPERATION, value->operation);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID))
    {
        value->unique_batch_item_id = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->unique_batch_item_id, sizeof(ByteString), "UniqueBatchItemID byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_UNIQUE_BATCH_ITEM_ID, value->unique_batch_item_id);
        CHECK_RESULT(ctx, result);
    }
    
    result = kmip_decode_enum(ctx, KMIP_TAG_RESULT_STATUS, &value->result_status);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_RESULT_STATUS, value->result_status);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_RESULT_REASON))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_RESULT_REASON, &value->result_reason);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_RESULT_MESSAGE))
    {
        value->result_message = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->result_message, sizeof(TextString), "ResultMessage text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_RESULT_MESSAGE, value->result_message);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE))
    {
        value->asynchronous_correlation_value = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->asynchronous_correlation_value, sizeof(ByteString), "AsynchronousCorrelationValue byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE, value->asynchronous_correlation_value);
        CHECK_RESULT(ctx, result);
    }
    
    /* NOTE (ph) Omitting the tag check is a good way to test error output. */
    //if(kmip_is_tag_next(ctx, KMIP_TAG_RESPONSE_PAYLOAD))
    {
        switch(value->operation)
        {
            case KMIP_OP_CREATE:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(CreateResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(CreateResponsePayload), "CreateResponsePayload structure");
            result = kmip_decode_create_response_payload(ctx, value->response_payload);
            break;

            case KMIP_OP_REGISTER:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(RegisterResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(RegisterResponsePayload), "RegisterResponsePayload structure");
            result = kmip_decode_register_response_payload(ctx, value->response_payload);
            break;
            
            case KMIP_OP_GET:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(GetResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(GetResponsePayload), "GetResponsePayload structure");
            
            result = kmip_decode_get_response_payload(ctx, value->response_payload);
            break;

            case KMIP_OP_GET_ATTRIBUTES:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(GetAttributeResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(GetAttributeResponsePayload), "GetAttributeResponsePayload structure");
            
            result = kmip_decode_get_attribute_response_payload(ctx, value->response_payload);
            break;
            
            case KMIP_OP_DESTROY:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(DestroyResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(DestroyResponsePayload), "DestroyResponsePayload structure");
            result = kmip_decode_destroy_response_payload(ctx, value->response_payload);
            break;
            
            case KMIP_OP_QUERY:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(QueryResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(QueryResponsePayload), "QueryResponsePayload structure");
            result = kmip_decode_query_response_payload(ctx, value->response_payload);
            break;

            case KMIP_OP_LOCATE:
            value->response_payload = ctx->calloc_func(ctx->state, 1, sizeof(LocateResponsePayload));
            CHECK_NEW_MEMORY(ctx, value->response_payload, sizeof(LocateResponsePayload), "LocateResponsePayload structure");
            result = kmip_decode_locate_response_payload(ctx, value->response_payload);
            break;

            default:
            kmip_push_error_frame(ctx, __func__, __LINE__);
            return(KMIP_NOT_IMPLEMENTED);
            break;
        };
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_nonce(KMIP *ctx, Nonce *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_NONCE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->nonce_id = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
    CHECK_NEW_MEMORY(ctx, value->nonce_id, sizeof(ByteString), "NonceID byte string");
    
    result = kmip_decode_byte_string(ctx, KMIP_TAG_NONCE_ID, value->nonce_id);
    CHECK_RESULT(ctx, result);
    
    value->nonce_value = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
    CHECK_NEW_MEMORY(ctx, value->nonce_value, sizeof(ByteString), "NonceValue byte string");
    
    result = kmip_decode_byte_string(ctx, KMIP_TAG_NONCE_VALUE, value->nonce_value);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_username_password_credential(KMIP *ctx, UsernamePasswordCredential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->username = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
    CHECK_NEW_MEMORY(ctx, value->username, sizeof(TextString), "Username text string");
    
    result = kmip_decode_text_string(ctx, KMIP_TAG_USERNAME, value->username);
    CHECK_RESULT(ctx, result);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_PASSWORD))
    {
        value->password = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->password, sizeof(TextString), "Password text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_PASSWORD, value->password);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_device_credential(KMIP *ctx, DeviceCredential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_DEVICE_SERIAL_NUMBER))
    {
        value->device_serial_number = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->device_serial_number, sizeof(TextString), "DeviceSerialNumber text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_DEVICE_SERIAL_NUMBER, value->device_serial_number);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_PASSWORD))
    {
        value->password = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->password, sizeof(TextString), "Password text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_PASSWORD, value->password);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_DEVICE_IDENTIFIER))
    {
        value->device_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->device_identifier, sizeof(TextString), "DeviceIdentifier text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_DEVICE_IDENTIFIER, value->device_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_NETWORK_IDENTIFIER))
    {
        value->network_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->network_identifier, sizeof(TextString), "NetworkIdentifier text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_NETWORK_IDENTIFIER, value->network_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_MACHINE_IDENTIFIER))
    {
        value->machine_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->machine_identifier, sizeof(TextString), "MachineIdentifier text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_MACHINE_IDENTIFIER, value->machine_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_MEDIA_IDENTIFIER))
    {
        value->media_identifier = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->media_identifier, sizeof(TextString), "MediaIdentifier text string");
        
        result = kmip_decode_text_string(ctx, KMIP_TAG_MEDIA_IDENTIFIER, value->media_identifier);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_attestation_credential(KMIP *ctx, AttestationCredential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_CREDENTIAL_VALUE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->nonce = ctx->calloc_func(ctx->state, 1, sizeof(Nonce));
    CHECK_NEW_MEMORY(ctx, value->nonce, sizeof(Nonce), "Nonce structure");
    
    result = kmip_decode_nonce(ctx, value->nonce);
    CHECK_RESULT(ctx, result);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_ATTESTATION_TYPE, &value->attestation_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_type);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ATTESTATION_MEASUREMENT))
    {
        value->attestation_measurement = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->attestation_measurement, sizeof(ByteString), "AttestationMeasurement byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_ATTESTATION_MEASUREMENT, value->attestation_measurement);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ATTESTATION_ASSERTION))
    {
        value->attestation_assertion = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
        CHECK_NEW_MEMORY(ctx, value->attestation_assertion, sizeof(ByteString), "AttestationAssertion byte string");
        
        result = kmip_decode_byte_string(ctx, KMIP_TAG_ATTESTATION_ASSERTION, value->attestation_assertion);
        CHECK_RESULT(ctx, result);
    }
    
    return(KMIP_OK);
}

int
kmip_decode_credential_value(KMIP *ctx, enum credential_type type, void **value)
{
    int result = 0;
    
    switch(type)
    {
        case KMIP_CRED_USERNAME_AND_PASSWORD:
        *value = ctx->calloc_func(ctx->state, 1, sizeof(UsernamePasswordCredential));
        CHECK_NEW_MEMORY(ctx, *value, sizeof(UsernamePasswordCredential), "UsernamePasswordCredential structure");
        result = kmip_decode_username_password_credential(ctx, (UsernamePasswordCredential *)*value);
        break;
        
        case KMIP_CRED_DEVICE:
        *value = ctx->calloc_func(ctx->state, 1, sizeof(DeviceCredential));
        CHECK_NEW_MEMORY(ctx, *value, sizeof(DeviceCredential), "DeviceCredential structure");
        result = kmip_decode_device_credential(ctx, (DeviceCredential *)*value);
        break;
        
        case KMIP_CRED_ATTESTATION:
        *value = ctx->calloc_func(ctx->state, 1, sizeof(AttestationCredential));
        CHECK_NEW_MEMORY(ctx, *value, sizeof(AttestationCredential), "AttestationCredential structure");
        result = kmip_decode_attestation_credential(ctx, (AttestationCredential*)*value);
        break;
        
        default:
        kmip_push_error_frame(ctx, __func__, __LINE__);
        return(KMIP_NOT_IMPLEMENTED);
        break;
    }
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_credential(KMIP *ctx, Credential *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_CREDENTIAL, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    result = kmip_decode_enum(ctx, KMIP_TAG_CREDENTIAL_TYPE, &value->credential_type);
    CHECK_RESULT(ctx, result);
    CHECK_ENUM(ctx, KMIP_TAG_CREDENTIAL_TYPE, value->credential_type);
    
    result = kmip_decode_credential_value(ctx, value->credential_type, &value->credential_value);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_authentication(KMIP *ctx, Authentication *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_AUTHENTICATION, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->credential = ctx->calloc_func(ctx->state, 1, sizeof(Credential));
    CHECK_NEW_MEMORY(ctx, value->credential, sizeof(Credential), "Credential structure");
    
    result = kmip_decode_credential(ctx, value->credential);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_request_header(KMIP *ctx, RequestHeader *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_HEADER, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->protocol_version = ctx->calloc_func(ctx->state, 1, sizeof(ProtocolVersion));
    CHECK_NEW_MEMORY(ctx, value->protocol_version, sizeof(ProtocolVersion), "ProtocolVersion structure");
    
    result = kmip_decode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_MAXIMUM_RESPONSE_SIZE))
    {
        result = kmip_decode_integer(ctx, KMIP_TAG_MAXIMUM_RESPONSE_SIZE, &value->maximum_response_size);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE))
        {
            value->client_correlation_value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->client_correlation_value, sizeof(TextString), "ClientCorrelationValue text string");
            
            result = kmip_decode_text_string(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE, value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE))
        {
            value->server_correlation_value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->server_correlation_value, sizeof(TextString), "ServerCorrelationValue text string");
            
            result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE, value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_ASYNCHRONOUS_INDICATOR))
    {
        result = kmip_decode_bool(ctx, KMIP_TAG_ASYNCHRONOUS_INDICATOR, &value->asynchronous_indicator);
        CHECK_RESULT(ctx, result);
    }
    
    if(ctx->version >= KMIP_1_2)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR))
        {
            result = kmip_decode_bool(ctx, KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR, &value->attestation_capable_indicator);
            CHECK_RESULT(ctx, result);
        }
        
        value->attestation_type_count = kmip_get_num_items_next(ctx, KMIP_TAG_ATTESTATION_TYPE);
        if(value->attestation_type_count > 0)
        {
            value->attestation_types = ctx->calloc_func(ctx->state, value->attestation_type_count, sizeof(enum attestation_type));
            CHECK_NEW_MEMORY(ctx, value->attestation_types, value->attestation_type_count * sizeof(enum attestation_type), "sequence of AttestationType enumerations");
            
            for(size_t i = 0; i < value->attestation_type_count; i++)
            {
                result = kmip_decode_enum(ctx, KMIP_TAG_ATTESTATION_TYPE, &value->attestation_types[i]);
                CHECK_RESULT(ctx, result);
                CHECK_ENUM(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_types[i]);
            }
        }
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_AUTHENTICATION))
    {
        value->authentication = ctx->calloc_func(ctx->state,1, sizeof(Authentication));
        CHECK_NEW_MEMORY(ctx, value->authentication, sizeof(Authentication), "Authentication structure");
        
        result = kmip_decode_authentication(ctx, value->authentication);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION))
    {
        result = kmip_decode_enum(ctx, KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION, &value->batch_error_continuation_option);
        CHECK_RESULT(ctx, result);
        CHECK_ENUM(ctx, KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION, value->batch_error_continuation_option);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_BATCH_ORDER_OPTION))
    {
        result = kmip_decode_bool(ctx, KMIP_TAG_BATCH_ORDER_OPTION, &value->batch_order_option);
        CHECK_RESULT(ctx, result);
    }
    
    if(kmip_is_tag_next(ctx, KMIP_TAG_TIME_STAMP))
    {
        result = kmip_decode_date_time(ctx, KMIP_TAG_TIME_STAMP, &value->time_stamp);
        CHECK_RESULT(ctx, result);
    }
    
    result = kmip_decode_integer(ctx, KMIP_TAG_BATCH_COUNT, &value->batch_count);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_response_header(KMIP *ctx, ResponseHeader *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_HEADER, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->protocol_version = ctx->calloc_func(ctx->state, 1, sizeof(ProtocolVersion));
    CHECK_NEW_MEMORY(ctx, value->protocol_version, sizeof(ProtocolVersion), "ProtocolVersion structure");
    
    result = kmip_decode_protocol_version(ctx, value->protocol_version);
    CHECK_RESULT(ctx, result);
    
    result = kmip_decode_date_time(ctx, KMIP_TAG_TIME_STAMP, &value->time_stamp);
    CHECK_RESULT(ctx, result);
    
    if(ctx->version >= KMIP_1_2)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_NONCE))
        {
            value->nonce = ctx->calloc_func(ctx->state, 1, sizeof(Nonce));
            CHECK_NEW_MEMORY(ctx, value->nonce, sizeof(Nonce), "Nonce structure");
            
            result = kmip_decode_nonce(ctx, value->nonce);
            CHECK_RESULT(ctx, result);
        }

        if(ctx->version >= KMIP_2_0)
        {
            if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_HASHED_PASSWORD))
            {
                value->server_hashed_password = ctx->calloc_func(ctx->state, 1, sizeof(ByteString));
                CHECK_NEW_MEMORY(ctx, value->server_hashed_password, sizeof(ByteString), "ByteString");

                result = kmip_decode_byte_string(ctx, KMIP_TAG_SERVER_HASHED_PASSWORD, value->server_hashed_password);
                CHECK_RESULT(ctx, result);
            }
        }

        value->attestation_type_count = kmip_get_num_items_next(ctx, KMIP_TAG_ATTESTATION_TYPE);
        if(value->attestation_type_count > 0)
        {
            value->attestation_types = ctx->calloc_func(ctx->state, value->attestation_type_count, sizeof(enum attestation_type));
            CHECK_NEW_MEMORY(ctx, value->attestation_types, value->attestation_type_count * sizeof(enum attestation_type), "sequence of AttestationType enumerations");
            
            for(size_t i = 0; i < value->attestation_type_count; i++)
            {
                result = kmip_decode_enum(ctx, KMIP_TAG_ATTESTATION_TYPE, &value->attestation_types[i]);
                CHECK_RESULT(ctx, result);
                CHECK_ENUM(ctx, KMIP_TAG_ATTESTATION_TYPE, value->attestation_types[i]);
            }
        }
    }
    
    if(ctx->version >= KMIP_1_4)
    {
        if(kmip_is_tag_next(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE))
        {
            value->client_correlation_value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->client_correlation_value, sizeof(TextString), "ClientCorrelationValue text string");
            
            result = kmip_decode_text_string(ctx, KMIP_TAG_CLIENT_CORRELATION_VALUE, value->client_correlation_value);
            CHECK_RESULT(ctx, result);
        }
        
        if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE))
        {
            value->server_correlation_value = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
            CHECK_NEW_MEMORY(ctx, value->server_correlation_value, sizeof(TextString), "ServerCorrelationValue text string");
            
            result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_CORRELATION_VALUE, value->server_correlation_value);
            CHECK_RESULT(ctx, result);
        }
    }
    
    result = kmip_decode_integer(ctx, KMIP_TAG_BATCH_COUNT, &value->batch_count);
    CHECK_RESULT(ctx, result);
    
    return(KMIP_OK);
}

int
kmip_decode_request_message(KMIP *ctx, RequestMessage *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_REQUEST_MESSAGE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->request_header = ctx->calloc_func(ctx->state, 1, sizeof(RequestHeader));
    CHECK_NEW_MEMORY(ctx, value->request_header, sizeof(RequestHeader), "RequestHeader structure");
    kmip_init_request_header(value->request_header);
    result = kmip_decode_request_header(ctx, value->request_header);
    CHECK_RESULT(ctx, result);
    
    value->batch_count = kmip_get_num_items_next(ctx, KMIP_TAG_BATCH_ITEM);
    if(value->batch_count > 0)
    {
        value->batch_items = ctx->calloc_func(ctx->state, value->batch_count, sizeof(RequestBatchItem));
        CHECK_NEW_MEMORY(ctx, value->batch_items, value->batch_count * sizeof(RequestBatchItem), "sequence of RequestBatchItem structures");
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            kmip_init_request_batch_item(&value->batch_items[i]);
            result = kmip_decode_request_batch_item(ctx, &value->batch_items[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_response_message(KMIP *ctx, ResponseMessage *value)
{
    CHECK_BUFFER_FULL(ctx, 8);
    
    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;
    
    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_MESSAGE, KMIP_TYPE_STRUCTURE);
    
    kmip_decode_length(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);
    
    value->response_header = ctx->calloc_func(ctx->state, 1, sizeof(ResponseHeader));
    CHECK_NEW_MEMORY(ctx, value->response_header, sizeof(ResponseHeader), "ResponseHeader structure");
    
    result = kmip_decode_response_header(ctx, value->response_header);
    CHECK_RESULT(ctx, result);
    
    value->batch_count = kmip_get_num_items_next(ctx, KMIP_TAG_BATCH_ITEM);
    if(value->batch_count > 0)
    {
        value->batch_items = ctx->calloc_func(ctx->state, value->batch_count, sizeof(ResponseBatchItem));
        CHECK_NEW_MEMORY(ctx, value->batch_items, value->batch_count * sizeof(ResponseBatchItem), "sequence of ResponseBatchItem structures");
        
        for(size_t i = 0; i < value->batch_count; i++)
        {
            result = kmip_decode_response_batch_item(ctx, &value->batch_items[i]);
            CHECK_RESULT(ctx, result);
        }
    }
    
    return(KMIP_OK);
}

int
kmip_decode_query_functions(KMIP *ctx, Functions* value)
{
    int result = 0;
    uint32 tag = kmip_peek_tag(ctx);

    value->function_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->function_list, sizeof(LinkedList), "LinkedList");

    while(tag == KMIP_TAG_QUERY_FUNCTION)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->function_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Query Function");

        result = kmip_decode_enum(ctx, KMIP_TAG_QUERY_FUNCTION, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

int
kmip_decode_query_request_payload(KMIP *ctx, QueryRequestPayload *value)
{
    CHECK_DECODE_ARGS(ctx, value);
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    result = kmip_decode_int32_be(ctx, &tag_type);
    CHECK_RESULT(ctx, result);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_QUERY_FUNCTION, KMIP_TYPE_STRUCTURE);

    result = kmip_decode_int32_be(ctx, &length);
    CHECK_RESULT(ctx, result);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_QUERY_FUNCTION))
    {
        value->functions = ctx->calloc_func(ctx->state, 1, sizeof(Functions));
        CHECK_NEW_MEMORY(ctx, value->functions, sizeof(Functions), "Functions");

        result = kmip_decode_query_functions(ctx, value->functions);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}


int
kmip_decode_operations(KMIP *ctx, Operations *value)
{
    int result = 0;

    value->operation_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->operation_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_OPERATION)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->operation_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Operation");


        result = kmip_decode_enum(ctx, KMIP_TAG_OPERATION, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

int
kmip_decode_object_types(KMIP *ctx, ObjectTypes *value)
{
    int result = 0;

    value->object_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->object_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_OBJECT_TYPE)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->object_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(int32));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(int32), "Object");

        result = kmip_decode_enum(ctx, KMIP_TAG_OBJECT_TYPE, (int32 *)item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

int
kmip_decode_alternative_endpoints(KMIP *ctx, AltEndpoints* value)
{
    int result = 0;

    value->endpoint_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->endpoint_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->endpoint_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(TextString), "Endpoint text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS, item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}

int
kmip_decode_server_information(KMIP *ctx, ServerInformation *value)
{
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_SERVER_INFORMATION, KMIP_TYPE_STRUCTURE);

    kmip_decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_NAME))
    {
        value->server_name = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_name, sizeof(TextString), "ServerName text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_NAME, value->server_name);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_SERIAL_NUMBER))
    {
        value->server_serial_number = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_serial_number, sizeof(TextString), "ServerSerialNumber text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_SERIAL_NUMBER, value->server_serial_number);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_VERSION))
    {
        value->server_version = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_version, sizeof(TextString), "ServerVersion text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_VERSION, value->server_version);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_LOAD))
    {
        value->server_load = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->server_load, sizeof(TextString), "ServerLoad text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_SERVER_LOAD, value->server_load);
        CHECK_RESULT(ctx, result);
    }


    if(kmip_is_tag_next(ctx, KMIP_TAG_PRODUCT_NAME))
    {
        value->product_name = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->product_name, sizeof(TextString), "ProductName text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_PRODUCT_NAME, value->product_name);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_BUILD_LEVEL))
    {
        value->build_level = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->build_level, sizeof(TextString), "BuildLevel text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_BUILD_LEVEL, value->build_level);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_BUILD_DATE))
    {
        value->build_date = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->build_date, sizeof(TextString), "BuildDate text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_BUILD_DATE, value->build_date);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_CLUSTER_INFO))
    {
        value->cluster_info = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->cluster_info, sizeof(TextString), "ClusterInfo text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_CLUSTER_INFO, value->cluster_info);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS))
    {
        value->alternative_failover_endpoints= ctx->calloc_func(ctx->state, 1, sizeof(AltEndpoints));
        CHECK_NEW_MEMORY(ctx, value->alternative_failover_endpoints, sizeof(AltEndpoints), "Alt Endpoints");
        result = kmip_decode_alternative_endpoints(ctx, value->alternative_failover_endpoints);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}

int
kmip_decode_query_response_payload(KMIP *ctx, QueryResponsePayload *value)
{
    int result = 0;

    int32 tag_type = 0;
    uint32 length = 0;

    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);

    kmip_decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_OPERATION))
    {
        value->operations = ctx->calloc_func(ctx->state, 1, sizeof(Operations));
        CHECK_NEW_MEMORY(ctx, value->operations, sizeof(Operations), "Operations");
        result = kmip_decode_operations(ctx, value->operations);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_OBJECT_TYPE))
    {
        value->objects = ctx->calloc_func(ctx->state, 1, sizeof(ObjectTypes));
        CHECK_NEW_MEMORY(ctx, value->objects, sizeof(ObjectTypes), "Object_Types");
        result = kmip_decode_object_types(ctx, value->objects);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_VENDOR_IDENTIFICATION))
    {
        value->vendor_identification = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, value->vendor_identification, sizeof(TextString), "Vendor Identifier text string");
        result = kmip_decode_text_string(ctx, KMIP_TAG_VENDOR_IDENTIFICATION, (TextString*)value->vendor_identification);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_SERVER_INFORMATION))
    {
        value->server_information = ctx->calloc_func(ctx->state, 1, sizeof(ServerInformation));
        CHECK_NEW_MEMORY(ctx, value->server_information, sizeof(ServerInformation), "Server Information");
        result = kmip_decode_server_information(ctx, value->server_information);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}

