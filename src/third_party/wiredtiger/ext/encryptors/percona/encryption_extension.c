/*======
This file is part of Percona Server for MongoDB.

Copyright (C) 2018-present Percona and/or its affiliates. All rights reserved.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the Server Side Public License, version 1,
    as published by MongoDB, Inc.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    Server Side Public License for more details.

    You should have received a copy of the Server Side Public License
    along with this program. If not, see
    <http://www.mongodb.com/licensing/server-side-public-license>.

    As a special exception, the copyright holders give permission to link the
    code of portions of this program with the OpenSSL library under certain
    conditions as described in each individual source file and distribute
    linked combinations including the program with the OpenSSL library. You
    must comply with the Server Side Public License in all respects for
    all of the code used other than as permitted herein. If you modify file(s)
    with this exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do so,
    delete this exception statement from your version. If you delete this
    exception statement from all source files in the program, then also delete
    it in the license file.
======= */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
//#include <assert>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <wiredtiger.h>
#include <wiredtiger_ext.h>

#include "encryption_keydb_c_api.h"

#define KEY_LEN 32
#define GCM_TAG_LEN 16
#define CHKSUM_LEN sizeof(uint32_t)

typedef struct {
    // WT_ENCRYPTOR must be the first field
    WT_ENCRYPTOR encryptor;
    WT_EXTENSION_API *wt_api;
    const EVP_CIPHER *cipher;
    int iv_len;
    unsigned char key[KEY_LEN];
    uint32_t (*wiredtiger_checksum_crc32c)(const void *, size_t);
} PERCONA_ENCRYPTOR;


static const bool printDebugMessages = false;
#define DBG if (printDebugMessages)
#define DBG_MSG(...) DBG pe->wt_api->msg_printf(pe->wt_api, session, __VA_ARGS__)

// define DBG_ENC_EXT to enable verbose debugging info (size of data before and after encryption, used key)
#ifdef DBG_ENC_EXT
typedef struct {
    size_t src_len;
    size_t dst_len;
    size_t result_len;
    unsigned char key[KEY_LEN];
} DEBUG_DATA;
#endif

static int report_error(
    PERCONA_ENCRYPTOR *pe, WT_SESSION *session, int err, const char *msg)
{
    WT_EXTENSION_API *wt_api;

    wt_api = pe->wt_api;
    (void)wt_api->err_printf(wt_api, session,
                             "encryption: %s: %s", msg, wt_api->strerror(wt_api, NULL, err));
    return err;
}

typedef struct {
    WT_EXTENSION_API *wt_api;
    WT_SESSION *session;
    int *pret;
} ERR_PARAM;

static void print_errors_cb(int (*cb) (const char *str, size_t len, void *u, unsigned long ecode),
                         void *u)
{
    unsigned long l;
    char buf[256];
    char buf2[4096];
    const char *file, *data;
    int line, flags;

    while ((l = ERR_get_error_line_data(&file, &line, &data, &flags)) != 0) {
        ERR_error_string_n(l, buf, sizeof(buf));
        BIO_snprintf(buf2, sizeof(buf2), "%s:%s:%d:%s\n", buf,
                     file, line, (flags & ERR_TXT_STRING) ? data : "");
        if (cb(buf2, strlen(buf2), u, l) <= 0)
            break;              /* abort outputting the error report */
    }
}

// callback for print_errors_cb
static int err_print_cb(const char *str, size_t len, void *param, unsigned long ecode) {
    ERR_PARAM *p = (ERR_PARAM*)param;
    p->wt_api->err_printf(p->wt_api, p->session,
                              "libcrypto: %s", str);
    if (ERR_GET_REASON(ecode) == EVP_R_BAD_DECRYPT) {
        *(p->pret) = WT_PANIC;
        p->wt_api->err_printf(p->wt_api, p->session,
                              "setting return code to WT_PANIC");
    }
    return 1;
}

static int handleErrors(PERCONA_ENCRYPTOR *pe, WT_SESSION *session, int *pret) {
    ERR_PARAM param;
    param.wt_api = pe->wt_api;
    param.session = session;
    param.pret = pret;

    print_errors_cb(&err_print_cb, &param);
    return 0;
}

static char value_type_char(int type)
{
    switch (type) {
        case WT_CONFIG_ITEM_STRING:
            return 's';
        case WT_CONFIG_ITEM_BOOL:
            return 'b';
        case WT_CONFIG_ITEM_ID:
            return '#';
        case WT_CONFIG_ITEM_NUM:
            return 'n';
        case WT_CONFIG_ITEM_STRUCT:
            return 'z';
    }
    return 'x';
}

static void dump_key(PERCONA_ENCRYPTOR *pe, WT_SESSION *session, unsigned char *key, const int _key_len, const char * msg) {
    const char* m = "0123456789ABCDEF";
    char buf[_key_len * 3 + 1];
    char* p=buf;
    for (int i=0; i<_key_len; ++i) {
        *p++ = m[*key >> 4];
        *p++ = m[*key & 0xf];
        *p++ = ' ';
        ++key;
    }
    *p = 0;
    DBG_MSG("%s: %s", msg, buf);
}

static int dump_config_arg(PERCONA_ENCRYPTOR *pe, WT_SESSION *session, WT_CONFIG_ARG *config) {
    WT_EXTENSION_API *wt_api = pe->wt_api;
    WT_CONFIG_PARSER *parser = NULL;
    int ret = wt_api->config_parser_open_arg(wt_api, session, config, &parser);
    if (ret != 0)
        return ret;
    WT_CONFIG_ITEM k, v;
    while ((ret = parser->next(parser, &k, &v)) == 0) {
        DBG_MSG("%c%c:%.*s:%.*s", value_type_char(k.type), value_type_char(v.type), (int)k.len, k.str, (int)v.len, v.str);
    }
    parser->close(parser);
    return 0;
}

static int parse_customization_config(PERCONA_ENCRYPTOR *pe, WT_SESSION *session, WT_CONFIG_ARG *config) {
    WT_EXTENSION_API *wt_api = pe->wt_api;
    WT_CONFIG_PARSER *parser = NULL;
    int ret = wt_api->config_parser_open_arg(wt_api, session, config, &parser);
    if (ret != 0)
        return ret;
    WT_CONFIG_ITEM k, v;
    while (parser->next(parser, &k, &v) == 0) {
        if (!strncmp("keyid", k.str, (int)k.len)) {
            if (0 != get_key_by_id(v.str, v.len, pe->key, pe)) {
                ret = report_error(pe, session, EINVAL, "cannot get key by keyid");
                break;
            }
        }
    }
    parser->close(parser);
    return ret;
}

static void store_IV(PERCONA_ENCRYPTOR *pe, uint8_t *dst) {
    uint8_t buf[pe->iv_len];
    store_pseudo_bytes(buf, pe->iv_len);
    //TODO: encrypt pseudo bytes same way as PS does
    memcpy(dst, buf, pe->iv_len);
}

static int panic_encrypt(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_len,
    size_t *result_lenp)
{
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("wiredTiger attempted to encrypt data block after encryptor paniced");
    return WT_PANIC;
}

static int percona_encrypt_cbc(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_len,
    size_t *result_lenp)
{
    int ret = EINVAL;
    int encrypted_len = 0;
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering encrypt %lu %lu", src_len, dst_len);
    if (dst_len < pe->iv_len + src_len + EVP_CIPHER_block_size(pe->cipher))
        return (report_error(pe, session,
                ENOMEM, "encrypt buffer not big enough"));

    *result_lenp = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx_value;
    EVP_CIPHER_CTX *ctx= &ctx_value;
    EVP_CIPHER_CTX_init(ctx);
#else
    EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
    if (unlikely(!ctx))
        goto err;
#endif

#ifdef DBG_ENC_EXT
    DEBUG_DATA *dbg_data = (DEBUG_DATA*)dst;
    *result_lenp += sizeof(DEBUG_DATA);
    dbg_data->src_len = src_len;
    dbg_data->dst_len = dst_len;
    dbg_data->result_len = 0;
    memcpy(dbg_data->key, pe->key, KEY_LEN);
#endif

    *(uint32_t*)(dst + *result_lenp) = (pe->wiredtiger_checksum_crc32c)(src, src_len);
    *result_lenp += CHKSUM_LEN;

    uint8_t *iv = dst + *result_lenp;
    store_IV(pe, iv);
    *result_lenp += pe->iv_len;

    if(1 != EVP_EncryptInit_ex(ctx, pe->cipher, NULL, pe->key, iv))
        goto err;

    if(1 != EVP_EncryptUpdate(ctx, dst + *result_lenp, &encrypted_len, src, src_len))
        goto err;
    *result_lenp += encrypted_len;

    if(1 != EVP_EncryptFinal_ex(ctx, dst + *result_lenp, &encrypted_len))
        goto err;
    *result_lenp += encrypted_len;

    ret = 0;
    goto cleanup;

err:
    handleErrors(pe, session, &ret);

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
    DBG_MSG("exiting encrypt %lu", *result_lenp);
#ifdef DBG_ENC_EXT
    dbg_data->result_len = *result_lenp;
#endif
    return ret;
}

static int percona_encrypt_gcm(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_len,
    size_t *result_lenp)
{
    int ret = EINVAL;
    int encrypted_len = 0;
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering encrypt %lu %lu", src_len, dst_len);
    if (dst_len < pe->iv_len + src_len + GCM_TAG_LEN)
        return (report_error(pe, session,
                ENOMEM, "encrypt buffer not big enough"));

    *result_lenp = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx_value;
    EVP_CIPHER_CTX *ctx= &ctx_value;
    EVP_CIPHER_CTX_init(ctx);
#else
    EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
    if (unlikely(!ctx))
        goto err;
#endif

    if (0 != get_iv_gcm(dst, pe->iv_len)) {
        ret = report_error(pe, session, EINVAL, "failed generating IV for GCM");
        goto cleanup;
    }
    *result_lenp += pe->iv_len;

    if(1 != EVP_EncryptInit_ex(ctx, pe->cipher, NULL, pe->key, dst))
        goto err;

    // we don't provide any AAD data yet

    if(1 != EVP_EncryptUpdate(ctx, dst + *result_lenp, &encrypted_len, src, src_len))
        goto err;
    *result_lenp += encrypted_len;

    if(1 != EVP_EncryptFinal_ex(ctx, dst + *result_lenp, &encrypted_len))
        goto err;
    *result_lenp += encrypted_len;

    // get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, dst + *result_lenp))
        goto err;
    *result_lenp += GCM_TAG_LEN;

    ret = 0;
    goto cleanup;

err:
    handleErrors(pe, session, &ret);

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
    DBG_MSG("exiting encrypt %lu", *result_lenp);
    return ret;
}

static int percona_decrypt_cbc(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_len,
    size_t *result_lenp)
{
    int ret = EINVAL;
    int decrypted_len = 0;
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    uint32_t crc32c = 0;
    DBG_MSG("entering decrypt %lu %lu", src_len, dst_len);

    *result_lenp = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx_value;
    EVP_CIPHER_CTX *ctx= &ctx_value;
    EVP_CIPHER_CTX_init(ctx);
#else
    EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
    if (unlikely(!ctx))
        goto err;
#endif

#ifdef DBG_ENC_EXT
    DEBUG_DATA *dbg_data = (DEBUG_DATA*)src;
    char *key_msg = "";
    if (memcmp(dbg_data->key, pe->key, KEY_LEN)) {
        key_msg = "(WRONG KEY)";
        dump_key(pe, session, dbg_data->key, KEY_LEN, "encrypt key");
        dump_key(pe, session, pe->key, KEY_LEN, "decrypt key");
    }
    DBG_MSG("encrypt info s: %lu, d: %lu, r: %lu %s", dbg_data->src_len, dbg_data->dst_len, dbg_data->result_len, key_msg);
    src += sizeof(DEBUG_DATA);
    src_len -= sizeof(DEBUG_DATA);
#endif

    crc32c = *(uint32_t*)src;
    src += CHKSUM_LEN;
    src_len -= CHKSUM_LEN;

    if(1 != EVP_DecryptInit_ex(ctx, pe->cipher, NULL, pe->key, src))
        goto err;
    src += pe->iv_len;
    src_len -= pe->iv_len;

    if(1 != EVP_DecryptUpdate(ctx, dst, &decrypted_len, src, src_len))
        goto err;
    *result_lenp += decrypted_len;

    if(1 != EVP_DecryptFinal_ex(ctx, dst + *result_lenp, &decrypted_len))
        goto err;
    *result_lenp += decrypted_len;

    if ((pe->wiredtiger_checksum_crc32c)(dst, *result_lenp) != crc32c) {
        ret = report_error(pe, session, EINVAL, "Decrypted data integrity check has failed. Probably the encryption key was wrong.");
        ret = WT_PANIC;
        goto err;
    }

    ret = 0;
    goto cleanup;

err:
    handleErrors(pe, session, &ret);
    if (ret == WT_PANIC) {
        // go to readonly mode because the encryption key is probably wrong
        encryptor->encrypt = panic_encrypt;
    }

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
    DBG_MSG("exiting decrypt %lu", *result_lenp);
    return ret;
}

static int percona_decrypt_gcm(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    uint8_t *src, size_t src_len,
    uint8_t *dst, size_t dst_len,
    size_t *result_lenp)
{
    int ret = EINVAL;
    int decrypted_len = 0;
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering decrypt %lu %lu", src_len, dst_len);

    *result_lenp = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX ctx_value;
    EVP_CIPHER_CTX *ctx= &ctx_value;
    EVP_CIPHER_CTX_init(ctx);
#else
    EVP_CIPHER_CTX *ctx= EVP_CIPHER_CTX_new();
    if (unlikely(!ctx))
        goto err;
#endif

    if(1 != EVP_DecryptInit_ex(ctx, pe->cipher, NULL, pe->key, src))
        goto err;
    src += pe->iv_len;
    src_len -= pe->iv_len;

    // we have no AAD yet

    if(1 != EVP_DecryptUpdate(ctx, dst, &decrypted_len, src, src_len - GCM_TAG_LEN))
        goto err;
    *result_lenp += decrypted_len;
    dst += decrypted_len;
    src += src_len - GCM_TAG_LEN;
    src_len = GCM_TAG_LEN;

    // Set expected tag value. Works in OpenSSL 1.0.1d and later
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, src))
        goto err;

    if(1 != EVP_DecryptFinal_ex(ctx, dst, &decrypted_len))
        goto err;
    *result_lenp += decrypted_len;

    ret = 0;
    goto cleanup;

err:
    handleErrors(pe, session, &ret);
    if (ret == WT_PANIC) {
        // go to readonly mode because the encryption key is probably wrong
        encryptor->encrypt = panic_encrypt;
    }

cleanup:
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    EVP_CIPHER_CTX_cleanup(ctx);
#else
    EVP_CIPHER_CTX_free(ctx);
#endif
    DBG_MSG("exiting decrypt %lu", *result_lenp);
    return ret;
}

static int percona_sizing_cbc(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    size_t *expansion_constantp)
{
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering sizing");
    (void)session;              /* Unused parameters */

    *expansion_constantp = CHKSUM_LEN + pe->iv_len + EVP_CIPHER_block_size(pe->cipher);
#ifdef DBG_ENC_EXT
    *expansion_constantp += sizeof(DEBUG_DATA);
#endif
    return 0;
}

static int percona_sizing_gcm(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    size_t *expansion_constantp)
{
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering sizing");
    (void)session;              /* Unused parameters */

    *expansion_constantp = pe->iv_len + GCM_TAG_LEN;
    return 0;
}

static int percona_customize(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    WT_CONFIG_ARG *encrypt_config, WT_ENCRYPTOR **customp)
{
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering customize");
    DBG dump_config_arg(pe, session, encrypt_config);
    PERCONA_ENCRYPTOR *cpe;
    if ((cpe = calloc(1, sizeof(PERCONA_ENCRYPTOR))) == NULL)
            return errno;
    *cpe = *pe;
    // new instance passed to parse_customization_config because it should fill encryption key field
    int ret = parse_customization_config(cpe, session, encrypt_config);
    if (ret != 0) {
        free(cpe);
        return ret;
    }
    *customp = (WT_ENCRYPTOR*)cpe;
    return 0;
}

static int percona_sessioncreate(WT_ENCRYPTOR *encryptor, WT_SESSION *session,
    WT_CONFIG_ARG *encrypt_config)
{
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering sessioncreate");
    DBG dump_config_arg(pe, session, encrypt_config);
    // get/generate encryption key
    // possible errors are reported from parse_customization_config
    int ret = parse_customization_config(pe, session, encrypt_config);
    // if everything is ok we don't need this callback until next DB drop
    if (!ret) {
        pe->encryptor.sessioncreate = NULL;
    }
    return ret;
}

static int percona_terminate(WT_ENCRYPTOR *encryptor, WT_SESSION *session)
{
    PERCONA_ENCRYPTOR *pe = (PERCONA_ENCRYPTOR*)encryptor;
    DBG_MSG("entering terminate");
    free(encryptor);
    return 0;
}

static int init_from_config(PERCONA_ENCRYPTOR *pe, WT_CONFIG_ARG *config)
{
    WT_EXTENSION_API *wt_api = pe->wt_api;
    bool cipherMode = false;
    WT_CONFIG_PARSER *parser = NULL;
    int ret = wt_api->config_parser_open_arg(wt_api, NULL, config, &parser);
    if (ret != 0)
        return ret;

    WT_CONFIG_ITEM k, v;
    while ((ret = parser->next(parser, &k, &v)) == 0) {
        if (!strncmp("cipher", k.str, (int)k.len)) {
            if (!strncmp("AES256-CBC", v.str, (int)v.len)) {
                cipherMode = true;
                pe->cipher = EVP_aes_256_cbc();
                pe->encryptor.encrypt = percona_encrypt_cbc;
                pe->encryptor.decrypt = percona_decrypt_cbc;
                pe->encryptor.sizing = percona_sizing_cbc;
            }
            else if (!strncmp("AES256-GCM", v.str, (int)v.len)) {
                cipherMode = true;
                pe->cipher = EVP_aes_256_gcm();
                pe->encryptor.encrypt = percona_encrypt_gcm;
                pe->encryptor.decrypt = percona_decrypt_gcm;
                pe->encryptor.sizing = percona_sizing_gcm;
            }
            else
                return (report_error(pe, NULL, EINVAL, "specified cipher mode is not supported"));
        }
    }
    parser->close(parser);

    if (!cipherMode)
        return (report_error(pe, NULL, EINVAL, "cipher mode is not specified"));
    return 0;
}

int percona_encryption_extension_init(WT_CONNECTION *connection, WT_CONFIG_ARG *config) {
    int ret = 0;
    PERCONA_ENCRYPTOR *pe;
    WT_SESSION *session = NULL; // NULL session pointer for the DBG_MSG macro

    if ((pe = calloc(1, sizeof(PERCONA_ENCRYPTOR))) == NULL)
            return errno;

    pe->wt_api = connection->get_extension_api(connection);
    DBG_MSG("hello from the percona_encryption_extension_init");

    DBG dump_config_arg(pe, NULL, config);

    pe->encryptor.customize = percona_customize;
    pe->encryptor.terminate = percona_terminate;
    pe->encryptor.sessioncreate = NULL;

    ret = init_from_config(pe, config);
    if (ret != 0)
        goto failure;

    pe->iv_len = EVP_CIPHER_iv_length(pe->cipher);
    DBG_MSG("IV len is %d", pe->iv_len);
    DBG_MSG("key len is %d", EVP_CIPHER_key_length(pe->cipher));

    // get wiredTiger's crc32c function
    pe->wiredtiger_checksum_crc32c = wiredtiger_crc32c_func();

    // calloc initializes all allocated memory to zero
    // thus pe->key is filled with zeros
    // actual encryption keys are loaded by 'customize' callback

    return connection->add_encryptor(connection, "percona", (WT_ENCRYPTOR*)pe, NULL);

failure:
    free(pe);
    return ret;
}

// This is called when database is dropped.
// It should configure encryptor in a way to request new encryption key
// if new database with the same name will be created.
// (If this happens before connection is closed wiredTiger uses
// existing encryptor with old encryption key for specific keyid.
// This function configures encryptor to give it a chance to get new
// encryption key.)
int percona_encryption_extension_drop_keyid(void *vp) {
    PERCONA_ENCRYPTOR *pe = vp;
    pe->encryptor.sessioncreate = percona_sessioncreate;
    return 0;
}
