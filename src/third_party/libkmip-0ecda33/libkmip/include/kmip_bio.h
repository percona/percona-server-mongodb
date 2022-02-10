/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_BIO_H
#define KMIP_BIO_H

#include <openssl/ssl.h>
#include "kmip.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct query_response QueryResponse;
typedef struct locate_response LocateResponse;

typedef struct last_result
{
    enum operation operation;
    enum result_status result_status;
    enum result_reason result_reason;
    char result_message[128];
} LastResult;

int kmip_set_last_result(ResponseBatchItem*);
const LastResult* kmip_get_last_result(void);
int kmip_last_reason(void);
const char* kmip_last_message(void);
void kmip_clear_last_result(void);


/*
OpenSSH BIO API
*/

int kmip_bio_create_symmetric_key(BIO *, TemplateAttribute *, char **, int *);
int kmip_bio_register_symmetric_key(BIO *, TemplateAttribute *, char*, int, char **, int *);
int kmip_bio_get_symmetric_key(BIO *, char *, int, char **, int *);
int kmip_bio_get_name_attribute(BIO *, char *, int, char **, int *);
int kmip_bio_destroy_symmetric_key(BIO *, char *, int);

int kmip_bio_create_symmetric_key_with_context(KMIP *, BIO *, TemplateAttribute *, char **, int *);
int kmip_bio_get_symmetric_key_with_context(KMIP *, BIO *, char *, int, char **, int *);
int kmip_bio_destroy_symmetric_key_with_context(KMIP *, BIO *, char *, int);

int kmip_bio_locate(BIO *bio, Attribute* attribs, size_t attrib_count, LocateResponse* locate_result, int max_items, int offset);
int kmip_bio_query_with_context(KMIP *ctx, BIO *bio, enum query_function queries[], size_t query_count, QueryResponse* query_result);
int kmip_bio_locate_with_context(KMIP *ctx, BIO *bio, Attribute* attribs, size_t attrib_count, LocateResponse* locate_result, int max_items, int offset);
int kmip_bio_send_request_encoding(KMIP *, BIO *, char *, int, char **, int *);

#ifdef __cplusplus
}
#endif

#endif  /* KMIP_BIO_H */
