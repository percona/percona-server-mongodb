/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Labora`tory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "kmip.h"
#include "kmip_bio.h"
#include "kmip_memset.h"
#include "kmip_locate.h"
//#include "ssl_connect.h"


void
print_help(const char *app)
{
    printf("Usage: %s [flag value | flag] ...\n\n", app);
    printf("Flags:\n");
    printf("-a addr : the IP address of the KMIP server\n");
    printf("-c path : path to client certificate file\n");
    printf("-h      : print this help info\n");
    printf("-k path : path to client key file\n");
    printf("-p port : the port number of the KMIP server\n");
    printf("-r path : path to CA certificate file\n");
    printf("-n name : name of new key\n");
    printf("-g group : name of object group\n");
}

int
parse_arguments(int argc, char **argv,
                char **server_address, char **server_port,
                char **client_certificate, char **client_key, char **ca_certificate,
                char **key_name,
                char **group,
                int *print_usage)
{
    if(argc <= 1)
    {
        print_help(argv[0]);
        return(-1);
    }
    
    for(int i = 1; i < argc; i++)
    {
        if(strncmp(argv[i], "-a", 2) == 0)
        {
            *server_address = argv[++i];
        }
        else if(strncmp(argv[i], "-c", 2) == 0)
        {
            *client_certificate = argv[++i];
        }
        else if(strncmp(argv[i], "-h", 2) == 0)
        {
            *print_usage = 1;
        }
        else if(strncmp(argv[i], "-k", 2) == 0)
        {
            *client_key = argv[++i];
        }
        else if(strncmp(argv[i], "-p", 2) == 0)
        {
            *server_port = argv[++i];
        }
        else if(strncmp(argv[i], "-r", 2) == 0)
        {
            *ca_certificate = argv[++i];
        }
        else if(strncmp(argv[i], "-n", 2) == 0)
            *key_name = argv[++i];
        else if(strncmp(argv[i], "-g", 2) == 0)
            *group = argv[++i];
        else
        {
            printf("Invalid option: '%s'\n", argv[i]);
            print_help(argv[0]);
            return(-1);
        }
    }
    
    return(0);
}


void *
demo_calloc(void *state, size_t num, size_t size)
{
    void* ptr = calloc(num, size);
    printf("demo_calloc called: state = %p, num = %zu, size = %zu, ptr = %p\n", state, num, size, ptr);
    return(ptr);
}

void *
demo_realloc(void *state, void *ptr, size_t size)
{
    void* reptr = realloc(ptr, size);
    printf("demo_realloc called: state = %p, ptr = %p, size = %zu, reptr = %p\n", state, ptr, size, reptr);
    return(realloc(reptr, size));
}

void
demo_free(void *state, void *ptr)
{
    printf("demo_free called: state = %p, ptr = %p\n", state, ptr);
    free(ptr);
    return;
}


int use_low_level_api(KMIP *ctx, BIO *bio, Attribute* attribs, size_t attrib_count, LocateResponse* locate_result)
{
    if (ctx == NULL || bio == NULL || attribs == NULL || attrib_count == 0 || locate_result == NULL)
    {
        return(KMIP_ARG_INVALID);
    }

    printf("bio locate start \n");

    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 *encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
    if(encoding == NULL)
    {
        kmip_destroy(ctx);
        return(KMIP_MEMORY_ALLOC_FAILED);
    }
    printf("encoding = %p\n", encoding);
    kmip_set_buffer(ctx, encoding, buffer_total_size);

    /* Build the request message. */


    ProtocolVersion pv = {0};
    kmip_init_protocol_version(&pv, ctx->version);

    RequestHeader rh = {0};
    kmip_init_request_header(&rh);

    rh.protocol_version = &pv;
    rh.maximum_response_size = ctx->max_message_size;
    rh.time_stamp = time(NULL);
    rh.batch_count = 1;


    // copy input array to list
    LinkedList *attribute_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    for(size_t i = 0; i < attrib_count; i++)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        item->data = kmip_deep_copy_attribute(ctx, &attribs[i]);
        kmip_linked_list_enqueue(attribute_list, item);
    }

    LocateRequestPayload lrp = {0};
    lrp.maximum_items = 12;
    lrp.offset_items = 0;
    lrp.storage_status_mask = 0;
    lrp.group_member_option = 0;
    lrp.attribute_list = attribute_list;

    RequestBatchItem rbi = {0};
    kmip_init_request_batch_item(&rbi);
    rbi.operation = KMIP_OP_LOCATE;
    rbi.request_payload = &lrp;

    RequestMessage rm = {0};
    rm.request_header = &rh;
    rm.batch_items = &rbi;
    rm.batch_count = 1;

    /* Encode the request message. Dynamically resize the encoding buffer */
    /* if it's not big enough. Once encoding succeeds, send the request   */
    /* message.                                                           */
    int encode_result = kmip_encode_request_message(ctx, &rm);
    while(encode_result == KMIP_ERROR_BUFFER_FULL)
    {
        kmip_reset(ctx);
        ctx->free_func(ctx->state, encoding);

        buffer_blocks += 1;
        buffer_total_size = buffer_blocks * buffer_block_size;

        encoding = ctx->calloc_func(ctx->state, buffer_blocks, buffer_block_size);
        if(encoding == NULL)
        {
            printf("Failure: Could not automatically enlarge the encoding ");
            printf("buffer for the Locate request.\n");

            kmip_destroy(ctx);
            return(KMIP_MEMORY_ALLOC_FAILED);
        }
        printf("encoding = %p\n", encoding);

        kmip_set_buffer(ctx, encoding, buffer_total_size);
        encode_result = kmip_encode_request_message(ctx, &rm);
    }

    if(encode_result != KMIP_OK)
    {
        printf("An error occurred while encoding the Locate request.\n");
        printf("Error Code: %d\n", encode_result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, encode_result);
        printf("\n");
        printf("Context Error: %s\n", ctx->error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, ctx);

        kmip_free_buffer(ctx, encoding, buffer_total_size);
        encoding = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_destroy(ctx);
        return(encode_result);
    }

    kmip_print_request_message(stdout, &rm);
    printf("\n");

    char *response = NULL;
    int response_size = 0;

    printf("bio locate send request\n");

    int result = kmip_bio_send_request_encoding(ctx, bio, (char *)encoding, ctx->index - ctx->buffer, &response, &response_size);

    printf("bio locate response = %p\n", response);


    printf("\n");
    if(result < 0)
    {
        printf("An error occurred in locate request.\n");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, result);
        printf("\n");
        printf("Context Error: %s\n", ctx->error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, ctx);

        kmip_free_buffer(ctx, encoding, buffer_total_size);
        kmip_free_buffer(ctx, response, response_size);
        encoding = NULL;
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_destroy(ctx);
        return(result);
    }

    kmip_free_locate_request_payload(ctx, &lrp);


    if (response)
    {
        FILE* out = fopen( "/tmp/kmip_locate.dat", "w" );
        if (out)
        {
            if (fwrite( response, response_size, 1, out ) != 1 )
                fprintf(stderr, "failed writing dat file\n");
            fclose(out);
        }
        kmip_print_buffer(stdout, response, response_size);
    }

    printf("bio locate free encoding =  %p\n", encoding);
    kmip_free_buffer(ctx, encoding, buffer_total_size);
    encoding = NULL;
    kmip_set_buffer(ctx, response, response_size);

    /* Decode the response message and retrieve the operation results. */
    ResponseMessage resp_m = {0};
    int decode_result = kmip_decode_response_message(ctx, &resp_m);
    if(decode_result != KMIP_OK)
    {
        printf("An error occurred while decoding the Locate response.\n");
        printf("Error Code: %d\n", decode_result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, decode_result);
        printf("\n");
        printf("Context Error: %s\n", ctx->error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, ctx);

        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_destroy(ctx);
        return(decode_result);
    }

    kmip_print_response_message(stdout, &resp_m);
    printf("\n");

    if(resp_m.batch_count != 1 || resp_m.batch_items == NULL)
    {
        printf("Expected to find one batch item in the Locate response.\n");
        kmip_free_response_message(ctx, &resp_m);
        kmip_free_buffer(ctx, response, response_size);
        response = NULL;
        kmip_set_buffer(ctx, NULL, 0);
        kmip_destroy(ctx);
        return(KMIP_MALFORMED_RESPONSE);
    }

    ResponseBatchItem req = resp_m.batch_items[0];
    enum result_status result_status = req.result_status;

    printf("The KMIP operation was executed with no errors.\n");
    printf("Result: ");
    kmip_print_result_status_enum(stdout, result);
    printf(" (%d)\n\n", result);

    if(result == KMIP_STATUS_SUCCESS)
    {
        kmip_copy_locate_result(locate_result, (LocateResponsePayload*) req.response_payload);
    }

    printf("bio locate free response resp_m =  %p, response = %p\n", (void*)&resp_m, response);
    if (locate_result->ids_size)
    {
        printf("id[0] = %s\n", locate_result->ids[0]);
    }

    /* Clean up the response message, the response buffer, and the KMIP */
    /* context.                                                         */
    kmip_free_response_message(ctx, &resp_m);
    kmip_free_buffer(ctx, response, response_size);
    response = NULL;

    //kmip_set_buffer(ctx, NULL, 0);
   // kmip_destroy(ctx);

    printf("bio locate done \n");

    return(result_status);
}


Credential* get_credential(char* device_serial_number,char* device_identifier, char* machine_identifier )
{
    static Credential credential = {0};
    static DeviceCredential devc = {0};
    static TextString sn = {0};
    static TextString did = {0};
    static TextString mid = {0};

    memset(&devc,0, sizeof(devc) );
    if (device_serial_number)
    {
        sn.value = device_serial_number;
        sn.size = kmip_strnlen_s(device_serial_number, 50);
        devc.device_serial_number = &sn;
    }
    if (device_identifier)
    {
        did.value = device_identifier;
        did.size = kmip_strnlen_s(device_identifier, 50);
        devc.device_identifier = &did;
    }
    if (machine_identifier)
    {
        mid.value = machine_identifier;
        mid.size = kmip_strnlen_s(machine_identifier, 50);
        devc.machine_identifier = &mid;
    }

    credential.credential_type = KMIP_CRED_DEVICE;
    credential.credential_value = &devc;

    return &credential;
}

int
use_mid_level_api(BIO* bio,
                  char *key_name,
                  char *group,
                  LocateResponse* locate_result)
{
    int result;

    /* Set up the KMIP context and send the request message. */
    KMIP kmip_context = {0};

    //kmip_context.calloc_func = &demo_calloc;
    //kmip_context.realloc_func = &demo_realloc;
    //kmip_context.free_func = &demo_free;

    kmip_init(&kmip_context, NULL, 0, KMIP_1_4);
    

#define USE_DEVICE_CREDENTIALS
#ifdef USE_DEVICE_CREDENTIALS

    char device_serial_number[] = "J3003MFY";
    char device_identifier[] = "7X06";
    char machine_identifier[] = "ED98BF5CE30E11E7BA717ED30AE6BACF";

    Credential* cred = get_credential(device_serial_number,device_identifier, machine_identifier );
    result = kmip_add_credential(&kmip_context, cred);
    if(result != KMIP_OK)
    {
        printf("Failed to add credential to the KMIP context.\n");
    }
#endif // USE_DEVICE_CREDENTIALS

    /* Build the request message. */
    Attribute a[6] = {{0}};
    for(int i = 0; i < 6; i++)
        kmip_init_attribute(&a[i]);


    int idx = 0;

    // look for symmetric key
    enum object_type loctype = KMIP_OBJTYPE_SYMMETRIC_KEY;
    a[idx].type = KMIP_ATTR_OBJECT_TYPE;
    a[idx].value = &loctype;
    idx++;

    if (0)
    {
        enum cryptographic_algorithm algorithm = KMIP_CRYPTOALG_AES;
        a[idx].type = KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM;
        a[idx].value = &algorithm;
        idx++;

        int32 length = 256;
        a[idx].type = KMIP_ATTR_CRYPTOGRAPHIC_LENGTH;
        a[idx].value = &length;
        idx++;

        int32 mask = KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT;
        a[idx].type = KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK;
        a[idx].value = &mask;
        idx++;
    }

    TextString s = { 0 };
    Name n = { 0 };
    if (0 && key_name)
    {
        s.value = (char*) key_name;
        s.size = kmip_strnlen_s(key_name, 50);

        n.value = &s;
        n.type = KMIP_NAME_UNINTERPRETED_TEXT_STRING;

        a[idx].type = KMIP_ATTR_NAME;
        a[idx].value = &n;

        idx++;
    }

    TextString g = { 0 };
    if (group)
    {
        g.value = (char*) group;
        g.size = kmip_strnlen_s(group, 50);

        a[idx].type = KMIP_ATTR_OBJECT_GROUP;
        a[idx].value = &g;

        idx++;
    }

    int attrib_count = idx;

    result = kmip_bio_locate_with_context(&kmip_context, bio, a, attrib_count, locate_result, 16, 0);
    //result = use_low_level_api(&kmip_context, bio, a, attrib_count, locate_result);
    
    /* Handle the response results. */
    printf("\n");
    if(result < 0)
    {
        printf("An error occurred while running the locate.");
        printf("Error Code: %d\n", result);
        printf("Error Name: ");
        kmip_print_error_string(stderr, result);
        printf("\n");
        printf("Context Error: %s\n", kmip_context.error_message);
        printf("Stack trace:\n");
        kmip_print_stack_trace(stderr, &kmip_context);
    }
    else if(result >= 0)
    {
        printf("The KMIP operation was executed with no errors.\n");
        printf("Result: ");
        kmip_print_result_status_enum(stdout, result);
        printf(" (%d)\n", result);
        
        if(result == KMIP_STATUS_SUCCESS)
        {
            printf("Locate results: ");
            printf("located: %d\n", locate_result->located_items);
            printf("\n");
        }
    }
    
    printf("\n");
    
    /* Clean up the KMIP context and return the results. */
    kmip_set_buffer(&kmip_context, NULL, 0);
    kmip_destroy(&kmip_context);
    return(result);
}

int
main(int argc, char **argv)
{
    char *server_address = NULL;
    char *server_port = NULL;
    char *client_certificate = NULL;
    char *client_key = NULL;
    char *ca_certificate = NULL;
    char *key_name = NULL;
    char *group = NULL;
    int help = 0;
    
    int error = parse_arguments(argc, argv, &server_address, &server_port, &client_certificate, &client_key, &ca_certificate, &key_name, &group, &help);
    if(error)
    {
        return(error);
    }
    if(help)
    {
        print_help(argv[0]);
        return(0);
    }

    /* Set up the TLS connection to the KMIP server. */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_library_init();
    ctx = SSL_CTX_new(SSLv23_method());

    if (!ctx)
        return 1;

    SSL_SESSION* session = NULL;

    printf("\n");
    printf("Loading the client certificate: %s\n", client_certificate);
    if(SSL_CTX_use_certificate_file(ctx, client_certificate, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client certificate failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    printf("Loading the client key: %s\n", client_key);
    if(SSL_CTX_use_PrivateKey_file(ctx, client_key, SSL_FILETYPE_PEM) != 1)
    {
        fprintf(stderr, "Loading the client key failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    printf("Loading the CA certificate: %s\n", ca_certificate);
    if(SSL_CTX_load_verify_locations(ctx, ca_certificate, NULL) != 1)
    {
        fprintf(stderr, "Loading the CA file failed\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return(-1);
    }
    
    BIO *bio = NULL;
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL)
    {
        printf("BIO_new_ssl_connect failed\n");
        SSL_CTX_free(ctx);
        return(-1);
    }
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(bio, server_address);
    BIO_set_conn_port(bio, server_port);

    if(BIO_do_connect(bio) != 1)
    {
        fprintf(stderr, "BIO_do_connect failed\n");
        ERR_print_errors_fp(stderr);
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return(-1);
    }
    

    LocateResponse locate_result = {0};
    int result = use_mid_level_api(bio, key_name, group, &locate_result);

    if(result == KMIP_STATUS_SUCCESS)
    {
        printf("Locate results: ");
        printf("located items: %d\n", locate_result.located_items);
        printf("returned items: %zu\n", locate_result.ids_size);
        for(int i=0;i<locate_result.ids_size;++i){
          printf("id[%i]=  %s\n", i, locate_result.ids[i]);
        }
        printf("\n");
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return(result);
}
