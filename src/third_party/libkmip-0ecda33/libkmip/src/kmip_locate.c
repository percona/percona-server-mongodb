/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "kmip.h"
#include "kmip_memset.h"
#include "kmip_bio.h"
#include "kmip_locate.h"

/*
Locate Utilities
*/




void kmip_free_attribute_list(KMIP* ctx, LinkedList* value)
{
    if(value != NULL)
    {
        LinkedListItem *curr = kmip_linked_list_pop(value);
        while(curr != NULL)
        {
            Attribute *attribute = (Attribute *)curr->data;
            kmip_free_attribute(ctx, attribute);
            ctx->free_func(ctx->state, attribute);
            ctx->free_func(ctx->state, curr);
            curr = kmip_linked_list_pop(value);
        }
    }
}

int kmip_encode_attribute_list(KMIP* ctx, LinkedList* value)
{
    CHECK_ENCODE_ARGS(ctx, value);

    int result = 0;

    if(value != NULL)
    {
        LinkedListItem *curr = value->head;
        while(curr != NULL)
        {
            Attribute *attribute = (Attribute *)curr->data;
            result = kmip_encode_attribute(ctx, attribute);
            CHECK_RESULT(ctx, result);

            curr = curr->next;
        }
    }

    return(KMIP_OK);

}

void kmip_print_attribute_list(FILE* f, int indent, LinkedList* value)
{
    if(value != NULL)
    {
        LinkedListItem *curr = value->head;
        while(curr != NULL)
        {
            Attribute *attribute = (Attribute *)curr->data;
            kmip_print_attribute(f, indent + 2, attribute);

            curr = curr->next;
        }
    }
}

void kmip_print_locate_request_payload(FILE* f, int indent, LocateRequestPayload * value)
{
    if (value)
    {
        fprintf(f, "%*sMaximum items: ", indent + 2, "");
        kmip_print_integer(f, value->maximum_items);
        fprintf(f, "\n");

        fprintf(f, "%*sOffset items: ", indent + 2, "");
        kmip_print_integer(f, value->offset_items);
        fprintf(f, "\n");

        fprintf(f, "%*sStorage status: ", indent + 2, "");
        kmip_print_integer(f, value->storage_status_mask);
        fprintf(f, "\n");

        if(value->attribute_list)
            kmip_print_attribute_list(f, indent + 2, value->attribute_list);
    }
}

void kmip_free_locate_request_payload(KMIP* ctx, LocateRequestPayload *value)
{
    if (value->attribute_list)
    {
        kmip_free_attribute_list(ctx, value->attribute_list);
        ctx->free_func(ctx->state, value->attribute_list);
        value->attribute_list = NULL;
    }
}

int kmip_compare_locate_request_payload(const LocateRequestPayload *a, const LocateRequestPayload *b)
{
    (void) a;
    (void) b;
    return(KMIP_NOT_IMPLEMENTED);
}

int
kmip_encode_locate_request_payload(KMIP* ctx, const LocateRequestPayload* value)
{
    int result = 0;
    result = kmip_encode_int32_be(ctx, TAG_TYPE(KMIP_TAG_REQUEST_PAYLOAD, KMIP_TYPE_STRUCTURE));
    CHECK_RESULT(ctx, result);

    uint8 *length_index = ctx->index;
    uint8 *value_index = ctx->index += 4;

    if(value->maximum_items)
    {
        result = kmip_encode_integer(ctx, KMIP_TAG_MAXIMUM_ITEMS, value->maximum_items);
        CHECK_RESULT(ctx, result);
    }

    if (value->offset_items)
    {
        result = kmip_encode_integer(ctx, KMIP_TAG_OFFSET_ITEMS, value->offset_items);
        CHECK_RESULT(ctx, result);
    }

    if (value->storage_status_mask)
    {
        result = kmip_encode_integer(ctx, KMIP_TAG_STORAGE_STATUS_MASK, value->storage_status_mask);
        CHECK_RESULT(ctx, result);
    }

    if (value->group_member_option)
    {
        result = kmip_encode_enum(ctx, KMIP_TAG_OBJECT_GROUP_MEMBER, value->group_member_option);
        CHECK_RESULT(ctx, result);
    }

    if(ctx->version < KMIP_2_0)
    {
        if (value->attribute_list)
        {
            // copy input list to allow freeing
            LinkedList *list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
            if (list == NULL) 
            {
                return (KMIP_MEMORY_ALLOC_FAILED);
            }
            LinkedListItem *curr = value->attribute_list->head;
            while(curr != NULL)
            {
                LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
                if (item == NULL) 
                {
                    return (KMIP_MEMORY_ALLOC_FAILED);
                }
                item->data = kmip_deep_copy_attribute(ctx, curr->data);
                kmip_linked_list_enqueue(list, item);

                curr = curr->next;
            }

            result = kmip_encode_attribute_list(ctx, list);

            kmip_free_attribute_list(ctx, list);
            ctx->free_func(ctx->state, list);

            CHECK_RESULT(ctx, result);
        }
    }
    else
    {
        // todo : copy attrib list into Attribute - see kmip.c
        assert(0);
    }

    uint8 *curr_index = ctx->index;
    ctx->index = length_index;

    kmip_encode_int32_be(ctx, curr_index - value_index);

    ctx->index = curr_index;

    return(KMIP_OK);
}

int kmip_decode_locate_request_payload(KMIP* ctx, LocateRequestPayload *value)
{
    (void) ctx;
    (void) value;
    return(KMIP_NOT_IMPLEMENTED);
}

void kmip_print_locate_response_payload(FILE* f, int indent, LocateResponsePayload *value)
{
    fprintf(f, "%*sLocated Items: ", indent + 2, "");
    kmip_print_integer(f, value->located_items);
    fprintf(f, "\n");

    kmip_print_unique_identifiers(f, indent, value->unique_ids);
}
void kmip_free_locate_response_payload(KMIP* ctx, LocateResponsePayload *value)
{
    if (value->unique_ids)
    {
        kmip_free_unique_identifiers(ctx, value->unique_ids);
        ctx->free_func(ctx->state, value->unique_ids);
        value->unique_ids = NULL;
    }
}
int kmip_compare_locate_response_payload(const LocateResponsePayload *a, const LocateResponsePayload *b)
{
    (void) a;
    (void) b;
    return(KMIP_NOT_IMPLEMENTED);
}
int kmip_encode_locate_response_payload(KMIP* ctx, const LocateResponsePayload *value)
{
    (void) ctx;
    (void) value;
    return(KMIP_NOT_IMPLEMENTED);
}
int kmip_decode_locate_response_payload(KMIP* ctx, LocateResponsePayload *value)
{
    CHECK_BUFFER_FULL(ctx, 8);

    int result = 0;
    int32 tag_type = 0;
    uint32 length = 0;

    kmip_decode_int32_be(ctx, &tag_type);
    CHECK_TAG_TYPE(ctx, tag_type, KMIP_TAG_RESPONSE_PAYLOAD, KMIP_TYPE_STRUCTURE);

    kmip_decode_int32_be(ctx, &length);
    CHECK_BUFFER_FULL(ctx, length);

    if(kmip_is_tag_next(ctx, KMIP_TAG_LOCATED_ITEMS))
    {
        result = kmip_decode_integer(ctx, KMIP_TAG_LOCATED_ITEMS, &value->located_items);
        CHECK_RESULT(ctx, result);
    }

    if(kmip_is_tag_next(ctx, KMIP_TAG_UNIQUE_IDENTIFIER))
    {
        value->unique_ids = ctx->calloc_func(ctx->state, 1, sizeof(UniqueIdentifiers));
        if (value->unique_ids == NULL) 
        {
            return (KMIP_MEMORY_ALLOC_FAILED);
        }
        CHECK_NEW_MEMORY(ctx, value->unique_ids, sizeof(UniqueIdentifiers), "Unique_Identifiers");
        result = kmip_decode_unique_identifiers(ctx, value->unique_ids);
        CHECK_RESULT(ctx, result);
    }

    return(KMIP_OK);
}


void
kmip_print_unique_identifiers(FILE* f, int indent, UniqueIdentifiers* value)
{
    fprintf(f, "%*sUnique IDs @ %p\n", indent, "", (void *)value);

    if(value != NULL)
    {
        fprintf(f, "%*sUnique IDs: %zu\n", indent + 2, "", value->unique_identifier_list->size);
        LinkedListItem *curr = value->unique_identifier_list->head;
        size_t count = 1;
        while(curr != NULL)
        {
            fprintf(f, "%*sUnique ID: %zu: ", indent + 4, "", count);
            kmip_print_text_string(f, indent + 2, "", curr->data);
            fprintf(f, "\n");

            curr = curr->next;
            count++;
        }
    }
}

void
kmip_copy_unique_ids(char ids[][MAX_LOCATE_LEN], size_t* id_size, UniqueIdentifiers* value, unsigned max_ids)
{
    size_t idx = 0;
    if(value != NULL)
    {
        LinkedListItem *curr = value->unique_identifier_list->head;
        while(curr != NULL && idx < max_ids)
        {
            kmip_copy_textstring(ids[idx], curr->data, MAX_LOCATE_LEN-1);
            curr = curr->next;
            idx++;
        }
    }
    *id_size = idx;
}


void
kmip_free_unique_identifiers(KMIP *ctx, UniqueIdentifiers* value)
{
    if(value != NULL)
    {
        if(value->unique_identifier_list != NULL)
        {
            LinkedListItem *curr = kmip_linked_list_pop(value->unique_identifier_list);
            while(curr != NULL)
            {
                kmip_free_text_string(ctx, curr->data);
                ctx->free_func(ctx->state, curr->data);
                curr->data = NULL;
                ctx->free_func(ctx->state, curr);
                curr = kmip_linked_list_pop(value->unique_identifier_list);
            }
            ctx->free_func(ctx->state, value->unique_identifier_list);
            value->unique_identifier_list= NULL;
        }
    }

    return;
}


int kmip_decode_unique_identifiers(KMIP* ctx, UniqueIdentifiers* value)
{
    int result = 0;

    value->unique_identifier_list = ctx->calloc_func(ctx->state, 1, sizeof(LinkedList));
    CHECK_NEW_MEMORY(ctx, value->unique_identifier_list, sizeof(LinkedList), "LinkedList");

    uint32 tag = kmip_peek_tag(ctx);
    while(tag == KMIP_TAG_UNIQUE_IDENTIFIER)
    {
        LinkedListItem *item = ctx->calloc_func(ctx->state, 1, sizeof(LinkedListItem));
        CHECK_NEW_MEMORY(ctx, item, sizeof(LinkedListItem), "LinkedListItem");
        kmip_linked_list_enqueue(value->unique_identifier_list, item);

        item->data = ctx->calloc_func(ctx->state, 1, sizeof(TextString));
        CHECK_NEW_MEMORY(ctx, item->data, sizeof(TextString), "Unique ID text string");

        result = kmip_decode_text_string(ctx, KMIP_TAG_UNIQUE_IDENTIFIER, item->data);
        CHECK_RESULT(ctx, result);

        tag = kmip_peek_tag(ctx);
    }

    return(KMIP_OK);
}


void
kmip_copy_locate_result(LocateResponse* locate_result, LocateResponsePayload *pld)
{
    if(pld != NULL)
    {
        locate_result->located_items = pld->located_items;

        kmip_copy_unique_ids(locate_result->ids, &locate_result->ids_size, pld->unique_ids, MAX_LOCATE_IDS);
    }
}




