


// Object Group Member Option
enum group_member_option
{
    group_member_fresh       =  0x00000001,
    group_member_default     =  0x00000002
};


//Extensions                 0x8XXXXXXX

/*

4.35 Object Group

A Managed Object MAY be part of a group of objects. An object MAY belong to more than one group of objects.
To assign an object to a group of objects, the object group name SHOULD be set into this attribute.

Item                   Encoding
Object Group           Text String

*/

/*
Request Payload

Item                    REQUIRED    Description
Maximum Items           No          An Integer object that indicates the maximum number of object identifiers the server MAY return.
Offset Items            No          An Integer object that indicates the number of object identifiers to skip that satisfy the identification criteria specified in the request.
Storage Status Mask     No          An Integer object (used as a bit mask) that indicates whether only on-line objects, only archived objects, destroyed objects or any combination of these, are to be searched. If omitted, then only on-line objects SHALL be returned.
Object Group Member     No          An Enumeration object that indicates the object group member type.
Attributes              Yes         Specifies an attribute and its value(s) that are REQUIRED to match those in a candidate object (according to the matching rules defined above).

Note: the Attributes structure MAY be empty indicating all objects should match.

*/


/*

When the Object Group attribute and the Object Group Member flag are specified in the request,
and the value specified for Object Group Member is ‘Group Member Fresh’,
matching candidate objects SHALL be fresh objects from the object group.

If there are no more fresh objects in the group, the server MAY choose to generate a new object on-the-fly,
based on server policy. If the value specified for Object Group Member is ‘Group Member Default’,
the server locates the default object as defined by server policy.


*/

typedef struct locate_request_payload
{
    int32  maximum_items;      // An Integer object that indicates the maximum number of object identifiers the server MAY return.
    int32  offset_items;       // An Integer object that indicates the number of object identifiers to skip that satisfy the identification criteria specified in the request.
    int32  storage_status_mask; // An Integer object (used as a bit mask) that indicates whether only on-line objects, only archived objects, destroyed objects or any combination of these, are to be searched. If omitted, then only on-line objects SHALL be returned.
    enum   group_member_option group_member_option; // An Enumeration object that indicates the object group member type.
    LinkedList* attribute_list; // Specifies an attribute and its value(s) that are REQUIRED to match those in a candidate object (according to the matching rules defined above).
} LocateRequestPayload;


typedef struct unique_identifiers
{
    LinkedList *unique_identifier_list;
} UniqueIdentifiers;

typedef struct locate_response_payload
{
    int32 located_items;
    UniqueIdentifiers* unique_ids;
} LocateResponsePayload;


#define MAX_LOCATE_IDS   32
#define MAX_LOCATE_LEN   128

typedef struct locate_response
{
    int              located_items;
    size_t           ids_size;
    char             ids[MAX_LOCATE_IDS][MAX_LOCATE_LEN];
} LocateResponse;

void kmip_print_locate_request_payload(FILE*, int, LocateRequestPayload *);
void kmip_free_locate_request_payload(KMIP *, LocateRequestPayload *);
int kmip_compare_locate_request_payload(const LocateRequestPayload *, const LocateRequestPayload *);
int kmip_encode_locate_request_payload(KMIP *, const LocateRequestPayload *);
int kmip_decode_locate_request_payload(KMIP *, LocateRequestPayload *);

void kmip_print_locate_response_payload(FILE*, int, LocateResponsePayload *);
void kmip_free_locate_response_payload(KMIP *, LocateResponsePayload *);
int kmip_compare_locate_response_payload(const LocateResponsePayload *, const LocateResponsePayload *);
int kmip_encode_locate_response_payload(KMIP *, const LocateResponsePayload *);
int kmip_decode_locate_response_payload(KMIP *, LocateResponsePayload *);



void kmip_print_unique_identifiers(FILE*, int indent, UniqueIdentifiers* value);
void kmip_free_unique_identifiers(KMIP *ctx, UniqueIdentifiers* value);
int kmip_decode_unique_identifiers(KMIP* ctx, UniqueIdentifiers* value);


void kmip_copy_locate_result(LocateResponse* locate_result, LocateResponsePayload *pld);

