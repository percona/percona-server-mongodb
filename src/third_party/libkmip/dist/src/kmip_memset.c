/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
* All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#include "kmip_memset.h"

#if defined __STDC_LIB_EXT1__

#define __STDC_WANT_LIB_EXT1__ 1
#include <string.h>

void *
kmip_memset(void *ptr, int value, size_t size)
{
    if(ptr == NULL)
    {
        return(ptr);
    }
    
    memset_s(ptr, size, value, size);
    return(ptr);
}

#else

void *
kmip_base_memset(void *ptr, int value, size_t size)
{
    if(ptr != NULL)
    {
        unsigned char *index = (unsigned char*)ptr;
        for(size_t i = 0; i < size; i++)
        {
            *index++ = (unsigned char)value;
        }
    }
    
    return(ptr);
}

static void *
(* volatile kmip_indirect_memset)(void *, int, size_t) = kmip_base_memset;

void *
kmip_memset(void *ptr, int value, size_t size)
{
    if(ptr != NULL)
    {
        kmip_indirect_memset(ptr, value, size);
    }
    
    return(ptr);
}

#endif
