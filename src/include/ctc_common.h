#ifndef _CTC_COMMON_H_
#define _CTC_COMMON_H_

#include "ctc_api.h"
#include "ctc_error.h"

#define IS_SUCCESS(a)  (a == CTC_SUCCESS)
#define IS_FAILED(a)   (a != CTC_SUCCESS && a != CTC_SUCCESS_FRAGMENTED && a != CTC_SUCCESS_NO_DATA)

#define IS_NULL(a)     (a == NULL)
#define IS_NOT_NULL(a) (a != NULL)

typedef enum
{
    false,
    true
} bool;

#endif
