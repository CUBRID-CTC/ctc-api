#ifndef _CTC_COMMON_H_
#define _CTC_COMMON_H_

#define CTC_SUCCESS 0
#define CTC_FAILURE -1

#define IS_SUCCESS(a) (a == CTC_SUCCESS)
#define IS_FAILURE(a) (a != CTC_SUCCESS)

#define IS_NULL(a) (a == NULL)
#define IS_NOT_NULL(a) (a != NULL)

typedef enum
{
    false,
    true
} bool;

#endif
