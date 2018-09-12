#ifndef _CTC_API_H_
#define _CTC_API_H_

#include <pthread.h>
#include "ctc_common.h"

#define MAX_CTC_HANDLE_COUNT 100 /* CTC_SESSION_GROUP_MAX */
#define MAX_JOB_HANDLE_COUNT 10

typedef enum connection_type CONN_TYPE;
enum connection_type
{
    CTC_CONN_TYPE_DEFAULT,
    CTC_CONN_TYPE_CTRL_ONLY
};

typedef struct job_handle JOB_HANDLE;
struct job_handle
{
    int ID;

    int job_desc; /* receive from ctc_server */

    int job_sd;
};

typedef struct ctc_handle CTC_HANDLE;
struct ctc_handle
{
    int ID;

    int session_gid; /* receive from ctc_server */

    CONN_TYPE conn_type;

    int control_sd;

    JOB_HANDLE job_pool[MAX_JOB_HANDLE_COUNT];
};

extern pthread_once_t ctc_api_once_init;

void ctc_api_init (void);
int connect_server (CONN_TYPE, char*, int*);

#endif
