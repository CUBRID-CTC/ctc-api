#ifndef _CTC_API_H_
#define _CTC_API_H_

#include <pthread.h>
#include "ctc_common.h"
#include "ctc_network.h"

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

    JOB_SESSION job_session;
};

typedef struct ctc_handle CTC_HANDLE;
struct ctc_handle
{
    int ID;

    CONN_TYPE conn_type;

    CONTROL_SESSION control_session;

    JOB_HANDLE job_pool[MAX_JOB_HANDLE_COUNT];
};

extern pthread_once_t ctc_api_once_init;

void ctc_api_init (void);
int connect_server (CONN_TYPE, char *, int *);

#endif
