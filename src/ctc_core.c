#include "ctc_core.h"
#include "ctc_network.h"

pthread_once_t ctc_api_once_init = PTHREAD_ONCE_INIT;

CTC_HANDLE ctc_pool[MAX_CTC_HANDLE_COUNT];

void ctc_api_init (void)
{
    int i, j;

    for (i = 0; i < MAX_CTC_HANDLE_COUNT; i ++)
    {
        ctc_pool[i].ID = i;
        ctc_pool[i].session_gid = -1;

        for (j = 0; j < MAX_JOB_HANDLE_COUNT; j ++)
        {
            ctc_pool[i].job_pool[j].ID = j;
            ctc_pool[i].job_pool[j].job_desc = -1;
        }
    }
}

int alloc_ctc_handle (CTC_HANDLE** ctc_handle_p)
{
    int i;

    *ctc_handle_p = NULL;

    for (i = 0; i < MAX_CTC_HANDLE_COUNT; i ++)
    {
        if (ctc_pool[i].session_gid == -1)
        {
            *ctc_handle_p = &ctc_pool[i];
            
            break;
        }
    }

    if (IS_NULL (*ctc_handle_p))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int free_ctc_handle (CTC_HANDLE* ctc_handle_p)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void set_conn_type (CTC_HANDLE* ctc_handle, CONN_TYPE conn_type)
{
    ctc_handle->conn_type = conn_type;
}

int connect_server (CONN_TYPE conn_type, char* conn_str, int* ctc_handle_id)
{
    CTC_HANDLE* ctc_handle;

    int server_ip;
    short server_port;

    int state = 0;

    if (IS_FAILURE (alloc_ctc_handle (&ctc_handle)))
    {
        goto error;
    }

    state = 1;

    // parsing conn_str

    if (IS_FAILURE (open_control_session (ctc_handle, server_ip, server_port)))
    {
        goto error;
    }

    if (conn_type != CTC_CONN_TYPE_CTRL_ONLY)
    {
        if (IS_FAILURE (open_job_session (ctc_handle, server_ip, server_port)))
        {
            goto error;
        }
    }

    set_conn_type (ctc_handle, conn_type);

    *ctc_handle_id = ctc_handle->ID;

    return CTC_SUCCESS;

error:

    switch (state)
    {
        case 1:
            free_ctc_handle (ctc_handle);
        default:
            break;
    }

    return CTC_FAILURE;
}

#if 0
    if (IS_FAILURE (
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}
#endif
