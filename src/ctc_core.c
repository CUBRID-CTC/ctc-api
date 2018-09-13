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
        ctc_pool[i].control_session.session_gid = -1;

        for (j = 0; j < MAX_JOB_HANDLE_COUNT; j ++)
        {
            ctc_pool[i].job_pool[j].ID = j;
            ctc_pool[i].job_pool[j].job_session.job_desc = -1;
        }
    }
}

int validate_url (CTC_HANDLE* ctc_handle, char* url)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int alloc_ctc_handle (CTC_HANDLE** ctc_handle_p)
{
    int i;

    *ctc_handle_p = NULL;

    for (i = 0; i < MAX_CTC_HANDLE_COUNT; i ++)
    {
        if (ctc_pool[i].control_session.session_gid == -1)
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

int free_ctc_handle (CTC_HANDLE* ctc_handle)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int alloc_job_handle (CTC_HANDLE* ctc_handle, JOB_HANDLE** job_handle_p)
{
    int i;

    *job_handle_p = NULL;

    for (i = 0; i < MAX_JOB_HANDLE_COUNT; i ++)
    {
        if (ctc_handle->job_pool[i].job_session.job_desc == -1)
        {
            *job_handle_p = &ctc_handle->job_pool[i];
            
            break;
        }
    }

    if (IS_NULL (*job_handle_p))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int free_job_handle (CTC_HANDLE* ctc_handle, JOB_HANDLE* job_handle)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void set_conn_type (CTC_HANDLE* ctc_handle, CONN_TYPE conn_type)
{
    ctc_handle->conn_type = conn_type;
}

int connect_server (CONN_TYPE conn_type, char* url, int* ctc_handle_id)
{
    CTC_HANDLE* ctc_handle;
    JOB_HANDLE* job_handle;

    int state = 0;

    if (IS_FAILURE (alloc_ctc_handle (&ctc_handle)))
    {
        goto error;
    }

    state = 1;

    if (IS_FAILURE (validate_url (ctc_handle, url)))
    {
        goto error;
    }

    // cci:CUBRID:<host>:<port>:<db_name>:<db_user>:<db_password>:[?<properties>]
    // // ex) cci:CUBRID:192.168.0.1:33000
    // jdbc:cubrid:<host>:<port>:<db-name>:[user-id]:[password]:[?<property> [& <property>] ... ]
    // ctc:cubrid:
    //    ex) ctc:cubrid:ip:port
    // parsing conn_str
    // "cci:cubrid(-oracle|-mysql)?:([a-zA-Z_0-9\\.-]*):([0-9]*)

    if (IS_FAILURE (open_control_session (ctc_handle->control_session, conn_type)))
    {
        goto error;
    }

    if (conn_type != CTC_CONN_TYPE_CTRL_ONLY)
    {
        if (IS_FAILURE (alloc_job_handle (ctc_handle, &job_handle)))
        {

        }

        state = 2;

        if (IS_FAILURE (open_job_session (ctc_handle->control_session, job_handle->job_session)))
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
        case 2:
            free_job_handle (ctc_handle, job_handle);
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
