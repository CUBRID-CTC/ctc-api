#include <regex.h>
#include "ctc_core.h"

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

int alloc_ctc_handle (CTC_HANDLE **ctc_handle_p)
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

int free_ctc_handle (CTC_HANDLE *ctc_handle)
{
    JOB_SESSION *job_session;
    int i;

    for (i = 0; i < MAX_JOB_HANDLE_COUNT; i ++)
    {
        job_session = &ctc_handle->job_pool[i].job_session;

        if (job_session->job_desc != -1)
        {
            /* stop & destroy job thread */

            /* cleanup resource used by job thread */

            /* close the socket of job session */
            if (IS_FAILURE (close_job_session_socket_only (job_session)))
            {
                goto error;
            }
        }
    }

    ctc_handle->control_session.session_gid = -1;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int alloc_job_handle (CTC_HANDLE *ctc_handle, JOB_HANDLE **job_handle_p)
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

int free_job_handle (JOB_HANDLE *job_handle)
{
    job_handle->job_session.job_desc = -1;

    return CTC_SUCCESS;
}

int find_ctc_handle (int ctc_handle_id, CTC_HANDLE **ctc_handle_p)
{
    CTC_HANDLE *ctc_handle;

    ctc_handle = &ctc_pool[ctc_handle_id];

    if (ctc_handle->control_session.session_gid == -1)
    {
        goto error;
    }

    *ctc_handle_p = ctc_handle;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int find_job_handle (CTC_HANDLE *ctc_handle, int job_handle_id, JOB_HANDLE **job_handle_p)
{
    JOB_HANDLE *job_handle;

    job_handle = &ctc_handle->job_pool[job_handle_id];

    if (job_handle->job_session.job_desc == -1)
    {
        goto error;
    }

    *job_handle_p = job_handle;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int validate_url (char *url, CTC_HANDLE *ctc_handle)
{
    char *url_pattern = "^[[:blank:]]*ctc:cubrid:([[:digit:]]{1,3}.[[:digit:]]{1,3}.[[:digit:]]{1,3}.[[:digit:]]{1,3}):([[:digit:]]{1,5})[[:blank:]]*$";

    regex_t reg;
    regmatch_t match[3];

    if (IS_FAILURE (regcomp (&reg, url_pattern, REG_ICASE | REG_EXTENDED)))
    {
        goto error;
    }

    if (IS_FAILURE (regexec (&reg, url, 3, match, 0)))
    {
        goto error;
    }

    /* ip */
    memset (ctc_handle->control_session.ip, 0, sizeof (ctc_handle->control_session.ip));
    memcpy (ctc_handle->control_session.ip, url + match[1].rm_so, match[1].rm_eo - match[1].rm_so);

    /* port */
    ctc_handle->control_session.port = (unsigned short)strtol (url + match[2].rm_so, NULL, 10);

    regfree (&reg);

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int connect_server (CTC_CONN_TYPE conn_type, char *url, int *ctc_handle_id)
{
    CTC_HANDLE *ctc_handle;

    int state = 0;

    if (IS_FAILURE (alloc_ctc_handle (&ctc_handle)))
    {
        goto error;
    }

    state = 1;

    if (IS_FAILURE (validate_url (url, ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (open_control_session (&ctc_handle->control_session, conn_type)))
    {
        goto error;
    }

    state = 2;

    *ctc_handle_id = ctc_handle->ID;

    return CTC_SUCCESS;

error:

    switch (state)
    {
        case 2:
            close_control_session (&ctc_handle->control_session);
        case 1:
            free_ctc_handle (ctc_handle);
        default:
            break;
    }

    return CTC_FAILURE;
}

int disconnect_server (int ctc_handle_id)
{
    CTC_HANDLE *ctc_handle;

    int state = 0;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    state = 1;

    if (IS_FAILURE (close_control_session (&ctc_handle->control_session)))
    {
        goto error;
    }

    state = 2;

    if (IS_FAILURE (free_ctc_handle (ctc_handle)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    switch (state)
    {
        case 1:
            close_control_session (&ctc_handle->control_session);
        case 2:
            free_ctc_handle (ctc_handle);
        default:
            break;
    }

    return CTC_FAILURE;
}

int add_job (int ctc_handle_id)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    int state = 0;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (alloc_job_handle (ctc_handle, &job_handle)))
    {
        goto error;
    }

    state = 1;

    if (IS_FAILURE (open_job_session (&ctc_handle->control_session, &job_handle->job_session)))
    {
        goto error;
    }

    state = 2;

    return CTC_SUCCESS;

error:

    switch (state)
    {
        case 2:
            close_job_session (&ctc_handle->control_session, &job_handle->job_session);
        case 1:
            free_job_handle (job_handle);
        default:
            break;
    }

    return CTC_FAILURE;
}

int delete_job (int ctc_handle_id, int job_handle_id)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    int state = 0;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    state = 1;

    if (IS_FAILURE (close_job_session (&ctc_handle->control_session, &job_handle->job_session)))
    {
        goto error;
    }

    state = 2;

    if (IS_FAILURE (free_job_handle (job_handle)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    switch (state)
    {
        case 1:
            close_job_session (&ctc_handle->control_session, &job_handle->job_session);
        case 2:
            free_job_handle (job_handle);
        default:
            break;
    }

    return CTC_FAILURE;
}

int check_server_status (int ctc_handle_id, int *server_status)
{
    CTC_HANDLE *ctc_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (get_server_status (&ctc_handle->control_session, server_status)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int register_table (int ctc_handle_id, int job_handle_id, char *db_user, char *table_name)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (register_table_to_job (&ctc_handle->control_session, &job_handle->job_session, db_user, table_name)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int unregister_table (int ctc_handle_id, int job_handle_id, char *db_user, char *table_name)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (unregister_table_from_job (&ctc_handle->control_session, &job_handle->job_session, db_user, table_name)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void init_json_type_result (JSON_TYPE_RESULT *json_type_result)
{
    int i;

    for (i = 0; i < MAX_JSON_TYPE_RESULT_COUNT; i ++)
    {
        json_type_result->json[i] = NULL;
    }

    json_type_result->write_idx = 0;
    json_type_result->read_idx = 0;
    json_type_result->is_fragmented = false;
}

int cleanup_json_type_result (JSON_TYPE_RESULT *json_type_result)
{
    int i;

    for (i = 0; i < MAX_JSON_TYPE_RESULT_COUNT; i ++)
    {
        if (IS_NOT_NULL (json_type_result->json[i]))
        {
            free (json_type_result->json[i]);
            json_type_result->json[i] = NULL;
        }
    }

    json_type_result->write_idx = 0;
    json_type_result->read_idx = 0;
    json_type_result->is_fragmented = false;

    return CTC_SUCCESS;
}

int start_capture (int ctc_handle_id, int job_handle_id)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (start_capture_for_job (&ctc_handle->control_session, &job_handle->job_session)))
    {
        goto error;
    }

    init_json_type_result (&job_handle->json_type_result);

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int stop_capture (int ctc_handle_id, int job_handle_id, CTC_QUIT_JOB_CONDITION quit_job_condition)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (stop_capture_for_job (&ctc_handle->control_session, &job_handle->job_session, quit_job_condition)))
    {
        goto error;
    }

    if (quit_job_condition == CTC_QUIT_JOB_IMMEDIATELY)
    {
        if (IS_FAILURE (cleanup_json_type_result (&job_handle->json_type_result)))
        {
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

bool is_exist_json_type_result (JSON_TYPE_RESULT *json_type_result)
{
    if (json_type_result->read_idx < json_type_result->write_idx)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int copy_json_type_result_to_user_buffer (JSON_TYPE_RESULT *json_type_result, char *buffer, int buffer_size, int *data_size, bool *is_fragmented)
{
    char *json;
    int json_len;

    int remaining_buffer_size;

    remaining_buffer_size = buffer_size;

    while (json_type_result->read_idx < json_type_result->write_idx)
    {
        json = json_type_result->json[json_type_result->read_idx];
        json_len = strlen (json);

        if (json_len < remaining_buffer_size)
        {
            memcpy (buffer, json, json_len);
            buffer += json_len;

            remaining_buffer_size -= json_len;

            json_type_result->read_idx ++;
        }
        else
        {
            // 사용자 버퍼 크기가 적어서 데이터를 다 못 담는 경우는 무조건 fragmented
            break;
        }
    }

    // 변환된 모든 데이터를 다 읽은 경우
    // if (ctcp_packet == fragmented)
    // then
    //     fragmented
    // else
    //     no fragmented
    if (json_type_result->read_idx == json_type_result->write_idx)
    {
        *is_fragmented = json_type_result->is_fragmented;
    }
    else
    {
        *is_fragmented = true;
    }

    *data_size = buffer_size - remaining_buffer_size;

    return CTC_SUCCESS;
}

int read_capture_transaction (int ctc_handle_id, int job_handle_id, char *buffer, int buffer_size, int *data_size, bool *is_fragmented)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    *data_size = 0;
    *is_fragmented = false;

    // 이미 변환되어 남이있는 json 결과들이 있는가?
    if (is_exist_json_type_result (&job_handle->json_type_result))
    {
        if (IS_FAILURE (copy_json_type_result_to_user_buffer (&job_handle->json_type_result, buffer, buffer_size, data_size, is_fragmented)))
        {
            goto error;
        }
    }
    else
    {
        if (IS_FAILURE (read_capture_transaction_in_json (&job_handle->job_session, &job_handle->json_type_result)))
        {
            goto error;
        }

        if (is_exist_json_type_result (&job_handle->json_type_result))
        {
            if (IS_FAILURE (copy_json_type_result_to_user_buffer (&job_handle->json_type_result, buffer, buffer_size, data_size, is_fragmented)))
            {
                goto error;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_job_status (int ctc_handle_id, int job_handle_id, int *job_status)
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;

    if (IS_FAILURE (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (find_job_handle (ctc_handle, job_handle_id, &job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (get_job_status (&ctc_handle->control_session, &job_handle->job_session, job_status)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

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
