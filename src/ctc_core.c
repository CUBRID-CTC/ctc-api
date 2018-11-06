#include <regex.h>
#include "ctc_core.h"

pthread_once_t ctc_api_once_init = PTHREAD_ONCE_INIT;

CTC_HANDLE ctc_handle_pool[CTC_HANDLE_MAX_COUNT];

void ctc_api_init (void)
{
    int i, j;

    for (i = 0; i < CTC_HANDLE_MAX_COUNT; i ++)
    {
        ctc_handle_pool[i].control_session.session_gid = INITIAL_SESSION_GID;

        for (j = 0; j < JOB_DESC_MAX_COUNT; j ++)
        {
            ctc_handle_pool[i].job_desc_pool[j].job_session.job_desc = INITIAL_JOB_DESC;
        }
    }
}

int alloc_job_desc (CTC_HANDLE *ctc_handle, JOB_DESC **job_desc_p, int *job_desc_id)
{
    int i;

    *job_desc_p = NULL;

    for (i = 0; i < JOB_DESC_MAX_COUNT; i ++)
    {
        if (ctc_handle->job_desc_pool[i].job_session.job_desc == INITIAL_JOB_DESC)
        {
            *job_desc_p  = &ctc_handle->job_desc_pool[i];
            *job_desc_id = i;
            
            break;
        }
    }

    if (IS_NULL (*job_desc_p))
    {
        return CTC_FAILED_ALLOC_JOB_DESC;
    }

    return CTC_SUCCESS;
}

int free_job_desc (JOB_DESC *job_desc)
{
    job_desc->job_session.job_desc = INITIAL_JOB_DESC;

    return CTC_SUCCESS;
}

int alloc_ctc_handle (CTC_HANDLE **ctc_handle_p, int *ctc_handle_id)
{
    int i;

    *ctc_handle_p = NULL;

    for (i = 0; i < CTC_HANDLE_MAX_COUNT; i ++)
    {
        if (ctc_handle_pool[i].control_session.session_gid == INITIAL_SESSION_GID)
        {
            *ctc_handle_p  = &ctc_handle_pool[i];
            *ctc_handle_id = i;
            
            break;
        }
    }

    if (IS_NULL (*ctc_handle_p))
    {
        return CTC_FAILED_ALLOC_CTC_HANDLE;
    }

    return CTC_SUCCESS;
}

int free_ctc_handle (CTC_HANDLE *ctc_handle)
{
    int i;

    for (i = 0; i < JOB_DESC_MAX_COUNT; i ++)
    {
        free_job_desc (&ctc_handle->job_desc_pool[i]);
    }

    ctc_handle->control_session.session_gid = INITIAL_SESSION_GID;

    return CTC_SUCCESS;
}

int find_ctc_handle (int ctc_handle_id, CTC_HANDLE **ctc_handle_p)
{
    CTC_HANDLE *ctc_handle;

    if (ctc_handle_id < 0 || ctc_handle_id >= CTC_HANDLE_MAX_COUNT)
    {
        return CTC_FAILED_INVALID_CTC_HANDLE;
    }

    ctc_handle = &ctc_handle_pool[ctc_handle_id];

    if (ctc_handle->control_session.session_gid == INITIAL_SESSION_GID)
    {
        return CTC_FAILED_INVALID_CTC_HANDLE;
    }

    *ctc_handle_p = ctc_handle;

    return CTC_SUCCESS;
}

int find_job_desc (CTC_HANDLE *ctc_handle, int job_desc_id, JOB_DESC **job_desc_p)
{
    JOB_DESC *job_desc;

    if (job_desc_id < 0 || job_desc_id >= JOB_DESC_MAX_COUNT)
    {
        return CTC_FAILED_INVALID_JOB_DESC;
    }

    job_desc = &ctc_handle->job_desc_pool[job_desc_id];

    if (job_desc->job_session.job_desc == INITIAL_JOB_DESC)
    {
        return CTC_FAILED_INVALID_JOB_DESC;
    }

    *job_desc_p = job_desc;

    return CTC_SUCCESS;
}

int parse_url (char *url, CTC_HANDLE *ctc_handle)
{
    char *url_pattern = "^[[:blank:]]*ctc:cubrid:([[:digit:]]{1,3}.[[:digit:]]{1,3}.[[:digit:]]{1,3}.[[:digit:]]{1,3}):([[:digit:]]{1,5})[[:blank:]]*$";

    regex_t reg;
    regmatch_t match[3];

    if (IS_FAILED (regcomp (&reg, url_pattern, REG_ICASE | REG_EXTENDED)))
    {
        goto error;
    }

    if (IS_FAILED (regexec (&reg, url, 3, match, 0)))
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

    return CTC_FAILED_INVALID_CONN_STRING;
}

int open_connection (CTC_CONN_TYPE conn_type, char *url, int *ctc_handle_id)
{
    CTC_HANDLE *ctc_handle;
    int retval;

    int state = 0;

    retval = alloc_ctc_handle (&ctc_handle, ctc_handle_id);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    state = 1;

    retval = parse_url (url, ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = open_control_session (&ctc_handle->control_session, conn_type);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        free_ctc_handle (ctc_handle);
    }

    return retval;
}

int close_connection (int ctc_handle_id)
{
    CTC_HANDLE *ctc_handle;
    int retval;

    int state = 0;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    state = 1;

    retval = close_control_session (&ctc_handle->control_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = free_ctc_handle (ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        free_ctc_handle (ctc_handle);
    }

    return retval;
}

int add_job (int ctc_handle_id, int *job_desc_id)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    int state = 0;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = alloc_job_desc (ctc_handle, &job_desc, job_desc_id);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    state = 1;

    retval = open_job_session (&ctc_handle->control_session, &job_desc->job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        free_job_desc (job_desc);
    }

    return retval;
}

int delete_job (int ctc_handle_id, int job_desc_id)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    int state = 0;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = find_job_desc (ctc_handle, job_desc_id, &job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    state = 1;

    retval = close_job_session (&ctc_handle->control_session, &job_desc->job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = free_job_desc (job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        free_job_desc (job_desc);
    }

    return retval;
}

int check_server_status (int ctc_handle_id, int *server_status)
{
    CTC_HANDLE *ctc_handle;
    int retval;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = request_server_status (&ctc_handle->control_session, server_status);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int register_table (int ctc_handle_id, int job_desc_id, char *user_name, char *table_name)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = find_job_desc (ctc_handle, job_desc_id, &job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = request_register_table (&ctc_handle->control_session, &job_desc->job_session, user_name, table_name);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int unregister_table (int ctc_handle_id, int job_desc_id, char *user_name, char *table_name)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = find_job_desc (ctc_handle, job_desc_id, &job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = request_unregister_table (&ctc_handle->control_session, &job_desc->job_session, user_name, table_name);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
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

int start_capture (int ctc_handle_id, int job_desc_id)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = find_job_desc (ctc_handle, job_desc_id, &job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = request_start_capture (&ctc_handle->control_session, &job_desc->job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    init_json_type_result (&job_desc->json_type_result);

    return CTC_SUCCESS;

error:

    return retval;
}

int stop_capture (int ctc_handle_id, int job_desc_id, CTC_JOB_CLOSE_CONDITION job_close_condition)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = find_job_desc (ctc_handle, job_desc_id, &job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = request_stop_capture (&ctc_handle->control_session, &job_desc->job_session, job_close_condition);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    if (job_close_condition == CTC_JOB_CLOSE_IMMEDIATELY)
    {
        if (IS_FAILED (cleanup_json_type_result (&job_desc->json_type_result)))
        {
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return retval;
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

int read_capture_transaction (int ctc_handle_id, int job_desc_id, char *buffer, int buffer_size, int *data_size, bool *is_fragmented)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;

    if (IS_FAILED (find_ctc_handle (ctc_handle_id, &ctc_handle)))
    {
        goto error;
    }

    if (IS_FAILED (find_job_desc (ctc_handle, job_desc_id, &job_desc)))
    {
        goto error;
    }

    *data_size = 0;
    *is_fragmented = false;

    // 이미 변환되어 남이있는 json 결과들이 있는가?
    if (is_exist_json_type_result (&job_desc->json_type_result))
    {
        if (IS_FAILED (copy_json_type_result_to_user_buffer (&job_desc->json_type_result, buffer, buffer_size, data_size, is_fragmented)))
        {
            goto error;
        }
    }
    else
    {
        if (IS_FAILED (read_capture_transaction_in_json (&job_desc->job_session, &job_desc->json_type_result)))
        {
            goto error;
        }

        if (is_exist_json_type_result (&job_desc->json_type_result))
        {
            if (IS_FAILED (copy_json_type_result_to_user_buffer (&job_desc->json_type_result, buffer, buffer_size, data_size, is_fragmented)))
            {
                goto error;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int check_job_status (int ctc_handle_id, int job_desc_id, int *job_status)
{
    CTC_HANDLE *ctc_handle;
    JOB_DESC *job_desc;
    int retval;

    retval = find_ctc_handle (ctc_handle_id, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = find_job_desc (ctc_handle, job_desc_id, &job_desc);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = request_job_status (&ctc_handle->control_session, &job_desc->job_session, job_status);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

#if 0
    if (IS_FAILED (
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}
#endif
