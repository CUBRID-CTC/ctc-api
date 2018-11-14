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
            ctc_handle_pool[i].job_desc_pool[j].job_session.job_thread.is_thr_alive = false;

            ctc_handle_pool[i].job_desc_pool[j].json_result.result_array = NULL;
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

void free_job_desc (JOB_DESC *job_desc)
{
    if (job_desc->job_session.job_thread.is_thr_alive == true)
    {
        (void)request_stop_capture (NULL, &job_desc->job_session, CTC_JOB_CLOSE_IMMEDIATELY, false);
    }

    if (job_desc->job_session.job_desc != INITIAL_JOB_DESC)
    {
        (void)close_job_session (NULL, &job_desc->job_session, false); // 정상 루틴 수행시 close (socket) 여러번
        job_desc->job_session.job_desc = INITIAL_JOB_DESC;
    }

    if (IS_NOT_NULL (job_desc->json_result.result_array))
    {
        json_decref (job_desc->json_result.result_array);
        job_desc->json_result.result_array = NULL;
    }
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

void free_ctc_handle (CTC_HANDLE *ctc_handle)
{
    int i;

    for (i = 0; i < JOB_DESC_MAX_COUNT; i ++)
    {
        free_job_desc (&ctc_handle->job_desc_pool[i]);
    }

    ctc_handle->control_session.session_gid = INITIAL_SESSION_GID;
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

    int state = 0;

    if (IS_FAILED (regcomp (&reg, url_pattern, REG_ICASE | REG_EXTENDED)))
    {
        goto error;
    }

    state = 1;

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

    if (state)
    {
        regfree (&reg);
    }

    return CTC_FAILED_INVALID_CONNECTION_STRING;
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

    free_ctc_handle (ctc_handle);

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

    retval = close_job_session (&ctc_handle->control_session, &job_desc->job_session, true);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    free_job_desc (job_desc);

    return CTC_SUCCESS;

error:

    if (state)
    {
        free_job_desc (job_desc);
    }

    return retval;
}

int check_server_status (int ctc_handle_id, CTC_SERVER_STATUS *server_status)
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

int init_json_result (JSON_RESULT *json_result)
{
    int i;

    for (i = 0; i < JSON_ARRAY_SIZE; i ++)
    {
        json_result->json[i] = NULL;
    }

    json_result->json_read_idx = 0;
    json_result->is_fragmented = false;

    json_result->result_array = json_array ();
    if (IS_NULL (json_result->result_array))
    {
        return CTC_FAILED_JANSSON_EXTERNAL_LIBRARY;
    }

    return CTC_SUCCESS;
}

void clean_json_result (JSON_RESULT *json_result, bool is_free_result_array)
{
    int i;

    for (i = 0; i < JSON_ARRAY_SIZE; i ++) // read_idx == 0 인 경우 수행할 필요 없다. 다 안읽고 종료하는 경우에 대한 방어코드
    {
        if (IS_NOT_NULL (json_result->json[i]))
        {
            json_decref (json_result->json[i]);
            json_result->json[i] = NULL;
        }
    }

    json_result->json_read_idx = 0;
    json_result->is_fragmented = false;

    if (is_free_result_array)
    {
        json_decref (json_result->result_array);
        json_result->result_array = NULL;
    }
    else
    {
        json_array_clear (json_result->result_array);
    }
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

    retval = init_json_result (&job_desc->json_result);
    if (IS_FAILED (retval))
    {
        goto error;
    }

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

    retval = request_stop_capture (&ctc_handle->control_session, &job_desc->job_session, job_close_condition, true);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    clean_json_result (&job_desc->json_result, true);

    return CTC_SUCCESS;

error:

    return retval;
}

int read_json (JOB_DESC *job_desc, char *buffer, int buffer_size, int *data_size)
{
    JSON_RESULT *json_result;
    json_t *json;

    json_t *result_array;

    int result_size;

    json_result = &job_desc->json_result;
    json = json_result->json[json_result->json_read_idx];

    if (IS_NULL (json))
    {
        return CTC_SUCCESS_NO_DATA;
    }

    result_array = json_result->result_array;

    while (IS_NOT_NULL (json))
    {
        json_array_append (result_array, json);

        result_size = json_dumpb (result_array, NULL, 0, 0);

        if (result_size < buffer_size)
        {
            json_result->json_read_idx ++;
            json = json_result->json[json_result->json_read_idx];
        }
        else if (result_size == buffer_size)
        {
            json_result->json_read_idx ++;
            break;
        }
        else
        {
            /* buffer overflow */
            json_array_remove (result_array, json_array_size (result_array) - 1);
            break;
        }
    }

    if (json_array_size (result_array) == 0)
    {
        /* minimum required buffer size */
        *data_size = json_dumpb (json, NULL, 0, 0) + 2;

        return CTC_FAILED_TOO_SMALL_RESULT_BUFFER_SIZE;
    }

    *data_size = json_dumpb (result_array, buffer, buffer_size, 0);

#if defined(DEBUG)
    assert (*data_size <= buffer_size);
#endif

    if (json_result->is_fragmented == true)
    {
        return CTC_SUCCESS_FRAGMENTED;
    }
    else
    {
        json = json_result->json[json_result->json_read_idx];

        if (IS_NOT_NULL (json))
        {
            return CTC_SUCCESS_FRAGMENTED;
        }
        else
        {
            return CTC_SUCCESS;
        }
    }
}

int fetch_capture_transaction (int ctc_handle_id, int job_desc_id, char *buffer, int buffer_size, int *data_size)
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

    // job thread가 비정상 종료했는지 검사
    json_array_clear (job_desc->json_result.result_array); // fetch가 호출될 때마다 버퍼 clear 필요

    retval = read_json (job_desc, buffer, buffer_size, data_size);
    if (IS_FAILED (retval))
    {
        goto error;
    }
    else
    {
        if (retval == CTC_SUCCESS_NO_DATA)
        {
            clean_json_result (&job_desc->json_result, false);

            retval = convert_capture_transaction_to_json (&job_desc->job_session.capture_data, &job_desc->json_result);
            if (IS_FAILED (retval))
            {
                goto error;
            }

            if (retval != CTC_SUCCESS_NO_DATA)
            {
                retval = read_json (job_desc, buffer, buffer_size, data_size);
                if (IS_FAILED (retval))
                {
                    goto error;
                }
            }
        }
    }

error:

    return retval;
}

int check_job_status (int ctc_handle_id, int job_desc_id, CTC_JOB_STATUS *job_status)
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
