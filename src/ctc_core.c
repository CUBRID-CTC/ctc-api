#include <stdlib.h>
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
    // 소켓 정리, 할당된 job 정리

    ctc_handle->control_session.session_gid = -1;

    return CTC_SUCCESS;
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

int connect_server (int conn_type, char *url, int *ctc_handle_id)
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

int get_next_captured_data_write_pos (JOB_HANDLE *job_handle, CAPTURED_DATA **captured_data_p)
{
    job_handle->data_write_idx ++;

    if (job_handle->data_write_idx == MAX_DATA_BUFFER_COUNT)
    {
        job_handle->data_write_idx = 0;
    }

    if (job_handle->data_write_idx == job_handle->data_read_idx)
    {
        // overflow
        goto error;
    }

    *captured_data_p = &job_handle->captured_data_array[job_handle->data_write_idx];

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int get_current_captured_data_write_pos (JOB_HANDLE *job_handle, CAPTURED_DATA **captured_data_p)
{
    *captured_data_p = &job_handle->captured_data_array[job_handle->data_write_idx];

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int alloc_ctc_packet_buffer (CAPTURED_DATA *captured_data)
{
    CTCP *packet_buffer = NULL;

    packet_buffer = captured_data->packet_buffer;
    if (IS_NULL (packet_buffer))
    {
        packet_buffer = (CTCP *)malloc (CTCP_PACKET_SIZE * MAX_PACKET_COUNT_IN_DATA_BUFFER);
        if (IS_NULL (packet_buffer))
        {
            goto error;
        }

        captured_data->packet_buffer = packet_buffer;
    }

    captured_data->packet_write_idx = -1;
    captured_data->packet_read_idx = -1;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int free_ctc_packet_buffer (CAPTURED_DATA *captured_data)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int get_next_ctc_packet_write_pos (JOB_HANDLE *job_handle, CTCP **packet_buffer_p)
{
    CAPTURED_DATA *captured_data;
    CTCP *packet_buffer;

    if (IS_FAILURE (get_current_captured_data_write_pos (job_handle, &captured_data)))
    {
        goto error;
    }

    captured_data->packet_write_idx ++;

    if (captured_data->packet_write_idx == MAX_PACKET_COUNT_IN_DATA_BUFFER)
    {
        captured_data = NULL;

        if (IS_FAILURE (get_next_captured_data_write_pos (job_handle, &captured_data)))
        {
            goto error;
        }

        if (IS_FAILURE (alloc_ctc_packet_buffer (captured_data)))
        {
            goto error;
        }

        captured_data->packet_write_idx ++;
    }

    *packet_buffer_p = &captured_data->packet_buffer[captured_data->packet_write_idx];

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int prepare_capture (JOB_HANDLE *job_handle)
{
    int i;

    for (i = 0; i < MAX_DATA_BUFFER_COUNT; i ++)
    {
        job_handle->captured_data_array[i].packet_buffer = NULL;
        job_handle->captured_data_array[i].packet_write_idx = -1; 
        job_handle->captured_data_array[i].packet_read_idx = -1;
    }

    job_handle->data_write_idx = 0;
    job_handle->data_read_idx = 0;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int execute_capture (JOB_HANDLE *job_handle)
{
    CTCP *packet_buffer;

    while (job_handle->job_thread_is_alive == true)
    {
        if (IS_FAILURE (get_next_ctc_packet_write_pos (job_handle, &packet_buffer)))
        {
            goto error;
        }

        // read
    }

    return CTC_SUCCESS;

error:

    job_handle->job_thread_is_alive = false;

    return CTC_FAILURE;
}

// 자원 할당과 write는 job thread가 수행
// 자원 해제와 read는 main thread에서 수행
void *job_thread_main (void *arg)
{
    JOB_HANDLE *job_handle = (JOB_HANDLE *)arg;

    job_handle->job_thread_is_alive = true;

    if (IS_FAILURE (prepare_capture (job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (execute_capture (job_handle)))
    {
        goto error;
    }

    job_handle->job_thread_is_alive = false;

    return CTC_SUCCESS;

error:

    job_handle->job_thread_is_alive = false;

    return CTC_FAILURE;
}

int create_job_thread (JOB_HANDLE *job_handle)
{
    if (IS_FAILURE (pthread_create (&job_handle->job_thread, NULL, job_thread_main, (void *)job_handle)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
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

    if (IS_FAILURE (create_job_thread (job_handle)))
    {
        goto error;
    }

    if (IS_FAILURE (start_capture_for_job (&ctc_handle->control_session, &job_handle->job_session)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int stop_capture (int ctc_handle_id, int job_handle_id)
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
