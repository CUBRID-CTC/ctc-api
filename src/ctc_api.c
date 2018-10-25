#include "ctc_core.h"

int ctc_open_connection (int connection_type, char *connection_string)
{
    int ctc_handle;

    pthread_once (&ctc_api_once_init, ctc_api_init);

    if (connection_type != CTC_CONN_TYPE_DEFAULT &&
        connection_type != CTC_CONN_TYPE_CTRL_ONLY)
    {
        goto error;
    }

    if (IS_NULL (connection_string))
    {
        goto error;
    }

    if (IS_FAILURE (connect_server (connection_type, connection_string, &ctc_handle)))
    {
        goto error;
    }

    return ctc_handle;

error:

    return CTC_FAILURE;
}

int ctc_close_connection (int ctc_handle)
{
    if (IS_FAILURE (disconnect_server (ctc_handle)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_add_job (int ctc_handle)
{
    if (IS_FAILURE (add_job (ctc_handle)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_delete_job (int ctc_handle, int job_descriptor)
{
    if (IS_FAILURE (delete_job (ctc_handle, job_descriptor)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_check_server_status (int ctc_handle, int *server_status)
{
    if (IS_NULL (server_status))
    {
        goto error;
    }

    if (IS_FAILURE (check_server_status (ctc_handle, server_status)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_register_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name)
{
    if (IS_NULL (db_user_name) || IS_NULL (table_name))
    {
        goto error;
    }

    if (IS_FAILURE (register_table (ctc_handle, job_descriptor, db_user_name, table_name)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_unregister_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name)
{
    if (IS_NULL (db_user_name) || IS_NULL (table_name))
    {
        goto error;
    }

    if (IS_FAILURE (unregister_table (ctc_handle, job_descriptor, db_user_name, table_name)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_start_capture (int ctc_handle, int job_descriptor)
{
    if (IS_FAILURE (start_capture (ctc_handle, job_descriptor)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_stop_capture (int ctc_handle, int job_descriptor, int close_condition)
{
    if (close_condition != CTC_QUIT_JOB_IMMEDIATELY &&
        close_condition != CTC_QUIT_JOB_AFTER_TRANSACTION)
    {
        goto error;
    }

    if (IS_FAILURE (stop_capture (ctc_handle, job_descriptor, close_condition)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

// required_buffer_size --> result_data_size 로 변경
// return success 를 3개로 분류
// success --> transaction 완성
// success fragmented --> 더 읽어야 완성
// success but no data --> 읽을 데이터가 없다.
int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char *result_buffer, int result_buffer_size, int* result_data_size)
{
    if (IS_NULL (result_buffer) || IS_NULL (result_data_size) ||
        result_buffer_size <= 0)
    {
        goto error;
    }

    if (IS_FAILURE (fetch_capture_transaction (ctc_handle, job_descriptor, result_buffer, result_buffer_size, result_data_size)))
    {
        goto error;
    }

    return CTC_SUCCESS;
}

int ctc_check_job_status (int ctc_handle, int job_descriptor, int *job_status)
{
    if (IS_NULL (job_status))
    {
        goto error;
    }

    if (IS_FAILURE (check_job_status (ctc_handle, job_descriptor, job_status)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int ctc_set_job_attribute (int ctc_handle, int job_descriptor, int job_attr_id)
{
    return CTC_SUCCESS;
}

int ctc_get_statistics (int ctc_handle, int job_descriptor, int stat_id, int *stat_value)
{
    return CTC_SUCCESS;
}

