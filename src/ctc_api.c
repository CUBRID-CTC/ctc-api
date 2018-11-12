#include "ctc_core.h"

int ctc_open_connection (CTC_CONN_TYPE connection_type, char *connection_string)
{
    int ctc_handle;
    int retval;

    pthread_once (&ctc_api_once_init, ctc_api_init);

    if (connection_type != CTC_CONN_TYPE_DEFAULT &&
        connection_type != CTC_CONN_TYPE_CTRL_ONLY)
    {
        retval = CTC_FAILED_INVALID_ARGS;
        goto error;
    }

    if (IS_NULL (connection_string))
    {
        retval = CTC_FAILED_INVALID_ARGS;
        goto error;
    }

    retval = open_connection (connection_type, connection_string, &ctc_handle);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return ctc_handle;

error:

    return retval;
}

int ctc_close_connection (int ctc_handle)
{
    return close_connection (ctc_handle);
}

int ctc_add_job (int ctc_handle)
{
    int job_desc;
    int retval;

    retval = add_job (ctc_handle, &job_desc);
    if (IS_FAILED (retval))
    {
        return retval;
    }

    return job_desc;
}

int ctc_delete_job (int ctc_handle, int job_descriptor)
{
    return delete_job (ctc_handle, job_descriptor);
}

int ctc_check_server_status (int ctc_handle, int *server_status)
{
    if (IS_NULL (server_status))
    {
        return CTC_FAILED_INVALID_ARGS;
    }

    return check_server_status (ctc_handle, server_status);
}

int ctc_register_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name)
{
    if (IS_NULL (db_user_name) || IS_NULL (table_name))
    {
        return CTC_FAILED_INVALID_ARGS;
    }

    return register_table (ctc_handle, job_descriptor, db_user_name, table_name);
}

int ctc_unregister_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name)
{
    if (IS_NULL (db_user_name) || IS_NULL (table_name))
    {
        return CTC_FAILED_INVALID_ARGS;
    }

    return unregister_table (ctc_handle, job_descriptor, db_user_name, table_name);
}

int ctc_start_capture (int ctc_handle, int job_descriptor)
{
    return start_capture (ctc_handle, job_descriptor);
}

int ctc_stop_capture (int ctc_handle, int job_descriptor, CTC_JOB_CLOSE_CONDITION close_condition)
{
    if (close_condition != CTC_JOB_CLOSE_IMMEDIATELY)
    {
        return CTC_FAILED_INVALID_ARGS;
    }

    return stop_capture (ctc_handle, job_descriptor, close_condition);
}

int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char *result_buffer, int result_buffer_size, int *result_size)
{
    if (IS_NULL (result_buffer) || result_buffer_size <= 0 || IS_NULL (result_size))
    {
        return CTC_FAILED_INVALID_ARGS;
    }

    return fetch_capture_transaction (ctc_handle, job_descriptor, result_buffer, result_buffer_size, result_size);
}

int ctc_check_job_status (int ctc_handle, int job_descriptor, int *job_status)
{
    if (IS_NULL (job_status))
    {
        return CTC_FAILED_INVALID_ARGS;
    }

    return check_job_status (ctc_handle, job_descriptor, job_status);
}

#if 0
int ctc_set_job_attribute (int ctc_handle, int job_descriptor, int job_attr_id)
{
    return CTC_SUCCESS;
}

int ctc_get_statistics (int ctc_handle, int job_descriptor, int stat_id, int *stat_value)
{
    return CTC_SUCCESS;
}
#endif

