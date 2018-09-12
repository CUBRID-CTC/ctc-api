#include "ctc_core.h"

int ctc_open_connection (int connection_type, char* connection_string)
{
    int ctc_handle_id;

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

    if (IS_FAILURE (connect_server (connection_type, connection_string, &ctc_handle_id)))
    {
        goto error;
    }

    return ctc_handle_id;

error:

    return CTC_FAILURE;
}

int ctc_close_connection (int ctc_handle, int close_condition)
{

    return CTC_SUCCESS;
}

int ctc_add_job (int ctc_handle)
{

    return CTC_SUCCESS;
}

int ctc_delete_job (int ctc_handle, int job_descriptor)
{

    return CTC_SUCCESS;
}

int ctc_check_server_status (int ctc_handle)
{

    return CTC_SUCCESS;
}

int ctc_register_table (int ctc_handle, int job_descriptor, char* db_user_name, char* table_name)
{

    return CTC_SUCCESS;
}

int ctc_unregister_table (int ctc_handle, int job_descriptor, char* db_user_name, char* table_name)
{

    return CTC_SUCCESS;
}

int ctc_start_capture (int ctc_handle, int job_descriptor)
{

    return CTC_SUCCESS;
}

int ctc_stop_capture (int ctc_handle, int job_descriptor)
{

    return CTC_SUCCESS;
}

int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char* result_buffer, int result_buffer_size, int* required_buffer_size)
{

    return CTC_SUCCESS;
}

int ctc_check_job_status (int ctc_handle, int job_descriptor)
{

    return CTC_SUCCESS;
}

int ctc_set_job_attribute (int ctc_handle, int job_descriptor, int job_attr_id)
{

    return CTC_SUCCESS;
}

int ctc_get_statistics (int ctc_handle, int job_descriptor, int stat_id)
{

    return CTC_SUCCESS;
}
