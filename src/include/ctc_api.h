#ifndef _CTC_API_H_
#define _CTC_API_H_

typedef enum ctc_connection_type CTC_CONN_TYPE;
enum ctc_connection_type
{
    CTC_CONN_TYPE_DEFAULT   = 0,
    CTC_CONN_TYPE_CTRL_ONLY = 1
};

typedef enum ctc_job_close_condition CTC_JOB_CLOSE_CONDITION;
enum ctc_job_close_condition
{
    CTC_JOB_CLOSE_IMMEDIATELY       = 0,
    CTC_JOB_CLOSE_AFTER_TRANSACTION = 1
};

enum ctc_return_value
{
    CTC_SUCCESS_NO_DATA                       =  2,
    CTC_SUCCESS_FRAGMENTED                    =  1,
    CTC_SUCCESS                               =  0,

    CTC_FAILED                                = -1,
    CTC_FAILED_INVALID_ARGS                   = -2,
    CTC_FAILED_INVALID_CONN_STRING            = -3,
    CTC_FAILED_ALLOC_CTC_HANDLE               = -4,
    CTC_FAILED_FREE_CTC_HANDLE                = -5,
    CTC_FAILED_INVALID_CTC_HANDLE             = -6,
    CTC_FAILED_ALLOC_JOB_DESC                 = -7,
    CTC_FAILED_FREE_JOB_DESC                  = -8,
    CTC_FAILED_INVALID_JOB_DESC               = -9,
    CTC_FAILED_TOO_SMALL_RESULT_BUFFER_SIZE   = -10

    CTC_FAILED_OPEN_CONTROL_SESSION           = -100,
    CTC_FAILED_CLOSE_CONTROL_SESSION          = -101,
    CTC_FAILED_COMMUNICATE_CONTROL_SESSION    = -102,
    CTC_FAILED_OPEN_JOB_SESSION               = -103, 
    CTC_FAILED_CLOSE_JOB_SESSION              = -104,
    CTC_FAILED_COMMUNICATE_JOB_SESSION        = -105,
    CTC_FAILED_OVERFLOW_DATA_PAYLOAD          = -106,

    CTC_FAILED_RECEIVE_INVALID_OP_ID          = -107,
    CTC_FAILED_RECEIVE_INVALID_JOB_DESC       = -108,
    CTC_FAILED_RECEIVE_INVALID_SESSION_GID    = -109,
    CTC_FAILED_RECEIVE_NOT_SUPPORTED_PROTOCOL = -110,
    CTC_FAILED_RECEIVE_INVALID_STATUS         = -111,

    CTC_FAILED_CREATE_JOB_THREAD              = -200,
    CTC_FAILED_DESTROY_JOB_THREAD             = -201,
};

int ctc_open_connection (CTC_CONN_TYPE connection_type, char *connection_string);
int ctc_close_connection (int ctc_handle);
int ctc_add_job (int ctc_handle);
int ctc_delete_job (int ctc_handle, int job_descriptor);
int ctc_check_server_status (int ctc_handle, int *server_status);
int ctc_register_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name);
int ctc_unregister_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name);
int ctc_start_capture (int ctc_handle, int job_descriptor);
int ctc_stop_capture (int ctc_handle, int job_descriptor, CTC_JOB_CLOSE_CONDITION close_condition);
int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char *result_buffer, int result_buffer_size, int *result_size);
int ctc_check_job_status (int ctc_handle, int job_descriptor, int *job_status);

#endif
