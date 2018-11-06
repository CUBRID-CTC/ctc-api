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
    CTC_FAILED_OPEN_CONTROL_SESSION           = -10,
    CTC_FAILED_CLOSE_CONTROL_SESSION          = -11,
    CTC_FAILED_COMMUNICATE_CONTROL_SESSION    = -12,
    CTC_FAILED_OPEN_JOB_SESSION               = -13, 
    CTC_FAILED_CLOSE_JOB_SESSION              = -14,
    CTC_FAILED_COMMUNICATE_JOB_SESSION        = -15,
    CTC_FAILED_OVERFLOW_DATA_PAYLOAD          = -16,
    CTC_FAILED_CREATE_JOB_THREAD              = -17,
    CTC_FAILED_DESTROY_JOB_THREAD             = -18,
    CTC_FAILED_RECEIVE_INVALID_OP_ID          = -19,
    CTC_FAILED_RECEIVE_INVALID_JOB_DESC       = -20,
    CTC_FAILED_RECEIVE_INVALID_SESSION_GID    = -21,
    CTC_FAILED_RECEIVE_NOT_SUPPORTED_PROTOCOL = -22,
    CTC_FAILED_RECEIVE_INVALID_STATUS         = -23
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
int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char *result_buffer, int result_buffer_size, int *result_data_size);
int ctc_check_job_status (int ctc_handle, int job_descriptor, int *job_status);

#endif
