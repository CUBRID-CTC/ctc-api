#ifndef _CTC_API_H_
#define _CTC_API_H_

#define CTC_SUCCESS            (0)
#define CTC_SUCCESS_FRAGMENTED (1)
#define CTC_SUCCESS_NO_DATA    (2)

typedef enum ctc_connection_type CTC_CONN_TYPE;
enum ctc_connection_type
{
    CTC_CONN_TYPE_DEFAULT,
    CTC_CONN_TYPE_CTRL_ONLY
};

typedef enum ctc_job_close_condition CTC_JOB_CLOSE_CONDITION;
enum ctc_job_close_condition
{
    CTC_JOB_CLOSE_IMMEDIATELY,
    CTC_JOB_CLOSE_AFTER_TRANSACTION
};

typedef enum ctc_server_status CTC_SERVER_STATUS;
enum ctc_server_status
{
    CTC_SERVER_NOT_READY,
    CTC_SERVER_RUNNING,
    CTC_SERVER_CLOSING
};

typedef enum ctc_job_status CTC_JOB_STATUS;
enum ctc_job_status
{
    CTC_JOB_NONE,
    CTC_JOB_WAITING,
    CTC_JOB_PROCESSING,
    CTC_JOB_READY_TO_FETCH,
    CTC_JOB_CLOSING
};

int ctc_open_connection (CTC_CONN_TYPE connection_type, char *connection_string);
int ctc_close_connection (int ctc_handle);
int ctc_add_job (int ctc_handle);
int ctc_delete_job (int ctc_handle, int job_descriptor);
int ctc_check_server_status (int ctc_handle, CTC_SERVER_STATUS *server_status);
int ctc_register_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name);
int ctc_unregister_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name);
int ctc_start_capture (int ctc_handle, int job_descriptor);
int ctc_stop_capture (int ctc_handle, int job_descriptor, CTC_JOB_CLOSE_CONDITION close_condition);
int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char *result_buffer, int result_buffer_size, int *result_size);
int ctc_check_job_status (int ctc_handle, int job_descriptor, CTC_JOB_STATUS *job_status);

#endif
