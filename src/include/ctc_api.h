#ifndef _CTC_API_H_
#define _CTC_API_H_

#define CTC_SUCCESS             0
#define CTC_SUCCESS_FRAGMENTED  1
#define CTC_SUCCESS_NO_DATA     2
#define CTC_FAILURE            -1

typedef enum ctc_conn_type CTC_CONN_TYPE;
enum ctc_conn_type
{
    CTC_CONN_TYPE_DEFAULT   = 0,
    CTC_CONN_TYPE_CTRL_ONLY = 1
};

typedef enum ctc_quit_job_condition CTC_QUIT_JOB_CONDITION;
enum ctc_quit_job_condition
{
    CTC_QUIT_JOB_IMMEDIATELY       = 0,
    CTC_QUIT_JOB_AFTER_TRANSACTION = 1
};

int ctc_open_connection (int connection_type, char *connection_string);
int ctc_close_connection (int ctc_handle);
int ctc_add_job (int ctc_handle);
int ctc_delete_job (int ctc_handle, int job_descriptor);
int ctc_check_server_status (int ctc_handle, int *server_status);
int ctc_register_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name);
int ctc_unregister_table (int ctc_handle, int job_descriptor, char *db_user_name, char *table_name);
int ctc_start_capture (int ctc_handle, int job_descriptor);
int ctc_stop_capture (int ctc_handle, int job_descriptor, int close_condition);
int ctc_fetch_capture_transaction (int ctc_handle, int job_descriptor, char *result_buffer, int result_buffer_size, int *result_data_size);
int ctc_check_job_status (int ctc_handle, int job_descriptor, int *job_status);

#endif
