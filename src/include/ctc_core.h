#ifndef _CTC_CORE_H_
#define _CTC_CORE_H_

#include "ctc_network.h"

#define CTC_HANDLE_MAX_COUNT 100 /* CTC_SESSION_GROUP_MAX */
#define JOB_DESC_MAX_COUNT 10

typedef struct job_desc JOB_DESC;
struct job_desc
{
    //int job_desc_id;

    JOB_SESSION job_session;

    JSON_TYPE_RESULT json_type_result;
};

typedef struct ctc_handle CTC_HANDLE;
struct ctc_handle
{
    CONTROL_SESSION control_session;

    JOB_DESC job_desc_pool[JOB_DESC_MAX_COUNT];
};

extern pthread_once_t ctc_api_once_init;

void ctc_api_init (void);
int open_connection (CTC_CONN_TYPE conn_type, char *url, int *ctc_handle_id);
int close_connection (int ctc_handle_id);
int add_job (int ctc_handle_id, int *job_desc_id);
int delete_job (int ctc_handle_id, int job_desc_id);
int check_server_status (int ctc_handle_id, int *server_status);
int register_table (int ctc_handle_id, int job_desc_id, char *user_name, char *table_name);
int unregister_table (int ctc_handle_id, int job_desc_id, char *user_name, char *table_name);
int start_capture (int ctc_handle_id, int job_desc_id);
int stop_capture (int ctc_handle_id, int job_desc_id, CTC_JOB_CLOSE_CONDITION job_close_condition);
int read_capture_transaction (int ctc_handle_id, int job_desc_id, char *buffer, int buffer_size, int *data_size, bool *is_fragmented);
int check_job_status (int ctc_handle_id, int job_desc_id, int *job_status);

#endif
