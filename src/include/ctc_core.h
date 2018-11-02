#ifndef _CTC_CORE_H_
#define _CTC_CORE_H_

#include "ctc_network.h"

#define MAX_CTC_HANDLE_COUNT 100 /* CTC_SESSION_GROUP_MAX */
#define MAX_JOB_HANDLE_COUNT 10

typedef struct job_handle JOB_HANDLE;
struct job_handle
{
    int ID;

    JOB_SESSION job_session;

    JSON_TYPE_RESULT json_type_result;
};

typedef struct ctc_handle CTC_HANDLE;
struct ctc_handle
{
    int ID;

    CONTROL_SESSION control_session;

    JOB_HANDLE job_pool[MAX_JOB_HANDLE_COUNT];
};

extern pthread_once_t ctc_api_once_init;

void ctc_api_init (void);
int connect_server (CTC_CONN_TYPE conn_type, char *url, int *ctc_handle_id);
int disconnect_server (int ctc_handle_id);
int add_job (int ctc_handle_id);
int delete_job (int ctc_handle_id, int job_handle_id);
int check_server_status (int ctc_handle_id, int *server_status);
int register_table (int ctc_handle_id, int job_handle_id, char *db_user, char *table_name);
int unregister_table (int ctc_handle_id, int job_handle_id, char *db_user, char *table_name);
int start_capture (int ctc_handle_id, int job_handle_id);
int stop_capture (int ctc_handle_id, int job_handle_id, CTC_QUIT_JOB_CONDITION quit_job_condition);
int read_capture_transaction (int ctc_handle_id, int job_handle_id, char *buffer, int buffer_size, int *data_size, bool *is_fragmented);
int check_job_status (int ctc_handle_id, int job_handle_id, int *job_status);

#endif
