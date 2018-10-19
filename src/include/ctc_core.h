#ifndef _CTC_API_H_
#define _CTC_API_H_

#include <pthread.h>
#include "ctc_common.h"
#include "ctc_network.h"

#define MAX_CTC_HANDLE_COUNT 100 /* CTC_SESSION_GROUP_MAX */
#define MAX_JOB_HANDLE_COUNT 10

#define MAX_CAPTURED_DATA_BUFFER_COUNT 1000
#define MAX_CAPTURED_DATA_BUFFER_SIZE (4096 * 50) /* CTC_PACKET_SIZE * 50 */

typedef struct captured_data CAPTURED_DATA;
struct captured_data
{
    char *data_buffer;
    int remaining_buffer_size;

    int data_count;

    int write_offset;
    int read_offset;
};

typedef struct job_thread_args JOB_THREAD_ARGS;
struct job_thread_args
{
    CTC_HANDLE *ctc_handle;
    JOB_HANDLE *job_handle;
};

typedef struct job_handle JOB_HANDLE;
struct job_handle
{
    int ID;

    JOB_SESSION job_session;

    CAPTURED_DATA captured_data[MAX_CAPTURED_DATA_BUFFER_COUNT];
    int data_write_idx;
    int data_read_idx;

    pthread_t job_thread;
    bool job_thread_is_alive;
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
int connect_server (int conn_type, char *url, int *ctc_handle_id);
int disconnect_server (int ctc_handle_id);
int add_job (int ctc_handle_id);
int delete_job (int ctc_handle_id, int job_handle_id);
int check_server_status (int ctc_handle_id, int *server_status);
int register_table (int ctc_handle_id, int job_handle_id, char *db_user, char *table_name);
int unregister_table (int ctc_handle_id, int job_handle_id, char *db_user, char *table_name);
int check_job_status (int ctc_handle_id, int job_handle_id, int *job_status);

#endif
