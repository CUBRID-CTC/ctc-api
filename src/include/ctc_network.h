#ifndef _CTC_NETWORK_H_
#define _CTC_NETWORK_H_

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <jansson.h>
#include "ctc_common.h"

#define CTCP_MAJOR_VERSION 1
#define CTCP_MINOR_VERSION 0
#define CTCP_PATCH_VERSION 0
#define CTCP_BUILD_VERSION 0

#define CTCP_PACKET_MAX_SIZE          (4096)
#define CTCP_PACKET_HEADER_SIZE       (16)
#define CTCP_DATA_PAYLOAD_MAX_SIZE    (CTCP_PACKET_MAX_SIZE - CTCP_PACKET_HEADER_SIZE)

#define POLL_TIMEOUT                  (3000) /* msec */

#define INITIAL_SESSION_GID           (-1)
#define INITIAL_JOB_DESC              (-1)

#define CAPTURE_DATA_BUFFER_COUNT     (1000)
#define CAPTURE_DATA_BUFFER_SIZE      (CTCP_PACKET_MAX_SIZE * 50)

#define JSON_ARRAY_SIZE               (200)

typedef enum ctcp_operation_id CTCP_OP_ID;
enum ctcp_operation_id
{
    CTCP_CREATE_CONTROL_SESSION         = 0x01,
    CTCP_CREATE_CONTROL_SESSION_RESULT  = 0x02,
    CTCP_DESTROY_CONTROL_SESSION        = 0x03,
    CTCP_DESTROY_CONTROL_SESSION_RESULT = 0x04,
    CTCP_CREATE_JOB_SESSION             = 0x05,

    CTCP_CREATE_JOB_SESSION_RESULT      = 0x06,
    CTCP_DESTROY_JOB_SESSION            = 0x07,
    CTCP_DESTROY_JOB_SESSION_RESULT     = 0x08,
    CTCP_REQUEST_JOB_STATUS             = 0x09,
    CTCP_REQUEST_JOB_STATUS_RESULT      = 0x0A,

    CTCP_REQUEST_SERVER_STATUS          = 0x0B,
    CTCP_REQUEST_SERVER_STATUS_RESULT   = 0x0C,
    CTCP_REGISTER_TABLE                 = 0x0D,
    CTCP_REGISTER_TABLE_RESULT          = 0x0E,
    CTCP_UNREGISTER_TABLE               = 0x0F,

    CTCP_UNREGISTER_TABLE_RESULT        = 0x10,
    CTCP_SET_JOB_ATTRIBUTE              = 0x11,
    CTCP_SET_JOB_ATTRIBUTE_RESULT       = 0x12,
    CTCP_START_CAPTURE                  = 0x80,
    CTCP_START_CAPTURE_RESULT           = 0x81,

    CTCP_CAPTURED_DATA_RESULT           = 0x82,
    CTCP_STOP_CAPTURE                   = 0x83,
    CTCP_STOP_CAPTURE_RESULT            = 0x84
};

enum ctcp_result_code
{
    CTC_RC_SUCCESS                             = 0x00,
    CTC_RC_SUCCESS_FRAGMENTED                  = 0x01,
    CTC_RC_FAILED                              = 0x02,
    CTC_RC_FAILED_WRONG_PACKET                 = 0x03,
    CTC_RC_FAILED_OUT_OF_RANGE                 = 0x04,

    CTC_RC_FAILED_UNKNOWN_OPERATION            = 0x05,
    CTC_RC_FAILED_INVALID_HANDLE               = 0x06,
    CTC_RC_FAILED_INSUFFICIENT_SERVER_RESOURCE = 0x07,
    CTC_RC_FAILED_CREATE_SESSION               = 0x08,
    CTC_RC_FAILED_SESSION_NOT_EXIST            = 0x09,
    
    CTC_RC_FAILED_SESSION_IS_BUSY              = 0x0A,
    CTC_RC_FAILED_SESSION_CLOSE                = 0x0B,
    CTC_RC_FAILED_NO_MORE_JOB_ALLOWED          = 0x0C,
    CTC_RC_FAILED_INVALID_JOB                  = 0x0D,
    CTC_RC_FAILED_INVALID_JOB_STATUS           = 0x0E,

    CTC_RC_FAILED_INVALID_TABLE_NAME           = 0x0F,
    CTC_RC_FAILED_TABLE_ALREADY_EXIST          = 0x10,
    CTC_RC_FAILED_UNREGISTERED_TABLE           = 0x11,
    CTC_RC_FAILED_JOB_ATTR_NOT_EXIST           = 0x12,
    CTC_RC_FAILED_INVALID_JOB_ATTR_VALUE       = 0x13,

    CTC_RC_FAILED_NOT_SUPPORTED_FILTER         = 0x14,
    CTC_RC_FAILED_JOB_ALREADY_STARTED          = 0x15,
    CTC_RC_FAILED_JOB_ALREADY_STOPPED          = 0x16
};

typedef enum ctc_stmt_type CTC_STMT_TYPE;
enum ctc_stmt_type
{
    CTC_STMT_TYPE_INSERT = 1,
    CTC_STMT_TYPE_UPDATE = 2,
    CTC_STMT_TYPE_DELETE = 3,
    CTC_STMT_TYPE_COMMIT = 4
};

typedef struct ctcp_header CTCP_HEADER;
struct ctcp_header
{
    unsigned char op_id;
    char op_param_or_result_code;
    unsigned short job_desc;
    int session_gid;
    char version[4];
    int header_data; /* job or server status, data length, job attribute value */
};

/* sizeof (CTCP) == 4096 bytes */
typedef struct ctcp CTCP;
struct ctcp
{
    CTCP_HEADER header;
    char data_payload[CTCP_DATA_PAYLOAD_MAX_SIZE];
};

typedef struct job_thread_args JOB_THREAD_ARGS;
struct job_thread_args
{
    void *control_session;
    void *job_session;
};

typedef struct job_thread JOB_THREAD;
struct job_thread
{
    volatile bool is_thr_alive;

    pthread_t thr_id;
    JOB_THREAD_ARGS thr_args;
    volatile int thr_retval;
};

typedef struct capture_data CAPTURE_DATA;
struct capture_data
{
    volatile char *raw_data_buffer[CAPTURE_DATA_BUFFER_COUNT];

    volatile int raw_data_buffer_w_idx;
    volatile int raw_data_buffer_r_idx;

    char *buffer_w_pos;
    char *buffer_r_pos;

    volatile char *buffer_data_limit[CAPTURE_DATA_BUFFER_COUNT];
    int remaining_buffer_size;
};

typedef struct job_session JOB_SESSION;
struct job_session
{
    int job_desc;

    int sockfd;

    CAPTURE_DATA capture_data;

    JOB_THREAD job_thread;
};

typedef struct control_session CONTROL_SESSION;
struct control_session
{
    int session_gid;

    int sockfd;

    char ip[16]; /* struct in_addr */
    unsigned short port; /* htons, sin_port */
};

typedef struct json_result JSON_RESULT;
struct json_result
{
    json_t *json[JSON_ARRAY_SIZE];
    int json_read_idx;
    bool is_fragmented;

    json_t *result_array;
};

int open_control_session (CONTROL_SESSION *control_session, CTC_CONN_TYPE conn_type);
int close_control_session (CONTROL_SESSION *control_session);
int close_job_session_socket_only (JOB_SESSION *job_session);
int open_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session);
int close_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session, bool is_send_ctcp);
int request_server_status (CONTROL_SESSION *control_session, CTC_SERVER_STATUS *server_status);
int request_register_table (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name);
int request_unregister_table (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name);
int request_start_capture (CONTROL_SESSION *control_session, JOB_SESSION *job_session);
int request_stop_capture (CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTC_JOB_CLOSE_CONDITION job_close_condition, bool is_send_ctcp);
int request_job_status (CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTC_JOB_STATUS *job_status);
int convert_capture_transaction_to_json (CAPTURE_DATA *capture_data, JSON_RESULT *json_result);

#endif
