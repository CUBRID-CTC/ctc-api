#ifndef _CTC_NETWORK_H_
#define _CTC_NETWORK_H_

#include <string.h>
#include "ctc_common.h"

#define CTCP_MAJOR_VERSION 1
#define CTCP_MINOR_VERSION 0
#define CTCP_PATCH_VERSION 0
#define CTCP_BUILD_VERSION 0

#define CTCP_HEADER_SIZE 16
#define CTCP_MAX_DATA_PAYLOAD_SIZE 4080

#define CTCP_PACKET_SIZE (CTCP_HEADER_SIZE + CTCP_MAX_DATA_PAYLOAD_SIZE)

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
    CTCP_START_CAPTURE                  = 0x81,
    CTCP_START_CAPTURE_RESULT           = 0x82,
    CTCP_CAPTURED_DATA_RESULT           = 0x83,
    CTCP_STOP_CAPTURE                   = 0x84,
    CTCP_STOP_CAPTURE_RESULT            = 0x85
};

enum ctcp_result_code
{
    CTC_RC_SUCCESS                       = 0x00,
    CTC_RC_SUCCESS_FRAGMENTED            = 0x01,
    CTC_RC_FAILED                        = 0x02,
    CTC_RC_FAILED_WRONG_PACKET           = 0x03,
    CTC_RC_FAILED_OUT_OF_RANGE           = 0x04,
    CTC_RC_FAILED_UNKNOWN_OPERATION      = 0x05,
    CTC_RC_FAILED_INVALID_HANDLE         = 0x06,
    CTC_RC_FAILED_CREATE_SESSION         = 0x07,
    CTC_RC_FAILED_SESSION_NOT_EXIST      = 0x08,
    CTC_RC_FAILED_SESSION_IS_BUSY        = 0x09,
    CTC_RC_FAILED_SESSION_CLOSE          = 0x10,
    CTC_RC_FAILED_NO_MORE_JOB_ALLOWED    = 0x11,
    CTC_RC_FAILED_INVALID_JOB            = 0x12,
    CTC_RC_FAILED_UNREGISTERED_TABLE     = 0x13,
    CTC_RC_FAILED_INVALID_JOB_ATTR       = 0x14,
    CTC_RC_FAILED_INVALID_JOB_ATTR_VALUE = 0x15,
    CTC_RC_FAILED_NOT_SUPPORTED_FILTER   = 0x50
};

typedef enum ctc_conn_type CTC_CONN_TYPE;
enum ctc_conn_type
{
    CTC_CONN_TYPE_DEFAULT   = 0,
    CTC_CONN_TYPE_CTRL_ONLY = 1
};

enum ctc_server_status
{
    CTC_SERVER_NOT_READY = 0,
    CTC_SERVER_RUNNING   = 1,
    CTC_SERVER_CLOSING   = 2
};

enum job_status
{
    CTC_JOB_NONE           = 0,
    CTC_JOB_WAITING        = 1,
    CTC_JOB_PROCESSING     = 2,
    CTC_JOB_READY_TO_FETCH = 3,
    CTC_JOB_CLOSING        = 4
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
    char data_payload[CTCP_MAX_DATA_PAYLOAD_SIZE];
};

typedef struct job_session JOB_SESSION;
struct job_session
{
    int job_desc;

    int sockfd;
};

typedef struct control_session CONTROL_SESSION;
struct control_session
{
    int session_gid;

    int sockfd;

    CTC_CONN_TYPE conn_type;

    char ip[16]; /* struct in_addr */
    unsigned short port; /* htons, sin_port */
};

int open_control_session (CONTROL_SESSION *control_session, CTC_CONN_TYPE conn_type);
int close_control_session (CONTROL_SESSION *control_session);
int open_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session);
int close_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session);
int get_server_status (CONTROL_SESSION *control_session, int *server_status);
int register_table_to_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name);
int unregister_table_from_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name);
int get_job_status (CONTROL_SESSION *control_session, JOB_SESSION *job_session, int *job_status);

#endif
