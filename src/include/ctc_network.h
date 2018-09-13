#ifndef _CTC_NETWORK_H_
#define _CTC_NETWORK_H_

#include "ctc_common.h"

#define CTCP_MAJOR_VERSION 0x01
#define CTCP_MINOR_VERSION 0x00
#define CTCP_PATCH_VERSION 0x00

typedef enum ctcp_operation CTCP_OP;
enum ctcp_operation
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
    CTCP_STOP_CAPTURE                   = 0x83,
    CTCP_STOP_CAPTURE_RESULT            = 0x84
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

    char server_ip[16];
    short server_port;
};

#endif
