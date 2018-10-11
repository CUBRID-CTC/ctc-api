#ifndef _DEMO_SERVER_H_
#define _DEMO_SERVER_H_

#define CTCP_MAJOR_VERSION 1
#define CTCP_MINOR_VERSION 0
#define CTCP_PATCH_VERSION 0
#define CTCP_BUILD_VERSION 0

#define MAX_SESSION_GROUP_COUNT 100
#define MAX_JOB_COUNT 10

#define MAX_DATA_PAYLOAD_SIZE 4080

typedef enum
{
    false = 0,
    true  = 1
} bool;

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

enum ctc_conn_type
{
    CTC_CONN_TYPE_DEFAULT   = 0,
    CTC_CONN_TYPE_CTRL_ONLY = 1
};

enum ctc_close_condition
{
    CTC_QUIT_JOB_IMMEDIATELY       = 0,
    CTC_QUIT_JOB_AFTER_TRANSACTION = 1
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
    char data_payload[MAX_DATA_PAYLOAD_SIZE];
};

    // data_payload 크기는 4080 (MAX_DATA_PAYLOAD_SIZE)
    // 고정 크기
    // The number of items     : 4 byte ==> 39개
    // Transaction ID          : 4 byte ==> job_desc + 500
    // LSA                     : 4 byte ==> 7
    // User name length        : 4 byte ==> 4
    // User name value         : 4 byte ==> "dba1" 로 고정
    // Table name length       : 4 byte ==> 4
    // Table name value        : 4 byte ==> "tbl1" 로 고정
    // Statement type          : 2 byte ==> 1 (insert) 으로 고정, 아직 정의되어 있지 않음
    // The number of attribute : 2 byte ==> 3개로 고정
    // ================= 아래 부분 3번 반복 =======================
    // Attribute name length   : 4 byte ==> 8
    // Attribute name value    : 8 byte ==> "c1234567" 으로 고정
    // Attribute value length  : 4 byte ==> 8
    // Attribute value         : 8 byte ==> "12345678" 로 고정
    // ------------------------------------------------------------
    //                         : 24 byte
    //                      ==> 3 번 반복 24 byte * 3
    // ============================================================
    // --------------------------------------------------------
    //           one item size : 104 byte
    // 4080 byte / 104 byte = 39.xxx
    // 1 packet에는 39의 item이 들어갈 수 있다.
    //

// 한 item의 크기 ==> 100byte
// data payload 총 크기는 4080
// 여기서 the number of items (아이템 몇 개인지) 4 byte 빼면,
// 4076
// 4076 / 100 ==> 40개의 item이 들어갈 수 있고, 76 byte 남는다.
typedef struct item ITEM;
struct item
{
    // 총 크기 100
    int tx_id;
    int lsa;
    int user_name_len; // 4로 고정
    char user_name[4]; // "dba1"로 고정
    int table_name_len; // 4로 고정
    char table_name[4]; // "tbl1"로 고정


    short stmt_type; // 1, insert 로 고정

    short attr_num;  // 3개

    int attr_name_len_1; // 8
    char attr_name_1[8]; // "c1111117" 으로 고정
    int attr_val_len_1; // 8
    char attr_val_1[8]; // "11141118" 로 고정
    
    int attr_name_len_2; // 8
    char attr_name_2[8]; // "c2222227" 으로 고정
    int attr_val_len_2; // 8
    char attr_val_2[8]; // "22242228" 로 고정

    int attr_name_len_3; // 8
    char attr_name_3[8]; // "c3333337" 으로 고정
    int attr_val_len_3; // 8
    char attr_val_3[8]; // "33343338" 로 고정
};

typedef struct job JOB;
struct job
{
    int job_desc;
    int session_gid;

    /*
     * 자료구조 사용 여부
     *   - true: use
     *   - false: unuse
     */
    bool is_use;

    /*
     * 캡쳐 데이터 전송 진행 여부
     *   - true: demo_server --> ctc api로 임의의 데이터 스트림 전송 중
     *   - false: 전송 없음
     */
    bool is_capture_start;

    /*
     * job thread 종료 조건
     *   - true: 쓰레드 종료
     *   - false: 계속 쓰레드 수행
     */
    bool is_job_thread_stop;

    int job_sockfd;

    pthread_t job_thread;
};

typedef struct session_group SESSION_GROUP;
struct session_group
{
    int session_gid;

    /*
     * 자료구조 사용 여부
     *   - true: use
     *   - false: unuse
     */
    bool is_use;

    int conn_type;

    int ctrl_sockfd;

    JOB job[MAX_JOB_COUNT];

    pthread_t control_thread;
};

#endif
