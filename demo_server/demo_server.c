//32개의 클라이언트 처리
//32개 클라이언트에서 각각 16개의 테이블 생성 ==> 총 512개
//한 클라이언트에서 처리하는 테이블의 수는 16개

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "demo_server.h"

#define PRINT_ERR_LOG() do { printf ("[ERROR] %s () at %s:%d\n", __func__, __FILE__, __LINE__); } while (0)

SESSION_GROUP session_group_arr[MAX_SESSION_GROUP_COUNT];
int next_alloc_pos = 0;

// capture start 시 설정된 횟수 만큼 packet (4K) 쏘고 1초 쉰다.
// 해당 횟수 만큼 보내고 job thread 상태 확인 후 sleep (1초) 
int packet_count_at_once = 0;

// capture start 시 설정된 횟수 만큼 데이터(4K * packet_count_at_once) 보낸다.
// 0 이면 cature stop 전까지 계속 보낸다.
// 총 보내는 횟수는 packet_count_at_once * send_count
int send_count = 0;

// data_payload 하나 만들어두고 같은 놈을 계속 전송하자
char data_payload[MAX_DATA_PAYLOAD_SIZE];

int make_data_payload (void);
int execute_server (unsigned short listen_port);
int process_client_request (int service_fd);
int process_control_session_request (SESSION_GROUP *session_group, bool *is_finish);
int process_CREATE_CONTROL_SESSION (CTCP_HEADER *ctcp_header, int service_fd);
int process_DESTROY_CONTROL_SESSION (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_CREATE_JOB_SESSION (CTCP_HEADER *ctcp_header, int service_fd);
int process_DESTROY_JOB_SESSION (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_REQUEST_JOB_STATUS (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_REQUEST_SERVER_STATUS (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_REGISTER_TABLE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_UNREGISTER_TABLE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_START_CAPTURE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);
int process_STOP_CAPTURE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group);

void usage ()
{
    printf ("== USAGE ==\n");
    printf ("demo_server [PORT] [PACKET_COUNT_AT_ONCE] [SEND_COUNT]\n");
    printf ("ex) ./demo_server 20000 10 60\n\n");
}

int main (int argc, char *argv[])
{
    int listen_port;
    int i;

    if (argc < 4)
    {
        usage ();
        exit (1);
    }

    listen_port = atoi (argv[1]);

    if (listen_port > 65535)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    packet_count_at_once = atoi (argv[2]);

    if (packet_count_at_once <= 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    send_count = atoi (argv[3]);

    if (send_count < 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    for (i = 0; i < MAX_SESSION_GROUP_COUNT; i ++)
    {
        session_group_arr[i].is_use = false;
        session_group_arr[i].session_gid = i + 100; // session group id ==> 편의상 100 부터 할당 
    }

    // demo_server라 data_payload 미리 만들어두고 공유
    if (-1 == make_data_payload ())
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    printf ("demo_server start\n");

    if (-1 == execute_server (listen_port))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    printf ("demo_server stop\n");

    return 0;

error:

    printf ("demo_server stop with error\n");

    return -1;
}

int execute_server (unsigned short listen_port)
{
    int listen_fd, service_fd;
    int max_client;
    int addr_len;
    struct sockaddr_in server_addr, client_addr;

    listen_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    memset (&server_addr, 0, sizeof (server_addr));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl (INADDR_ANY);
    server_addr.sin_port = htons (listen_port);

    if (bind (listen_fd, (struct sockaddr *)&server_addr, sizeof (server_addr)) < 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    max_client = MAX_SESSION_GROUP_COUNT;

    if (listen (listen_fd, max_client) < 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    while (true)
    {
        addr_len = sizeof (client_addr);

        service_fd = accept (listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (service_fd < 0)
        {
            PRINT_ERR_LOG ();
            goto error;
        }

        // client IP / Port 출력
        printf ("== CLIENT INFO ==\n");
        printf ("[IP]   ==> %s\n", inet_ntoa (client_addr.sin_addr));
        printf ("[Port] ==> %d\n\n", ntohs (client_addr.sin_port));

        // 다음 두 개의 프로토콜만 올 수 있다.
        // - CTCP_CREATE_CONTROL_SESSION
        // - CTCP_CREATE_JOB_SESSION
        if (-1 == process_client_request (service_fd))
        {
            PRINT_ERR_LOG ();
            goto error;
        }
    }

    close (listen_fd);

    return 0;

error:

    return -1;
}

// server의 listen 소켓 요청 처리 함수
int process_client_request (int service_fd)
{
    CTCP_HEADER ctcp_header;
    int retval;

    retval = read (service_fd, &ctcp_header, sizeof (ctcp_header));
    if (retval == -1 || retval < sizeof (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // listen 소켓으로 요청 받는 프로토콜은 총 11개 중 2개 뿐이다.
    // 1) CTCP_CREATE_CONTROL_SESSION
    // 2) CTCP_CREATE_JOB_SESSION
    switch (ctcp_header.op_id)
    {
        case CTCP_CREATE_CONTROL_SESSION:
            if (-1 == process_CREATE_CONTROL_SESSION (&ctcp_header, service_fd))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;

        case CTCP_CREATE_JOB_SESSION:
            // job 생성 요청은 구현 상의 이슈로 listen_socket 으로 처리
            if (-1 == process_CREATE_JOB_SESSION (&ctcp_header, service_fd))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;

        case CTCP_DESTROY_CONTROL_SESSION:
        case CTCP_DESTROY_JOB_SESSION:
        case CTCP_REGISTER_TABLE:
        case CTCP_UNREGISTER_TABLE:
        case CTCP_START_CAPTURE:
        case CTCP_STOP_CAPTURE:
        case CTCP_REQUEST_SERVER_STATUS:
        case CTCP_REQUEST_JOB_STATUS:
        case CTCP_SET_JOB_ATTRIBUTE:
        default:
            PRINT_ERR_LOG ();
            goto error;
    }

    return 0;

error:

    return -1;
}

// control session으로 요청받는 프로토콜 처리
int process_control_session_request (SESSION_GROUP *session_group, bool *is_finish)
{
    CTCP_HEADER ctcp_header;
    int retval;

    // demo_server라 요청을 무한 대기하도록 하였음.
    // 테스트 중 문제가 있다면, select () or poll () 사용
    retval = read (session_group->ctrl_sockfd, &ctcp_header, sizeof (ctcp_header));
    if (retval == -1 || retval < sizeof (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    switch (ctcp_header.op_id)
    {
        case CTCP_DESTROY_CONTROL_SESSION:
            if (-1 == process_DESTROY_CONTROL_SESSION (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            *is_finish = true;

            break;
        case CTCP_DESTROY_JOB_SESSION:
            if (-1 == process_DESTROY_JOB_SESSION (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_REQUEST_JOB_STATUS:
            if (-1 == process_REQUEST_JOB_STATUS (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_REQUEST_SERVER_STATUS:
            if (-1 == process_REQUEST_SERVER_STATUS (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_REGISTER_TABLE:
            if (-1 == process_REGISTER_TABLE (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_UNREGISTER_TABLE:
            if (-1 == process_UNREGISTER_TABLE (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;

        case CTCP_START_CAPTURE:
            if (-1 == process_START_CAPTURE (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_STOP_CAPTURE:
            if (-1 == process_STOP_CAPTURE (&ctcp_header, session_group))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;

        case CTCP_CREATE_CONTROL_SESSION:
        case CTCP_CREATE_JOB_SESSION:
        case CTCP_SET_JOB_ATTRIBUTE:
        default:
            PRINT_ERR_LOG ();
            goto error;
    }

    return 0;

error:

    return -1;
}

int check_version_info (CTCP_HEADER *ctcp_header)
{
    if (ctcp_header->version[0] != CTCP_MAJOR_VERSION ||
        ctcp_header->version[1] != CTCP_MINOR_VERSION ||
        ctcp_header->version[2] != CTCP_PATCH_VERSION ||
        ctcp_header->version[3] != CTCP_BUILD_VERSION)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

    return -1;
}

void make_version_info (CTCP_HEADER *ctcp_header)
{
    ctcp_header->version[0] = CTCP_MAJOR_VERSION;
    ctcp_header->version[1] = CTCP_MINOR_VERSION;
    ctcp_header->version[2] = CTCP_PATCH_VERSION;
    ctcp_header->version[3] = CTCP_BUILD_VERSION;
}

// control session 의 요청사항을 처리하는 쓰레드
void *execute_control_thread (void *sess_group)
{
    SESSION_GROUP *session_group = sess_group;
    CTCP_HEADER ctcp_header_result;

    bool is_finish = false;

    /* send CTCP_CREATE_CONTROL_SESSION_RESULT */
    ctcp_header_result.op_id = CTCP_CREATE_CONTROL_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    while (is_finish != true)
    {
        // control session 으로 요청 받을 수 있는 ctcp 대기
        if (-1 == process_control_session_request (session_group, &is_finish))
        {
            PRINT_ERR_LOG ();
            goto error;
        }
    }

    // job 정리가 필요하면 여기서

    close (session_group->ctrl_sockfd);
    
    // 전역 배열에 대한 처리라 위험할 수 있지만 next_alloc_pos 전역변수로 최대한 회피하는 전략
    session_group->is_use = false;
    
    pthread_exit (NULL);

error:

    close (session_group->ctrl_sockfd);

    session_group->is_use = false;

    pthread_exit (NULL);
}

// i : 1 , u : 2, d : 3, c : 4


// capture start 시 설정된 횟수 만큼 packet (4K) 쏘고 1초 쉰다.
// 해당 횟수 만큼 보내고 job thread 상태 확인 후 sleep (1초) 
//int packet_count_at_once = 0;

// capture start 시 설정된 횟수 만큼 데이터(4K * packet_count_at_once) 보낸다.
// 0 이면 cature stop 전까지 계속 보낸다.
// 총 보내는 횟수는 packet_count_at_once * send_count
// int send_count = 0;
/*
typedef struct ctcp CTCP;
struct ctcp
{
    CTCP_HEADER header;
    char data_payload[MAX_DATA_PAYLOAD_SIZE];
};
*/

int make_data_payload (void)
{
    char *where;
    ITEM item; // 한 ITEM 크기는 100 byte 이고, data_payload 부분에 40개의 ITEM이 들어갈 수 있다.
    int num_of_items;

    int i;

    item.tx_id = 777;
    item.lsa = 888;

    item.user_name_len = 4;
    memcpy (item.user_name, "dba1", 4);

    item.table_name_len = 4;
    memcpy (item.table_name, "tbl1", 4);

    item.stmt_type = 1; // insert 고정

    item.attr_num = 3;

    item.attr_name_len_1 = 8;
    memcpy (item.attr_name_1, "c1111111", 8);
    item.attr_val_len_1 = 8;
    memcpy (item.attr_val_1, "11111111", 8);

    item.attr_name_len_2 = 8;
    memcpy (item.attr_name_2, "c2222222", 8);
    item.attr_val_len_2 = 8;
    memcpy (item.attr_val_2, "22222222", 8);

    item.attr_name_len_3 = 8;
    memcpy (item.attr_name_3, "c3333333", 8);
    item.attr_val_len_3 = 8;
    memcpy (item.attr_val_3, "33333333", 8);

    num_of_items = 40;
    where = data_payload; // data_payload는 전역변수

    memcpy (where, &num_of_items, 4);
    where = where + 4;

    for (i=0; i<40; i++)
    {
        memcpy (where, &item, 100);
        where = where + 100;
    }
}

int send_captured_data (JOB* job)
{
    int packet_send_count = packet_count_at_once; // 4k 패킷을 이 횟수만큼 전송
    CTCP ctcp;
    CTCP_HEADER *ctcp_header_result = &ctcp.header;

    while (packet_send_count)
    {
        ctcp_header_result->op_id = CTCP_START_CAPTURE_RESULT;

        if (packet_send_count == 1) // 전송 packet이 하나 남았으면
        {
            ctcp_header_result->op_param_or_result_code = CTC_RC_SUCCESS;
        }
        else
        {
            ctcp_header_result->op_param_or_result_code = CTC_RC_SUCCESS_FRAGMENTED;
        }

        ctcp_header_result->job_desc = job->job_desc;
        ctcp_header_result->session_gid = job->session_gid;

        make_version_info (ctcp_header_result);

        // 하드 코딩해라
        ctcp_header_result->header_data = 4004; // 4080 - 76 = 4004 byte

        memcpy (ctcp.data_payload, data_payload, 4004);

        if (-1 == write (job->job_sockfd, &ctcp, sizeof (ctcp)))
        {
            PRINT_ERR_LOG ();
            goto error;
        }

        packet_send_count --;
    }

    return 0;

error:

    return -1;
}

void *execute_job_thread (void *job_p)
{
    JOB *job = job_p;
    int data_send_count = 0;

    if (send_count == 0)
    {
        data_send_count = -1; // 무한으로 데이터 전송
    }
    else
    {
        data_send_count = send_count;
    }

    job->is_capture_start = true;

    while (job->is_capture_start == true && job->is_job_thread_stop == false)
    {
        if (-1 == send_captured_data (job))
        {
            PRINT_ERR_LOG ();
            goto error;
        }

        if (data_send_count == -1)
        {
            // 무한 전송이라 감소시킬 필요 없다.
        }
        else
        {
            data_send_count --;
        }

        if (data_send_count == 0)
        {
            break;
        }

        sleep (1);
    }

    // 전송의 끝임을 알려야

    close (job->job_sockfd);

    pthread_exit (NULL);

error:

    close (job->job_sockfd);

    pthread_exit (NULL);
}

int process_CREATE_CONTROL_SESSION (CTCP_HEADER *ctcp_header, int service_fd)
{
    SESSION_GROUP *session_group;
    CTCP_HEADER ctcp_header_result;
    int i;

    // CTCP_CREATE_CONTROL_SESSION 프로토콜 검사
    if (ctcp_header->op_param_or_result_code != CTC_CONN_TYPE_DEFAULT &&
        ctcp_header->op_param_or_result_code != CTC_CONN_TYPE_CTRL_ONLY)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->job_desc != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    session_group = NULL;

    // session_group 할당
    // next_alloc_pos 전역 변수로 전역 배열의 동시성 충돌 최대한 회피
    for (i = 0; i < MAX_SESSION_GROUP_COUNT; i ++)
    {
        if (next_alloc_pos >= MAX_SESSION_GROUP_COUNT)
        {
            next_alloc_pos = 0;
        }

        if (session_group_arr[next_alloc_pos].is_use == false)
        {
            session_group = &session_group_arr[next_alloc_pos];
            session_group->is_use = true;

            next_alloc_pos ++;

            break;
        }

        next_alloc_pos ++;
    }

    if (session_group == NULL)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    session_group->conn_type = ctcp_header->op_param_or_result_code;

    // job 배열 초기화
    for (i = 0; i < MAX_JOB_COUNT; i ++)
    {
        session_group->job[i].is_use = false;
        session_group->job[i].job_desc = i + 300; // 편의상 job descriptor는 300 부터 할당
    }

    session_group->ctrl_sockfd = service_fd;

    // control session 요청을 처리하는 쓰레드 생성
    if (0 != pthread_create (&session_group->control_thread, NULL, execute_control_thread, (void *)session_group))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // CTCP_DESTROY_CONTROL_SESSION 프로토콜이control_thread의 control session 으로 요청되기에,
    // main thread에서 join 타이밍 잡기 어렵다.
    if (0 != pthread_detach (session_group->control_thread))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

    /* 실패 시 실패 프로토콜 전송 */
    /* send CTCP_CREATE_CONTROL_SESSION_RESULT with ERROR */
    ctcp_header_result.op_id = CTCP_CREATE_CONTROL_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = 0;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (service_fd, &ctcp_header_result, sizeof (ctcp_header_result));

    close (service_fd);

    return -1;
}

int process_DESTROY_CONTROL_SESSION (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->job_desc != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_DESTROY_CONTROL_SESSION_RESULT
    ctcp_header_result.op_id = CTCP_DESTROY_CONTROL_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    // send CTCP_DESTROY_CONTROL_SESSION_RESULT with error
    ctcp_header_result.op_id = CTCP_DESTROY_CONTROL_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_SESSION_CLOSE;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    return -1;
}

int process_CREATE_JOB_SESSION (CTCP_HEADER *ctcp_header, int service_fd)
{
    SESSION_GROUP *session_group;
    JOB *job;
    int i;
    CTCP_HEADER ctcp_header_result;

    // CTCP_CREATE_JOB_SESSION 프로토콜 검사
    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->job_desc != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid < 0 || ctcp_header->session_gid >= MAX_SESSION_GROUP_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // session_group 찾고
    session_group = &session_group_arr[ctcp_header->session_gid];

    if (session_group->is_use != true)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // 클라이언트가 job 단위로 쓰레드를 돌리지 않는 이상 동시성 제어 불필요
    job = NULL;

    for (i = 0; i < MAX_JOB_COUNT; i ++)
    {
        if (session_group->job[i].is_use == false)
        {
            job = &session_group->job[i];
            session_group->job[i].is_use = true;

            break;
        }
    }

    if (job == NULL)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    job->session_gid = session_group->session_gid;

    job->job_sockfd = service_fd;

    /* send CTCP_CREATE_JOB_SESSION_RESULT */
    ctcp_header_result.op_id = CTCP_CREATE_JOB_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = job->job_desc;
    ctcp_header_result.session_gid = job->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    if (-1 == write (service_fd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

    /* 실패 시 실패 프로토콜 전송 */
    /* send CTCP_CREATE_JOB_SESSION_RESULT with ERROR */
    ctcp_header_result.op_id = CTCP_CREATE_JOB_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_NO_MORE_JOB_ALLOWED;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (service_fd, &ctcp_header_result, sizeof (ctcp_header_result));

    close (service_fd);

    return -1;
}

int process_DESTROY_JOB_SESSION (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    JOB *job;
    CTCP_HEADER ctcp_header_result;

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job desc later
    if (ctcp_header->job_desc >= MAX_JOB_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != false)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_DESTROY_JOB_SESSION_RESULT
    ctcp_header_result.op_id = CTCP_DESTROY_JOB_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = job->job_desc;
    ctcp_header_result.session_gid = job->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    job->is_capture_start = false;
    job->is_job_thread_stop = true;

    if (0 != pthread_join (job->job_thread, NULL))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    job->is_use = false;
  
    return 0;

error:

    // send CTCP_DESTROY_JOB_SESSION_RESULT with error
    ctcp_header_result.op_id = CTCP_DESTROY_JOB_SESSION_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = ctcp_header->job_desc;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    job->is_use = false;

    return -1;
}

int process_REQUEST_JOB_STATUS (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    JOB *job;
    CTCP_HEADER ctcp_header_result;

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job desc later
    if (ctcp_header->job_desc >= MAX_JOB_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != true)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_REQUEST_JOB_STATUS_RESULT
    ctcp_header_result.op_id = CTCP_REQUEST_JOB_STATUS_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = job->job_desc;
    ctcp_header_result.session_gid = job->session_gid;

    make_version_info (&ctcp_header_result);

    // demo_server 이기 때문에 api 사용자가 start_capture를 호출한 경우 무조건 job에 읽을 데이터가 있다고 알려주고,
    // start_capture를 호출하지 않은 경우 그냥 waiting 상태라고 알려주자.
    if (job->is_capture_start == true)
    {
        ctcp_header_result.header_data = 3; /* CTC_JOB_READY_TO_FETCH */
    }
    else
    {
        ctcp_header_result.header_data = 1; /* CTC_JOB_WAITING */
    }

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    // send CTCP_REQUEST_JOB_STATUS_RESULT with error
    ctcp_header_result.op_id = CTCP_REQUEST_JOB_STATUS_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = ctcp_header->job_desc;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    return -1;
}

int process_REQUEST_SERVER_STATUS (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->job_desc != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_REQUEST_SERVER_STATUS_RESULT
    ctcp_header_result.op_id = CTCP_REQUEST_SERVER_STATUS_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    // demo_server의 경우 서버는 항상 수행 중
    ctcp_header_result.header_data = 1; /* CTC_SERVER_RUNNING */

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    // send CTCP_REQUEST_SERVER_STATUS_RESULT with error
    ctcp_header_result.op_id = CTCP_REQUEST_SERVER_STATUS_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    return -1;
}

int process_REGISTER_TABLE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;
    JOB *job;

    int data_len;
    int retval;
    char data_buffer[4096];

    int user_name_len;
    char user_name[1024];
    int table_name_len;
    char table_name[1024];

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job desc later
    if (ctcp_header->job_desc >= MAX_JOB_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    data_len = ctcp_header->header_data;
    if (data_len <= 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    retval = read (session_group->ctrl_sockfd, data_buffer, data_len);
    if (retval == -1 || retval != data_len)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // user name
    memcpy (&user_name_len, data_buffer, sizeof (int));
    snprintf (user_name, user_name_len + 1, "%s", data_buffer + sizeof (int));

    // table name
    memcpy (&table_name_len, data_buffer + sizeof (int) + user_name_len, sizeof (int));
    snprintf (table_name, table_name_len + 1, "%s", data_buffer + sizeof (int) + user_name_len + sizeof (int));

    if (sizeof (int) + user_name_len + sizeof (int) + table_name_len != data_len)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    /* 사용자 명, 테이블 명 읽을 필요가 있다면 여기서 처리 */
    printf ("== REGISTER TABLE INFO ==\n");
    printf ("user_name ==> %s, length ==> %d\n", user_name, user_name_len);
    printf ("table_name ==> %s, length ==> %d\n\n", table_name, table_name_len);

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != true)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_REGISTER_TABLE_RESULT
    ctcp_header_result.op_id = CTCP_REGISTER_TABLE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = job->job_desc;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    // send CTCP_REGISTER_TABLE_RESULT with error
    ctcp_header_result.op_id = CTCP_REGISTER_TABLE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = ctcp_header->job_desc;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    return -1;
}

int process_UNREGISTER_TABLE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;
    JOB *job;

    int data_len;
    int retval;
    char data_buffer[4096];

    int user_name_len;
    char user_name[1024];
    int table_name_len;
    char table_name[1024];

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job desc later
    if (ctcp_header->job_desc >= MAX_JOB_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    data_len = ctcp_header->header_data;
    if (data_len <= 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    retval = read (session_group->ctrl_sockfd, data_buffer, data_len);
    if (retval == -1 || retval != data_len)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // user name
    memcpy (&user_name_len, data_buffer, sizeof (int));
    snprintf (user_name, user_name_len + 1, "%s", data_buffer + sizeof (int));

    // table name
    memcpy (&table_name_len, data_buffer + sizeof (int) + user_name_len, sizeof (int));
    snprintf (table_name, table_name_len + 1, "%s", data_buffer + sizeof (int) + user_name_len + sizeof (int));

    if (sizeof (int) + user_name_len + sizeof (int) + table_name_len != data_len)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    /* 사용자 명, 테이블 명 읽을 필요가 있다면 여기서 처리 */
    printf ("== UNREGISTER TABLE INFO ==\n");
    printf ("user_name ==> %s, length ==> %d\n", user_name, user_name_len);
    printf ("table_name ==> %s, length ==> %d\n\n", table_name, table_name_len);

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != true)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_UNREGISTER_TABLE_RESULT
    ctcp_header_result.op_id = CTCP_UNREGISTER_TABLE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = job->job_desc;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    // send CTCP_UNREGISTER_TABLE_RESULT with error
    ctcp_header_result.op_id = CTCP_UNREGISTER_TABLE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = ctcp_header->job_desc;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    return -1;
}

int process_START_CAPTURE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;
    JOB *job = NULL;

    if (ctcp_header->op_param_or_result_code != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job desc later
    if (ctcp_header->job_desc >= MAX_JOB_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != true)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_START_CAPTURE_RESULT
    // 이 놈의 경우 job_thread에서 보내준다.

    // capture data를 전송하는 job 쓰레드 생성
    if (0 != pthread_create (&job->job_thread, NULL, execute_job_thread, (void *)job))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

    // send CTCP_STOP_CAPTURE_RESULT with error
    ctcp_header_result.op_id = CTCP_STOP_CAPTURE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = ctcp_header->job_desc;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    session_group->job[ctcp_header->job_desc].is_job_thread_stop = true;

    return -1;
}

int process_STOP_CAPTURE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;
    JOB *job = NULL;

    if (ctcp_header->op_param_or_result_code != CTC_QUIT_JOB_IMMEDIATELY ||
        ctcp_header->op_param_or_result_code != CTC_QUIT_JOB_AFTER_TRANSACTION)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job desc later
    if (ctcp_header->job_desc >= MAX_JOB_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->session_gid != session_group->session_gid)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (-1 == check_version_info (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (ctcp_header->header_data != 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != true)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // send CTCP_STOP_CAPTURE_RESULT
    ctcp_header_result.op_id = CTCP_STOP_CAPTURE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header_result.job_desc = 0;
    ctcp_header_result.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    job->is_capture_start = false;
    job->is_job_thread_stop = true;

    if (0 != pthread_join (job->job_thread, NULL))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    // send CTCP_STOP_CAPTURE_RESULT with error
    ctcp_header_result.op_id = CTCP_STOP_CAPTURE_RESULT;
    ctcp_header_result.op_param_or_result_code = CTC_RC_FAILED_INVALID_HANDLE;
    ctcp_header_result.job_desc = ctcp_header->job_desc;
    ctcp_header_result.session_gid = ctcp_header->session_gid;

    make_version_info (&ctcp_header_result);

    ctcp_header_result.header_data = 0;

    write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result));

    session_group->job[ctcp_header->job_desc].is_job_thread_stop = true;

    return -1;
}

