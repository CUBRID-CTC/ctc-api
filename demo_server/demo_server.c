//32개의 클라이언트 처리
//32개 클라이언트에서 각각 16개의 테이블 생성 ==> 총 512개
//한 클라이언트에서 처리하는 테이블의 수는 16개

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <pthread.h>
#include "demo_server.h"

#define PRINT_ERR_LOG() do { printf ("[ERROR] %s () at %s:%d\n", __func__, __FILE__, __LINE__); } while (0)

SESSION_GROUP session_group_arr[MAX_SESSION_GROUP_COUNT];
int next_session_gid = 0;

int execute_server (int listen_port, int max_client);
int execute_service (int service_fd);
int execute_service_ctrl_session (int ctrl_fd, SESSION_GROUP *session_group, int *is_finish);
int execute_service_job_session (int service_fd);
int process_CREATE_CONTROL_SESSION (CTCP_HEADER *ctcp_header, int service_fd);
int process_CREATE_JOB_SESSION (CTCP_HEADER *ctcp_header, int service_fd);

void usage ()
{
    printf ("demo_server [PORT] [MAX_CLIENT] [LIFE_TIME]\n");
    printf ("ex) ./demo_server 20000 32 60\n");
}

int main (int argc, char *argv[])
{
    int listen_port;
    int max_client;
    int life_time;

    if (argc < 3)
    {
        usage ();
        exit (1);
    }

    listen_port = atoi (argv[1]);
    max_client = atoi (argv[2]);

    if (listen_port > 65535)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (max_client > MAX_SESSION_GROUP_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    printf ("demo_server start\n");

    if (-1 == execute_server (listen_port, max_client))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    printf ("demo_server stop\n");

    return 0;

error:

    return -1;
}

int execute_server (int listen_port, int max_client)
{
    int listen_fd, service_fd;
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

    if (listen (listen_fd, max_client) < 0)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    // demo_server 이기 때문에 max_client 까지만 서비스하고 종료
    while (max_client)
    {
        addr_len = sizeof (client_addr);

        service_fd = accept (listen_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (service_fd < 0)
        {
            PRINT_ERR_LOG ();
            goto error;
        }

        if (-1 == execute_service (service_fd))
        {
            PRINT_ERR_LOG ();
            goto error;
        }

        max_client --;
    }

    close (listen_fd);

    return 0;

error:

    return -1;
}

// server의 listen 소켓 요청 처리 함수
int execute_service (int service_fd)
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
int execute_service_ctrl_session (int ctrl_fd, SESSION_GROUP *session_group, int *is_finish)
{
    CTCP_HEADER ctcp_header;
    int retval;

    retval = read (ctrl_fd, &ctcp_header, sizeof (ctcp_header));
    if (retval == -1 || retval < sizeof (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    switch (ctcp_header.op_id)
    {
        case CTCP_DESTROY_CONTROL_SESSION:

            *is_finish = 1;

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

            break;
        case CTCP_STOP_CAPTURE:

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

int execute_service_job_session (int service_fd)
{
    CTCP_HEADER ctcp_header;
    int retval;

    retval = read (service_fd, &ctcp_header, sizeof (ctcp_header));
    if (retval == -1 || retval < sizeof (ctcp_header))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    switch (ctcp_header.op_id)
    {
        case CTCP_CREATE_CONTROL_SESSION:
            if (-1 == process_CREATE_CONTROL_SESSION (&ctcp_header, service_fd))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_DESTROY_CONTROL_SESSION:

            break;
        case CTCP_CREATE_JOB_SESSION:
            // job 생성 요청은 구현 상의 이슈로 listen_socket 으로 처리
            if (-1 == process_CREATE_JOB_SESSION (&ctcp_header, service_fd))
            {
                PRINT_ERR_LOG ();
                goto error;
            }

            break;
        case CTCP_DESTROY_JOB_SESSION:

            break;
        case CTCP_REQUEST_JOB_STATUS:

            break;
        case CTCP_REQUEST_SERVER_STATUS:

            break;
        case CTCP_REGISTER_TABLE:

            break;
        case CTCP_UNREGISTER_TABLE:

            break;
        case CTCP_SET_JOB_ATTRIBUTE:

            break;
        case CTCP_START_CAPTURE:

            break;
        case CTCP_STOP_CAPTURE:

            break;
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

void *execute_control_thread (void *sess_group)
{
    SESSION_GROUP *session_group = sess_group;
    CTCP_HEADER ctcp_header;

    int is_finish = 0;

    /* send CTCP_CREATE_CONTROL_SESSION_RESULT */
    ctcp_header.op_id = CTCP_CREATE_CONTROL_SESSION_RESULT;
    ctcp_header.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header.job_desc = 0;
    ctcp_header.session_gid = session_group->session_gid;

    make_version_info (&ctcp_header);

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header, sizeof (ctcp_header)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    while (1)
    {
        // control session 으로 요청 받을 수 있는 ctcp 대기
        if (-1 == execute_service_ctrl_session (session_group->ctrl_sockfd, session_group, &is_finish))
        {
            PRINT_ERR_LOG ();
            goto error;
        }

        if (is_finish == 1)
        {
            break;
        }
    }

    // job 정리가 필요하면 여기서

    pthread_exit (NULL);

error:

    pthread_exit (NULL);
}

int process_CREATE_CONTROL_SESSION (CTCP_HEADER *ctcp_header, int service_fd)
{
    SESSION_GROUP *session_group;
    int i;

    // 여러 클라이언트 동시 접속 처리하려면 공유 변수 사용시 뮤텍스 처리
    if (next_session_gid >= MAX_SESSION_GROUP_COUNT)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

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

    // session_group 할당
    session_group = &session_group_arr[next_session_gid];

    session_group->session_gid = next_session_gid;

    next_session_gid ++;

    session_group->conn_type = ctcp_header->op_param_or_result_code;

    // job 배열 초기화
    for (i = 0; i < MAX_JOB_COUNT; i ++)
    {
        session_group->job[i].is_use = 0;
        session_group->job[i].job_desc = i;
    }

    session_group->ctrl_sockfd = service_fd;

    // control session 요청을 처리하는 쓰레드 생성
    if (0 != pthread_create (&session_group->control_thread, NULL, execute_control_thread, (void *)session_group))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (0 != pthread_detach (session_group->control_thread))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

    return -1;
}

    /*
       typedef struct ctcp_header CTCP_HEADER;
       struct ctcp_header
       {
       unsigned char op_id;
       char op_param_or_result_code;
       unsigned short job_desc;
       int session_gid;
       char version[4];gg
       int header_data;
       */
void *execute_job_thread (void *job_p)
{
    JOB *job = job_p;
    CTCP_HEADER ctcp_header;

    // send CTCP_CREATE_JOB_SESSION_RESULT
    ctcp_header.op_id = CTCP_CREATE_CONTROL_SESSION_RESULT;
    ctcp_header.op_param_or_result_code = CTC_RC_SUCCESS;
    ctcp_header.job_desc = job->job_desc;
    ctcp_header.session_gid = job->session_gid;

    make_version_info (&ctcp_header);

    if (-1 == write (job->job_sockfd, &ctcp_header, sizeof (ctcp_header)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    while (1)
    {
        // control session으로 CTCP_START_CAPTURE 받을 때 까지 할 일 없다.
        // 일단 demo_server 니깐 flag로 처리하고 추후 테스트시 문제가 되면 condition value 나 기타 다른 방법 강구
        if (job->is_capture_start == 1)
        {

        }

        if (job->is_stop == 1)
        {
            break;
        }

        sleep (1);
    }

    pthread_exit (NULL);

error:

    job->is_use = 0;

    pthread_exit (NULL);
}

int process_CREATE_JOB_SESSION (CTCP_HEADER *ctcp_header, int service_fd)
{
    SESSION_GROUP *session_group;
    JOB *job;
    int i;

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

    session_group = &session_group_arr[ctcp_header->session_gid];

    // 클라이언트가 job 단위로 쓰레드를 돌리지 않는 이상 동시성 제어 불필요
    job = NULL;

    for (i = 0; i < MAX_JOB_COUNT; i ++)
    {
        if (session_group->job[i].is_use == 0)
        {
            job = &session_group->job[i];
            session_group->job[i].is_use = 1;
        }
    }

    if (job == NULL)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    job->session_gid = session_group->session_gid;

    job->job_sockfd = service_fd;

    job->is_capture_start = 0;
    job->is_stop = 0;

    // job session 요청을 처리하는 쓰레드 생성
    if (0 != pthread_create (&job->job_thread, NULL, execute_job_thread, (void *)job))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

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

    if (job->is_use != 1)
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    job->is_capture_start = 0;
    job->is_stop = 1;

    if (0 != pthread_join (job->job_thread, NULL))
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

    job->is_use = 0;
  
    return 0;

error:

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

    if (job->is_use != 1)
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
    if (job->is_capture_start == 1)
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

    // 서버는 항상 수행 중
    ctcp_header_result.header_data = 1; /* CTC_SERVER_RUNNING */

    if (-1 == write (session_group->ctrl_sockfd, &ctcp_header_result, sizeof (ctcp_header_result)))
    {
        PRINT_ERR_LOG ();
        goto error;
    }
  
    return 0;

error:

    return -1;
}

int process_REGISTER_TABLE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;
    JOB *job;

    int data_len;
    int retval;
    char data_buffer[1024];


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

    /* 사용자 명, 테이블 명 읽을 필요가 있다면 여기서 처리 */

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != 1)
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

    return -1;
}

int process_UNREGISTER_TABLE (CTCP_HEADER *ctcp_header, SESSION_GROUP *session_group)
{
    CTCP_HEADER ctcp_header_result;
    JOB *job;

    int data_len;
    int retval;
    char data_buffer[1024];

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

    /* 사용자 명, 테이블 명 읽을 필요가 있다면 여기서 처리 */

    // get job
    job = &session_group->job[ctcp_header->job_desc];

    if (job->is_use != 1)
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

    return -1;
}
