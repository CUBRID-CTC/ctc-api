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

    int retval;

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
        if (-1 == execute_service (session_group->ctrl_sockfd))
        {
            PRINT_ERR_LOG ();
            goto error;
        }
    }

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

    session_group->conn_type = ctcp_header->op_param_or_result_code;

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

    next_session_gid ++;

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
void *execute_job_thread (JOB *job)
{
#if 0
    CTCP_HEADER ctcp_header;

    int retval;

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
        if (-1 == execute_service (session_group->ctrl_sockfd))
        {
            PRINT_ERR_LOG ();
            goto error;
        }
    }

    pthread_exit (NULL);

error:

    pthread_exit (NULL);
#endif
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

    // job session 요청을 처리하는 쓰레드 생성
    if (0 != pthread_create (&job->job_thread, NULL, execute_job_thread, (void *)job))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    if (0 != pthread_detach (job->job_thread))
    {
        PRINT_ERR_LOG ();
        goto error;
    }

    return 0;

error:

    return -1;
}

#if 0
        inet_ntop (AF_INET, &client_addr.sin_addr.s_addr, temp, sizeof (temp));
        printf ("Server : %s client connected.\n", temp);

        msg_size = read (client_fd, buffer, 1024);
        write (client_fd, buffer, msg_size);
        close (client_fd);
        printf ("Server : %s client closed.\n", temp);
#endif
