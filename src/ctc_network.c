#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "ctc_network.h"

int make_ctcp_header (CTCP_OP_ID op_id, char op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int header_data, CTCP_HEADER *ctcp_header)
{
    memset (ctcp_header, 0, CTCP_PACKET_HEADER_SIZE);

    /* Operation ID */
    ctcp_header->op_id = op_id;

    /* Operation specific param */
    ctcp_header->op_param_or_result_code = op_param;

    /* Job descriptor */
    if (job_session != NULL && job_session->job_desc != -1)
    {
        ctcp_header->job_desc = job_session->job_desc;
    }

    /* Session group ID */
    if (control_session->session_gid != -1)
    {
        ctcp_header->session_gid = control_session->session_gid;
    }

    /* Protocol version */
    ctcp_header->version[0] = CTCP_MAJOR_VERSION;
    ctcp_header->version[1] = CTCP_MINOR_VERSION;
    ctcp_header->version[2] = CTCP_PATCH_VERSION;
    ctcp_header->version[3] = CTCP_BUILD_VERSION;

    /* etc - job or server status, data length, job attribute value */
    ctcp_header->header_data = header_data;

    return CTC_SUCCESS;
}

int make_ctcp_data_payload (char *ctcp_data_payload, char *data, int data_size)
{
    if (data_size > CTCP_MAX_DATA_PAYLOAD_SIZE)
    {
        goto error;
    }

    memcpy (ctcp_data_payload, data, data_size);

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int send_ctcp (CTCP_OP_ID op_id, char op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int header_data, char *data)
{
    CTCP ctcp;

    int data_payload_size = 0;
    int data_size = 0;
    int retval;

    if (IS_FAILURE (make_ctcp_header (op_id, op_param, control_session, job_session, header_data, &ctcp.header)))
    {
        goto error;
    }

    if (IS_NOT_NULL (data))
    {
        if (IS_FAILURE (make_ctcp_data_payload (ctcp.data_payload, data, header_data)))
        {
            goto error;
        }

        data_payload_size = header_data;
    }

    data_size = CTCP_PACKET_HEADER_SIZE + data_payload_size;

    if (op_id != CTCP_CREATE_JOB_SESSION)
    {
        retval = write (control_session->sockfd, &ctcp, data_size);
        if (retval == -1 || retval < data_size)
        {
            goto error;
        }
    }
    else
    {
        retval = write (job_session->sockfd, &ctcp.header, data_size);
        if (retval == -1 || retval < data_size)
        {
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_operation_id (CTCP_HEADER *ctcp_header, CTCP_OP_ID op_id)
{
    return ctcp_header->op_id == op_id ? CTC_SUCCESS : CTC_FAILURE;
}

int check_result_code (CTCP_HEADER *ctcp_header)
{
    if (ctcp_header->op_param_or_result_code != CTC_RC_SUCCESS &&
        ctcp_header->op_param_or_result_code != CTC_RC_SUCCESS_FRAGMENTED)
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_protocol_version (CTCP_HEADER *ctcp_header)
{
    if (ctcp_header->version[0] != CTCP_MAJOR_VERSION)
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_job_desc (CTCP_HEADER *ctcp_header, JOB_SESSION *job_session)
{
    if (job_session != NULL && job_session->job_desc != -1)
    {
        if (ctcp_header->job_desc != job_session->job_desc)
        {
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_session_gid (CTCP_HEADER *ctcp_header, CONTROL_SESSION *control_session)
{
    if (control_session->session_gid != -1)
    {
        if (ctcp_header->session_gid != control_session->session_gid)
        {
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int set_session_gid (CONTROL_SESSION *control_session, int session_gid)
{
    if (session_gid < 0)
    {
        goto error;
    }

    control_session->session_gid = session_gid;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void set_job_desc (JOB_SESSION *job_session, unsigned short job_desc)
{
    job_session->job_desc = job_desc;
}

int recv_ctcp_header (CTCP_OP_ID op_id, CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTCP_HEADER *ctcp_header)
{
    int retval;

    if (op_id == CTCP_CREATE_JOB_SESSION_RESULT ||
        op_id == CTCP_CAPTURED_DATA_RESULT)
    {
        retval = read (job_session->sockfd, ctcp_header, CTCP_PACKET_HEADER_SIZE);
    }
    else
    {
        retval = read (control_session->sockfd, ctcp_header, CTCP_PACKET_HEADER_SIZE);
    }

    // peer 에서 연결 끊은 경우 고려해야 한다. 에러로 처리 해야하는 경우와 아닌 경우 구분
    if (retval == -1 || retval < CTCP_PACKET_HEADER_SIZE)
    {
        goto error;
    }

    /* Operation ID */
    if (IS_FAILURE (check_operation_id (ctcp_header, op_id)))
    {
        goto error;
    }

    /* Result code */
    if (IS_FAILURE (check_result_code (ctcp_header)))
    {
        goto error;
    }

    /* Job descriptor */
    if (IS_FAILURE (check_job_desc (ctcp_header, job_session)))
    {
        goto error;
    }

    /* Session group ID */
    if (IS_FAILURE (check_session_gid (ctcp_header, control_session)))
    {
        goto error;
    }

    /* Protocol version */
    if (IS_FAILURE (check_protocol_version (ctcp_header)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int recv_ctcp (CTCP_OP_ID op_id, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int *header_data)
{
    CTCP_HEADER ctcp_header;

    if (IS_FAILURE (recv_ctcp_header (op_id, control_session, job_session, &ctcp_header)))
    {
        goto error;
    }

    switch (ctcp_header.op_id)
    {
        case CTCP_CREATE_CONTROL_SESSION_RESULT:
            set_session_gid (control_session, ctcp_header.session_gid);

            break;
        case CTCP_DESTROY_CONTROL_SESSION_RESULT:
            /* nothing to do */

            break;
        case CTCP_CREATE_JOB_SESSION_RESULT:
            set_job_desc (job_session, ctcp_header.job_desc);

            break;
        case CTCP_DESTROY_JOB_SESSION_RESULT:
            /* nothing to do */

            break;
        case CTCP_REQUEST_JOB_STATUS_RESULT:
            *header_data = ctcp_header.header_data;

            break;
        case CTCP_REQUEST_SERVER_STATUS_RESULT:
            *header_data = ctcp_header.header_data;

            break;
        case CTCP_REGISTER_TABLE_RESULT:
            /* nothing to do */

            break;
        case CTCP_UNREGISTER_TABLE_RESULT:
            /* nothing to do */

            break;
        case CTCP_SET_JOB_ATTRIBUTE_RESULT:
            /* nothing to do */

            break;
        case CTCP_START_CAPTURE_RESULT:
            /* nothing to do */
            break;

        case CTCP_STOP_CAPTURE_RESULT:
            /* nothing to do */

            break;
        case CTCP_CAPTURED_DATA_RESULT:
            *header_data = ctcp_header.header_data;
            job_session->result_code = ctcp_header.op_param_or_result_code; // error 처리할 때 코드가 바뀔 것

            break;
        default:
            goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int recv_ctcp_data_payload (JOB_SESSION *job_session, char *buffer, int data_size)
{
    int retval;

    retval = read (job_session->sockfd, buffer, data_size);

    // peer 에서 연결 끊은 경우 고려해야 한다. 에러로 처리 해야하는 경우와 아닌 경우 구분
    if (retval == -1 || retval < CTCP_PACKET_HEADER_SIZE)
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void set_conn_type (CONTROL_SESSION *control_session, CTC_CONN_TYPE conn_type)
{
    control_session->conn_type = conn_type;
}

int open_control_session (CONTROL_SESSION *control_session, CTC_CONN_TYPE conn_type)
{
    struct sockaddr_in server_addr;

    control_session->sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (control_session->sockfd == -1)
    {
        goto error;
    }

    memset (&server_addr, 0, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr (control_session->ip);
    server_addr.sin_port = htons (control_session->port);

    if (IS_FAILURE (connect (control_session->sockfd, (struct sockaddr *)&server_addr, sizeof (server_addr))))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_CREATE_CONTROL_SESSION, conn_type, control_session, NULL, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_CREATE_CONTROL_SESSION_RESULT, control_session, NULL, NULL)))
    {
        goto error;
    }

    set_conn_type (control_session, conn_type);

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int close_control_session (CONTROL_SESSION *control_session)
{
    if (IS_FAILURE (send_ctcp (CTCP_DESTROY_CONTROL_SESSION, 0, control_session, NULL, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_DESTROY_CONTROL_SESSION_RESULT, control_session, NULL, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (close (control_session->sockfd)))
    {
        goto error;
    }

    control_session->sockfd = -1;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int open_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    struct sockaddr_in server_addr;

    job_session->sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (job_session->sockfd == -1)
    {
        goto error;
    }

    memset (&server_addr, 0, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr (control_session->ip);
    server_addr.sin_port = htons (control_session->port);

    if (IS_FAILURE (connect (job_session->sockfd, (struct sockaddr *)&server_addr, sizeof (server_addr))))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_CREATE_JOB_SESSION, 0, control_session, job_session, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_CREATE_JOB_SESSION_RESULT, control_session, job_session, NULL)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int close_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    if (IS_FAILURE (send_ctcp (CTCP_DESTROY_JOB_SESSION, 0, control_session, job_session, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_DESTROY_JOB_SESSION_RESULT, control_session, job_session, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (close (job_session->sockfd)))
    {
        goto error;
    }

    job_session->sockfd = -1;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int close_job_session_socket_only (JOB_SESSION *job_session)
{
    if (IS_FAILURE (close (job_session->sockfd)))
    {
        goto error;
    }

    job_session->sockfd = -1;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_received_server_status (int server_status)
{
    switch (server_status)
    {
        case CTC_SERVER_NOT_READY:
        case CTC_SERVER_RUNNING:
        case CTC_SERVER_CLOSING:
            break;
        default:
            goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int get_server_status (CONTROL_SESSION *control_session, int *server_status)
{
    if (IS_FAILURE (send_ctcp (CTCP_REQUEST_SERVER_STATUS, 0, control_session, NULL, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_REQUEST_SERVER_STATUS_RESULT, control_session, NULL, server_status)))
    {
        goto error;
    }

    if (IS_FAILURE (check_received_server_status (*server_status)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int make_send_data (char *user_name, char *table_name, char *buffer, int buffer_size, int *data_len)
{
    int data_size;
    int user_name_len;
    int table_name_len;
    char *write_pos;

    user_name_len  = strlen (user_name);
    table_name_len = strlen (table_name);

    data_size = sizeof (int) + user_name_len + sizeof (int) + table_name_len;

    if (data_size > buffer_size)
    {
        goto error;
    }

    write_pos = buffer;

    memcpy (write_pos, &user_name_len, sizeof (int));
    write_pos += sizeof (int);

    memcpy (write_pos, user_name, user_name_len);
    write_pos += user_name_len;

    memcpy (write_pos, &table_name_len, sizeof (int));
    write_pos += sizeof (int);

    memcpy (write_pos, table_name, table_name_len);

    *data_len = data_size;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int register_table_to_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name)
{
    char buffer[CTCP_MAX_DATA_PAYLOAD_SIZE];
    int data_len = 0;

    if (IS_FAILURE (make_send_data (user_name, table_name, buffer, CTCP_MAX_DATA_PAYLOAD_SIZE, &data_len)))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_REGISTER_TABLE, 0, control_session, job_session, data_len, buffer)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_REGISTER_TABLE_RESULT, control_session, job_session, NULL)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int unregister_table_from_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name)
{
    char buffer[CTCP_MAX_DATA_PAYLOAD_SIZE];
    int data_len = 0;

    if (IS_FAILURE (make_send_data (user_name, table_name, buffer, CTCP_MAX_DATA_PAYLOAD_SIZE, &data_len)))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_UNREGISTER_TABLE, 0, control_session, job_session, data_len, buffer)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_UNREGISTER_TABLE_RESULT, control_session, job_session, NULL)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void init_capture_trans_buffer_array (JOB_SESSION *job_session)
{
    int i;

    for (i = 0; i < MAX_CAPTURE_TRANS_BUFFER_COUNT; i ++)
    {
        job_session->capture_trans_buffer[i] = NULL;
    }

    job_session->write_idx = 0;
    job_session->read_idx = 0;
}

int cleanup_capture_trans_buffer (JOB_SESSION *job_session)
{
    int i;

    for (i = 0; i < MAX_CAPTURE_TRANS_BUFFER_COUNT; i ++)
    {
        if (IS_NOT_NULL (job_session->capture_trans_buffer[i]))
        {
            free (job_session->capture_trans_buffer[i]);
        }
    }

    job_session->write_idx = 0;
    job_session->read_idx = 0;

    return CTC_SUCCESS;
}

void init_capture_trans_buffer (CAPTURE_TRANS_BUFFER *capture_trans_buffer)
{
    memset (capture_trans_buffer->buffer, 0, CAPTURE_TRANS_BUFFER_SIZE);
    capture_trans_buffer->remaining_buffer_size = CAPTURE_TRANS_BUFFER_SIZE;

    capture_trans_buffer->write_pos = capture_trans_buffer->buffer;
    capture_trans_buffer->read_pos = capture_trans_buffer->buffer;
}

int alloc_capture_trans_buffer (JOB_SESSION *job_session, int requested_buffer_size, char **capture_trans_buffer_p)
{
    CAPTURE_TRANS_BUFFER *capture_trans_buffer;

    if (requested_buffer_size <= 0 || requested_buffer_size > CAPTURE_TRANS_BUFFER_SIZE ||
        IS_NULL (capture_trans_buffer_p))
    {
        goto error;
    }

    while (1)
    {
        capture_trans_buffer = job_session->capture_trans_buffer[job_session->write_idx];

        if (IS_NULL (capture_trans_buffer))
        {
            capture_trans_buffer = (CAPTURE_TRANS_BUFFER *)malloc (sizeof (CAPTURE_TRANS_BUFFER));
            if (IS_NULL (capture_trans_buffer))
            {
                goto error;
            }

            init_capture_trans_buffer (capture_trans_buffer);

            job_session->capture_trans_buffer[job_session->write_idx] = capture_trans_buffer;

            capture_trans_buffer->remaining_buffer_size -= requested_buffer_size;

            *capture_trans_buffer_p = (char *)capture_trans_buffer->write_pos;

            break;
        }
        else
        {
            if (capture_trans_buffer->remaining_buffer_size < requested_buffer_size)
            {
                job_session->write_idx ++;

                if (job_session->write_idx == MAX_CAPTURE_TRANS_BUFFER_COUNT)
                {
                    job_session->write_idx = 0;
                }

                if (job_session->write_idx == job_session->read_idx)
                {
                    // overflow
                    goto error;
                }
            }
            else
            {
                capture_trans_buffer->remaining_buffer_size -= requested_buffer_size;

                *capture_trans_buffer_p = (char *)capture_trans_buffer->write_pos;

                break;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int fetch_capture_transaction_from_server (JOB_SESSION *job_session, char *buffer, int buffer_size, int data_size)
{
    CAPTURE_TRANS_BUFFER *capture_trans_buffer;

    memcpy (buffer, &job_session->result_code, sizeof (job_session->result_code));
    buffer += sizeof (job_session->result_code);

    if (IS_FAILURE (recv_ctcp_data_payload (job_session, buffer, data_size)))
    {
        goto error;
    }

    capture_trans_buffer = job_session->capture_trans_buffer[job_session->write_idx];

    capture_trans_buffer->write_pos += buffer_size;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int fetch_capture_transaction (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    char *buffer;
    int buffer_size;

    int data_payload_size;

    while (job_session->job_thread_is_alive == true)
    {
        data_payload_size = 0;

        if (IS_FAILURE (recv_ctcp (CTCP_CAPTURED_DATA_RESULT, control_session, job_session, &data_payload_size)))
        {
            goto error;
        }

        if (data_payload_size != 0)
        {
            buffer = NULL;
            buffer_size = sizeof (job_session->result_code) + data_payload_size;

            if (IS_FAILURE (alloc_capture_trans_buffer (job_session, buffer_size, &buffer)))
            {
                goto error;
            }

            if (IS_FAILURE (fetch_capture_transaction_from_server (job_session, buffer, buffer_size, data_payload_size)))
            {
                goto error;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void *job_thread_main (void *arg)
{
    JOB_THREAD_ARGS *job_thread_args = (JOB_THREAD_ARGS *)arg;
    int retval;

    CONTROL_SESSION *control_session = job_thread_args->control_session;
    JOB_SESSION *job_session = job_thread_args->job_session;

    job_session->job_thread_is_alive = true;

    init_capture_trans_buffer_array (job_session);

    if (IS_FAILURE (fetch_capture_transaction (control_session, job_session)))
    {
        goto error;
    }

    // 소켓 정리, 종료시 자원 정리
    
    job_session->job_thread_is_alive = false;

    retval = CTC_SUCCESS;

    pthread_exit (NULL);

error:

    // 소켓 정리, 종료시 자원 정리

    job_session->job_thread_is_alive = false;

    retval = CTC_FAILURE;

    pthread_exit (NULL);
}

int create_job_thread (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    job_session->job_thread_args.control_session = control_session;
    job_session->job_thread_args.job_session = job_session;

    if (IS_FAILURE (pthread_create (&job_session->job_thread, NULL, job_thread_main, (void *)&job_session->job_thread_args)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int destroy_job_thread (JOB_SESSION *job_session)
{
    int exit_status;

    job_session->job_thread_is_alive = false;

//    if (IS_FAILURE (pthread_join (job_session->job_thread, (void **)&exit_status)))
    if (IS_FAILURE (pthread_join (job_session->job_thread, NULL)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int start_capture_for_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    if (IS_FAILURE (create_job_thread (control_session, job_session)))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_START_CAPTURE, 0, control_session, job_session, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_START_CAPTURE_RESULT, control_session, job_session, NULL)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void set_quit_job_condition (JOB_SESSION *job_session, CTC_QUIT_JOB_CONDITION quit_job_condition) 
{
    job_session->quit_job_condition = quit_job_condition;
}

int stop_capture_for_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTC_QUIT_JOB_CONDITION quit_job_condition)
{
    if (IS_FAILURE (send_ctcp (CTCP_STOP_CAPTURE, quit_job_condition, control_session, job_session, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_STOP_CAPTURE_RESULT, control_session, job_session, NULL)))
    {
        goto error;
    }

    if (quit_job_condition == CTC_QUIT_JOB_IMMEDIATELY)
    {
        if (IS_FAILURE (destroy_job_thread (job_session)))
        {
            goto error;
        }

        if (IS_FAILURE (cleanup_capture_trans_buffer (job_session)))
        {
            goto error;
        }
    }
    else
    {
        // 이번에 지원 안함
        goto error;
    }

    set_quit_job_condition (job_session, quit_job_condition);

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int reinit_json_type_result (JSON_TYPE_RESULT *json_type_result)
{
    int i;

    for (i = 0; i < json_type_result->write_idx; i ++)
    {
        free (json_type_result->json[i]);
        json_type_result->json[i] = NULL;
    }

    json_type_result->write_idx = 0;
    json_type_result->read_idx = 0;
    json_type_result->is_fragmented = false;

    return CTC_SUCCESS;
}

char *get_read_pos (JOB_SESSION *job_session)
{
    CAPTURE_TRANS_BUFFER *capture_trans_buffer;
    bool is_exist_data;

    is_exist_data = false;

    while (1)
    {
        if (job_session->read_idx != job_session->write_idx)
        {
            capture_trans_buffer = job_session->capture_trans_buffer[job_session->read_idx];

            if (capture_trans_buffer->read_pos < capture_trans_buffer->write_pos)
            {
                is_exist_data = true;
                break;
            }
            else if (capture_trans_buffer->read_pos == capture_trans_buffer->write_pos)
            {
                // 해당 버퍼는 끝까지 읽었다는 것, 여기를 타는데 좀 이상해 보이는 부분도 있다. 이제 막 읽기 시작했고, write 부분이랑 같지 않은데 여기를 탄다면 이상
                free (capture_trans_buffer);

                job_session->capture_trans_buffer[job_session->read_idx] = NULL;
                job_session->read_idx ++;
            }
            else
            {
                // assert
            }
        }
        else
        {
            capture_trans_buffer = job_session->capture_trans_buffer[job_session->read_idx];

            if (IS_NULL (capture_trans_buffer))
            {
                is_exist_data = false;
                break;
            }

            if (capture_trans_buffer->read_pos < capture_trans_buffer->write_pos)
            {
                is_exist_data = true;
                break;
            }
            else if (capture_trans_buffer->read_pos == capture_trans_buffer->write_pos)
            {
                is_exist_data = false;
                break;
            }
            else
            {
                // assert
            }
        }
    }

    return is_exist_data ? capture_trans_buffer->read_pos : NULL;
}

void set_read_pos (JOB_SESSION *job_session, char *next_read_pos)
{
    CAPTURE_TRANS_BUFFER *capture_trans_buffer;

    capture_trans_buffer = job_session->capture_trans_buffer[job_session->read_idx];

    capture_trans_buffer->read_pos = next_read_pos;

    if (capture_trans_buffer->read_pos > capture_trans_buffer->read_pos)
    {
        // assert
    }
}

int read_data_header (char **read_pos_p, JSON_TYPE_RESULT *json_type_result)
{
    char *read_pos;
    char is_fragmented;

    read_pos = *read_pos_p;

    memcpy (&is_fragmented, read_pos, sizeof (is_fragmented));
    read_pos += sizeof (is_fragmented);

    if (is_fragmented == CTC_RC_SUCCESS_FRAGMENTED)
    {
        json_type_result->is_fragmented = true;
    }
    else if (is_fragmented == CTC_RC_SUCCESS)
    {
        json_type_result->is_fragmented = false;
    }
    else
    {
        goto error;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_number_of_items (char **read_pos_p, int *number_of_items)
{
    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (number_of_items, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (*number_of_items > MAX_JSON_TYPE_RESULT_COUNT)
    {
        goto error;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_and_write_transaction_id (char **read_pos_p, char **write_pos_p)
{
    char *read_pos;
    char *write_pos;

    char *tx_id = "{ \"Transaction ID\": \"";
    char *tx_id_val2 = "777";
    int tx_id_val;

    read_pos = *read_pos_p;
    write_pos = *write_pos_p;

    memcpy (write_pos, tx_id, strlen (tx_id));
    write_pos += strlen (tx_id);

    memcpy (&tx_id_val, read_pos, sizeof (int));
    read_pos += sizeof (int);

    //memcpy (write_pos, &tx_id_val, sizeof (int));
    //write_pos += sizeof (int);

    memcpy (write_pos, tx_id_val2, strlen (tx_id_val2));
    write_pos += strlen (tx_id_val2);

    *read_pos_p = read_pos;
    *write_pos_p = write_pos;

    return CTC_SUCCESS;
}

int read_and_write_user_name (char **read_pos_p, char **write_pos_p)
{
    char *read_pos;
    char *write_pos;

    char *user_name = "\", \"User\": \"";
    int user_name_len = 0;

    read_pos = *read_pos_p;
    write_pos = *write_pos_p;

    memcpy (write_pos, user_name, strlen (user_name));
    write_pos += strlen (user_name);

    memcpy (&user_name_len, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (user_name_len <= 0)
    {
        goto error;
    }

    memcpy (write_pos, read_pos, user_name_len);
    read_pos += user_name_len;
    write_pos += user_name_len;

    *read_pos_p = read_pos;
    *write_pos_p = write_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_and_write_table_name (char **read_pos_p, char **write_pos_p)
{
    char *read_pos;
    char *write_pos;

    char *table_name = "\", \"Table\": \"";
    int table_name_len = 0;

    read_pos = *read_pos_p;
    write_pos = *write_pos_p;

    memcpy (write_pos, table_name, strlen (table_name));
    write_pos += strlen (table_name);

    memcpy (&table_name_len, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (table_name_len <= 0)
    {
        goto error;
    }

    memcpy (write_pos, read_pos, table_name_len);
    read_pos += table_name_len;
    write_pos += table_name_len;

    *read_pos_p = read_pos;
    *write_pos_p = write_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_and_write_stmt_type (char **read_pos_p, char **write_pos_p)
{
    char *read_pos;
    char *write_pos;

    char *stmt_type_insert = "\", \"Statement type\": \"insert\", ";
    char *stmt_type_update = "\", \"Statement type\": \"update\", ";
    char *stmt_type_delete = "\", \"Statement type\": \"delete\", ";

    int stmt_type;

    read_pos = *read_pos_p;
    write_pos = *write_pos_p;

    memcpy (&stmt_type, read_pos, sizeof (int));
    read_pos += sizeof (int);

    switch (stmt_type)
    {
        case CTC_STMT_TYPE_INSERT:
            memcpy (write_pos, stmt_type_insert, strlen (stmt_type_insert));
            write_pos += strlen (stmt_type_insert);
            break;
        case CTC_STMT_TYPE_UPDATE:
            memcpy (write_pos, stmt_type_update, strlen (stmt_type_update));
            write_pos += strlen (stmt_type_update);
            break;
        case CTC_STMT_TYPE_DELETE:
            memcpy (write_pos, stmt_type_delete, strlen (stmt_type_delete));
            write_pos += strlen (stmt_type_delete);
            break;
        default:
            goto error;
    }

    *read_pos_p = read_pos;
    *write_pos_p = write_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_and_write_columns (char **read_pos_p, char **write_pos_p)
{
    char *read_pos;
    char *write_pos;

    char *columns = "\"Columns\": { \"";
    char *colon = "\": \"";
    char *comma = "\", \"";
    char *end = "\" } }"; // null 문자 취급되는지 확인

    int number_of_column;

    int column_name_len;
    int column_value_len;

    int i;

    read_pos = *read_pos_p;
    write_pos = *write_pos_p;

    memcpy (write_pos, columns, strlen (columns));
    write_pos += strlen (columns);

    memcpy (&number_of_column, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (number_of_column <= 0)
    {
        goto error;
    }

    for (i = 0; i < number_of_column; i ++)
    {
        /* column name */
        memcpy (&column_name_len, read_pos, sizeof (int));
        read_pos += sizeof (int);

        if (column_name_len <= 0)
        {
            goto error;
        }

        memcpy (write_pos, read_pos, column_name_len);
        read_pos += column_name_len;
        write_pos += column_name_len;

        memcpy (write_pos, colon, strlen (colon));
        write_pos += strlen (colon);

        /* column value */
        memcpy (&column_value_len, read_pos, sizeof (int));
        read_pos += sizeof (int);

        if (column_value_len <= 0 )
        {
            goto error;
        }

        memcpy (write_pos, read_pos, column_value_len);
        read_pos += column_value_len;
        write_pos += column_value_len;

        if (i == number_of_column - 1)
        {
            memcpy (write_pos, end, strlen (end));
            write_pos += strlen (end);
        }
        else
        {
            memcpy (write_pos, comma, strlen (comma));
            write_pos += strlen (comma);
        }
    }

    write_pos[0] = '\0'; // 문자열로 만들어 준다.
    write_pos ++;

    *read_pos_p = read_pos;
    *write_pos_p = write_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int register_to_json_type_result (JSON_TYPE_RESULT *json_type_result, char *json_buffer)
{
    char *json;

    json = strdup (json_buffer);
    if (IS_NULL (json))
    {
        goto error;
    }

    json_type_result->json[json_type_result->write_idx ++] = json;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int convert_capture_transaction_to_json (JOB_SESSION *job_session, JSON_TYPE_RESULT *json_type_result)
{
    int i;
    int number_of_items;

    char *read_pos;
    char *write_pos;

    char temp[4096];

    read_pos = get_read_pos (job_session);
    if (IS_NULL (read_pos))
    {
        goto end;
    }

    if (IS_FAILURE (read_data_header (&read_pos, json_type_result)))
    {
        goto error;
    }

    if (IS_FAILURE (read_number_of_items (&read_pos, &number_of_items)))
    {
        goto error;
    }

    if (number_of_items <= 0)
    {
        goto error;
    }

    for (i = 0; i < number_of_items; i ++)
    {
        write_pos = temp;

        /* Transaction ID */
        if (IS_FAILURE (read_and_write_transaction_id (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* User name */
        if (IS_FAILURE (read_and_write_user_name (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* Table name */
        if (IS_FAILURE (read_and_write_table_name (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* Statement type */
        if (IS_FAILURE (read_and_write_stmt_type (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* Columns */
        if (IS_FAILURE (read_and_write_columns (&read_pos, &write_pos)))
        {
            goto error;
        }

        if (IS_FAILURE (register_to_json_type_result (json_type_result, temp)))
        {
            goto error;
        }
    }

    set_read_pos (job_session, read_pos);

end:

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_capture_transaction_in_json (JOB_SESSION *job_session, JSON_TYPE_RESULT *json_type_result)
{
    if (IS_FAILURE (reinit_json_type_result (json_type_result)))
    {
        goto error;
    }

    if (IS_FAILURE (convert_capture_transaction_to_json (job_session, json_type_result)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_received_job_status (int job_status)
{
    switch (job_status)
    {
        case CTC_JOB_NONE:
        case CTC_JOB_WAITING:
        case CTC_JOB_PROCESSING:
        case CTC_JOB_READY_TO_FETCH:
        case CTC_JOB_CLOSING:
            break;
        default:
            goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int get_job_status (CONTROL_SESSION *control_session, JOB_SESSION *job_session, int *job_status)
{
    if (IS_FAILURE (send_ctcp (CTCP_REQUEST_JOB_STATUS, 0, control_session, job_session, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_REQUEST_JOB_STATUS_RESULT, control_session, job_session, job_status)))
    {
        goto error;
    }

    if (IS_FAILURE (check_received_job_status (*job_status)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}
