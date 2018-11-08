#include <stdio.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include "ctc_network.h"

int make_ctcp_header (CTCP_OP_ID op_id, char op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int header_data, CTCP *ctcp)
{
    memset (&ctcp->header, 0, CTCP_PACKET_HEADER_SIZE);

    /* Operation ID */
    ctcp->header.op_id = op_id;

    /* Operation specific param */
    ctcp->header.op_param_or_result_code = op_param;

    /* Job descriptor */
    if (job_session != NULL && job_session->job_desc != INITIAL_JOB_DESC)
    {
        ctcp->header.job_desc = job_session->job_desc;
    }

    /* Session group ID */
    if (control_session->session_gid != INITIAL_SESSION_GID)
    {
        ctcp->header.session_gid = control_session->session_gid;
    }

    /* Protocol version */
    ctcp->header.version[0] = CTCP_MAJOR_VERSION;
    ctcp->header.version[1] = CTCP_MINOR_VERSION;
    ctcp->header.version[2] = CTCP_PATCH_VERSION;
    ctcp->header.version[3] = CTCP_BUILD_VERSION;

    /* etc - job or server status, data length, job attribute value */
    ctcp->header.header_data = header_data;

    return CTC_SUCCESS;
}

int make_ctcp_data_payload (char *data, int data_size, CTCP *ctcp)
{
    if (data_size > CTCP_MAX_DATA_PAYLOAD_SIZE)
    {
        return CTC_FAILED_OVERFLOW_DATA_PAYLOAD;
    }

    memcpy (ctcp->data_payload, data, data_size);

    return CTC_SUCCESS;
}

int send_stream (int sockfd, char *data, int data_size)
{
    int write_size;

    while (data_size > 0)
    {
        write_size = write (sockfd, data, data_size);
        if (write_size <= 0)
        {
            return CTC_FAILED;
        }

        data += write_size;
        data_size -= write_size;
    }

    return CTC_SUCCESS;
}

int send_ctcp (CTCP_OP_ID op_id, char op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int header_data, char *data)
{
    CTCP ctcp;

    int data_payload_size = 0;
    int ctcp_size = 0;
    int retval;

    retval = make_ctcp_header (op_id, op_param, control_session, job_session, header_data, &ctcp);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    if (op_id == CTCP_REGISTER_TABLE ||
        op_id == CTCP_UNREGISTER_TABLE)
    {
        retval = make_ctcp_data_payload (data, header_data, &ctcp);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        data_payload_size = header_data;
    }

    ctcp_size = CTCP_PACKET_HEADER_SIZE + data_payload_size;

    if (op_id != CTCP_CREATE_JOB_SESSION)
    {
        if (IS_FAILED (send_stream (control_session->sockfd, (char *)&ctcp, ctcp_size)))
        {
            retval = CTC_FAILED_COMMUNICATE_CONTROL_SESSION;
            goto error;
        }
    }
    else
    {
        if (IS_FAILED (send_stream (job_session->sockfd, (char *)&ctcp.header, ctcp_size)))
        {
            retval = CTC_FAILED_COMMUNICATE_JOB_SESSION;
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int check_operation_id (CTCP_HEADER *ctcp_header, CTCP_OP_ID op_id)
{
    if (ctcp_header->op_id != op_id)
    {
        return CTC_FAILED_RECEIVE_INVALID_OP_ID;
    }

    return CTC_SUCCESS;
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

    return CTC_FAILED;
}

int check_job_desc (CTCP_HEADER *ctcp_header, JOB_SESSION *job_session)
{
    if (job_session != NULL && job_session->job_desc != INITIAL_JOB_DESC)
    {
        if (ctcp_header->job_desc != job_session->job_desc)
        {
            return CTC_FAILED_RECEIVE_INVALID_JOB_DESC;
        }
    }

    return CTC_SUCCESS;
}

int check_session_gid (CTCP_HEADER *ctcp_header, CONTROL_SESSION *control_session)
{
    if (control_session->session_gid != INITIAL_SESSION_GID)
    {
        if (ctcp_header->session_gid != control_session->session_gid)
        {
            return CTC_FAILED_RECEIVE_INVALID_SESSION_GID;
        }
    }

    return CTC_SUCCESS;
}

int check_protocol_version (CTCP_HEADER *ctcp_header)
{
    if (ctcp_header->version[0] != CTCP_MAJOR_VERSION)
    {
        return CTC_FAILED_RECEIVE_NOT_SUPPORTED_PROTOCOL;
    }

    return CTC_SUCCESS;
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

    return CTC_FAILED;
}

void set_job_desc (JOB_SESSION *job_session, unsigned short job_desc)
{
    job_session->job_desc = job_desc;
}

int recv_stream (int sockfd, char *buffer, int requested_recv_size, int timeout)
{
    struct pollfd poll_fds[1];
    int poll_timeout;
    int total_read_size;
    int read_size;
    int retval;

    total_read_size = 0;

    while (total_read_size < requested_recv_size)
    {
        poll_fds[0].fd = sockfd;
        poll_fds[0].events = POLLIN;

        if (timeout <= 0 || timeout > SOCKET_TIMEOUT)
        {
            poll_timeout = SOCKET_TIMEOUT;
        }
        else
        {
            poll_timeout = timeout;
        }

        retval = poll (poll_fds, 1, poll_timeout);

        if (retval == 0) /* timeout */
        {
            return CTC_FAILED;
        }
        else if (retval < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            return CTC_FAILED;
        }
        else
        {
            if (poll_fds[0].revents & POLLERR || poll_fds[0].revents & POLLHUP)
            {
                return CTC_FAILED;
            }

            read_size = read (sockfd, buffer + total_read_size, requested_recv_size - total_read_size);
            if (read_size <= 0)
            {
                return CTC_FAILED;
            }

            total_read_size += read_size;
        }
    }

    return CTC_SUCCESS;
}

int recv_ctcp_header (CTCP_OP_ID op_id, CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTCP_HEADER *ctcp_header)
{
    int retval;

    if (op_id == CTCP_CREATE_JOB_SESSION_RESULT ||
        op_id == CTCP_CAPTURED_DATA_RESULT)
    {
        retval = recv_stream (job_session->sockfd, (char *)ctcp_header, CTCP_PACKET_HEADER_SIZE, 0);
        if (IS_FAILED (retval))
        {
            retval = CTC_FAILED_COMMUNICATE_JOB_SESSION;
            goto error;
        }
    }
    else
    {
        retval = recv_stream (control_session->sockfd, (char *)ctcp_header, CTCP_PACKET_HEADER_SIZE, 0);
        if (IS_FAILED (retval))
        {
            retval = CTC_FAILED_COMMUNICATE_CONTROL_SESSION;
            goto error;
        }
    }

    /* Operation ID */
    retval = check_operation_id (ctcp_header, op_id);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Result code */
    if (IS_FAILED (check_result_code (ctcp_header)))
    {
        goto error;
    }

    /* Job descriptor */
    retval = check_job_desc (ctcp_header, job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Session group ID */
    retval = check_session_gid (ctcp_header, control_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Protocol version */
    retval = check_protocol_version (ctcp_header);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int recv_ctcp (CTCP_OP_ID op_id, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int *header_data)
{
    CTCP ctcp;
    int retval;

    retval = recv_ctcp_header (op_id, control_session, job_session, &ctcp.header);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    switch (ctcp.header.op_id)
    {
        case CTCP_CREATE_CONTROL_SESSION_RESULT:
            set_session_gid (control_session, ctcp.header.session_gid);

            break;
        case CTCP_CREATE_JOB_SESSION_RESULT:
            set_job_desc (job_session, ctcp.header.job_desc);

            break;
        case CTCP_REQUEST_JOB_STATUS_RESULT:
            *header_data = ctcp.header.header_data;

            break;
        case CTCP_REQUEST_SERVER_STATUS_RESULT:
            *header_data = ctcp.header.header_data;

            break;
        case CTCP_CAPTURED_DATA_RESULT:
            *header_data = ctcp.header.header_data;
            job_session->result_code = ctcp.header.op_param_or_result_code; // error 처리할 때 코드가 바뀔 것

            break;
        default:
            // assert
            goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
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

    return CTC_FAILED;
}

int open_control_session (CONTROL_SESSION *control_session, CTC_CONN_TYPE conn_type)
{
    struct sockaddr_in server_addr;
    int retval;

    int state = 0;

    control_session->sockfd = socket (PF_INET, SOCK_STREAM, 0);
    if (control_session->sockfd == -1)
    {
        retval = CTC_FAILED_OPEN_CONTROL_SESSION;
        goto error;
    }

    state = 1;

    memset (&server_addr, 0, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr (control_session->ip);
    server_addr.sin_port = htons (control_session->port);

    if (IS_FAILED (connect (control_session->sockfd, (struct sockaddr *)&server_addr, sizeof (server_addr))))
    {
        retval = CTC_FAILED_OPEN_CONTROL_SESSION;
        goto error;
    }

    retval = send_ctcp (CTCP_CREATE_CONTROL_SESSION, conn_type, control_session, NULL, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_CREATE_CONTROL_SESSION_RESULT, control_session, NULL, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        close (control_session->sockfd);
    }

    return retval;
}

int close_control_session (CONTROL_SESSION *control_session)
{
    int retval;

    retval = send_ctcp (CTCP_DESTROY_CONTROL_SESSION, 0, control_session, NULL, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_DESTROY_CONTROL_SESSION_RESULT, control_session, NULL, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    if (IS_FAILED (close (control_session->sockfd)))
    {
        retval = CTC_FAILED_CLOSE_CONTROL_SESSION;
        goto error;
    }

    return CTC_SUCCESS;

error:

    close (control_session->sockfd);

    return retval;
}

int open_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    struct sockaddr_in server_addr;
    int retval;

    int state = 0;

    job_session->sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (job_session->sockfd == -1)
    {
        retval = CTC_FAILED_OPEN_JOB_SESSION;
        goto error;
    }

    state = 1;

    memset (&server_addr, 0, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr (control_session->ip);
    server_addr.sin_port = htons (control_session->port);

    if (IS_FAILED (connect (job_session->sockfd, (struct sockaddr *)&server_addr, sizeof (server_addr))))
    {
        retval = CTC_FAILED_OPEN_JOB_SESSION;
        goto error;
    }

    retval = send_ctcp (CTCP_CREATE_JOB_SESSION, 0, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_CREATE_JOB_SESSION_RESULT, control_session, job_session, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        close (job_session->sockfd);
    }

    return retval;
}

int close_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    int retval;

    retval = send_ctcp (CTCP_DESTROY_JOB_SESSION, 0, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_DESTROY_JOB_SESSION_RESULT, control_session, job_session, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    if (IS_FAILED (close (job_session->sockfd)))
    {
        retval = CTC_FAILED_CLOSE_JOB_SESSION;
        goto error;
    }

    return CTC_SUCCESS;

error:

    close (job_session->sockfd);

    return retval;
}

int close_job_session_socket_only (JOB_SESSION *job_session)
{
    if (IS_FAILED (close (job_session->sockfd)))
    {
        goto error;
    }

    job_session->sockfd = -1;

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int check_received_server_status (int server_status)
{
    if (server_status == CTC_SERVER_NOT_READY ||
        server_status == CTC_SERVER_RUNNING ||
        server_status == CTC_SERVER_CLOSING)
    {
        return CTC_SUCCESS;
    }
    else
    {
        return CTC_FAILED_RECEIVE_INVALID_STATUS;
    }
}

int request_server_status (CONTROL_SESSION *control_session, int *server_status)
{
    int retval;

    retval = send_ctcp (CTCP_REQUEST_SERVER_STATUS, 0, control_session, NULL, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_REQUEST_SERVER_STATUS_RESULT, control_session, NULL, server_status);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = check_received_server_status (*server_status);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int make_data_payload (char *user_name, char *table_name, char *buffer, int buffer_size, int *data_len)
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
        return CTC_FAILED_OVERFLOW_DATA_PAYLOAD;
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
}

int request_register_table (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name)
{
    char data_payload[CTCP_MAX_DATA_PAYLOAD_SIZE];
    int data_payload_len = 0;
    int retval;

    retval = make_data_payload (user_name, table_name, data_payload, CTCP_MAX_DATA_PAYLOAD_SIZE, &data_payload_len);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = send_ctcp (CTCP_REGISTER_TABLE, 0, control_session, job_session, data_payload_len, data_payload);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_REGISTER_TABLE_RESULT, control_session, job_session, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int request_unregister_table (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *user_name, char *table_name)
{
    char data_payload[CTCP_MAX_DATA_PAYLOAD_SIZE];
    int data_payload_len = 0;
    int retval;

    retval = make_data_payload (user_name, table_name, data_payload, CTCP_MAX_DATA_PAYLOAD_SIZE, &data_payload_len);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = send_ctcp (CTCP_UNREGISTER_TABLE, 0, control_session, job_session, data_payload_len, data_payload);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_UNREGISTER_TABLE_RESULT, control_session, job_session, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
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

    return CTC_FAILED;
}

int fetch_capture_transaction_from_server (JOB_SESSION *job_session, char *buffer, int buffer_size, int data_size)
{
    CAPTURE_TRANS_BUFFER *capture_trans_buffer;

    memcpy (buffer, &job_session->result_code, sizeof (job_session->result_code));
    buffer += sizeof (job_session->result_code);

    if (IS_FAILED (recv_ctcp_data_payload (job_session, buffer, data_size)))
    {
        goto error;
    }

    capture_trans_buffer = job_session->capture_trans_buffer[job_session->write_idx];

    capture_trans_buffer->write_pos += buffer_size;

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int fetch_capture_transaction (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    char *buffer;
    int buffer_size;

    int data_payload_size;

    while (job_session->is_alive_job_thread == true)
    {
        data_payload_size = 0;

        if (IS_FAILED (recv_ctcp (CTCP_CAPTURED_DATA_RESULT, control_session, job_session, &data_payload_size)))
        {
            goto error;
        }

        if (data_payload_size != 0)
        {
            buffer = NULL;
            buffer_size = sizeof (job_session->result_code) + data_payload_size;

            if (IS_FAILED (alloc_capture_trans_buffer (job_session, buffer_size, &buffer)))
            {
                goto error;
            }

            if (IS_FAILED (fetch_capture_transaction_from_server (job_session, buffer, buffer_size, data_payload_size)))
            {
                goto error;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

void *job_thread_main (void *arg)
{
    JOB_THREAD_ARGS *job_thread_args = (JOB_THREAD_ARGS *)arg;
    int retval;

    CONTROL_SESSION *control_session = job_thread_args->control_session;
    JOB_SESSION *job_session = job_thread_args->job_session;

    job_session->is_alive_job_thread = true;

    init_capture_trans_buffer_array (job_session);

    if (IS_FAILED (fetch_capture_transaction (control_session, job_session)))
    {
        goto error;
    }

    // 소켓 정리, 종료시 자원 정리
    
    job_session->is_alive_job_thread = false;

    retval = CTC_SUCCESS;

    pthread_exit (NULL);

error:

    // 소켓 정리, 종료시 자원 정리

    job_session->is_alive_job_thread = false;

    retval = CTC_FAILED;

    pthread_exit (NULL);
}

int create_job_thread (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    job_session->job_thread.thr_args.control_session = control_session;
    job_session->job_thread.thr_args.job_session = job_session;

    if (IS_FAILED (pthread_create (&job_session->job_thread.thr_id, NULL, job_thread_main, (void *)&job_session->job_thread.thr_args)))
    {
        return CTC_FAILED_CREATE_JOB_THREAD;
    }

    return CTC_SUCCESS;
}

int destroy_job_thread (JOB_SESSION *job_session)
{
    int exit_status;

    job_session->is_alive_job_thread = false;

    if (IS_FAILED (pthread_join (job_session->job_thread.thr_id, NULL)))
    {
        return CTC_FAILED_DESTROY_JOB_THREAD;
    }

    return CTC_SUCCESS;
}

int request_start_capture (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    int retval;

    retval = create_job_thread (control_session, job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = send_ctcp (CTCP_START_CAPTURE, 0, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_START_CAPTURE_RESULT, control_session, job_session, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

void set_job_close_condition (JOB_SESSION *job_session, CTC_JOB_CLOSE_CONDITION job_close_condition) 
{
    job_session->job_close_condition = job_close_condition;
}

int request_stop_capture (CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTC_JOB_CLOSE_CONDITION job_close_condition)
{
    int retval;

    retval = send_ctcp (CTCP_STOP_CAPTURE, job_close_condition, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_STOP_CAPTURE_RESULT, control_session, job_session, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    if (job_close_condition == CTC_JOB_CLOSE_IMMEDIATELY)
    {
        if (IS_FAILED (destroy_job_thread (job_session)))
        {
            goto error;
        }

        if (IS_FAILED (cleanup_capture_trans_buffer (job_session)))
        {
            goto error;
        }
    }
    else
    {
        // 이번에 지원 안함
        goto error;
    }

    set_job_close_condition (job_session, job_close_condition);

    return CTC_SUCCESS;

error:

    return retval;
}

int reinit_json_result (JSON_RESULT *json_result)
{
    int i;

    for (i = 0; i < json_result->write_idx; i ++)
    {
        free (json_result->json[i]);
        json_result->json[i] = NULL;
    }

    json_result->write_idx = 0;
    json_result->read_idx = 0;
    json_result->is_fragmented = false;

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

int read_data_header (char **read_pos_p, JSON_RESULT *json_result)
{
    char *read_pos;
    char is_fragmented;

    read_pos = *read_pos_p;

    memcpy (&is_fragmented, read_pos, sizeof (is_fragmented));
    read_pos += sizeof (is_fragmented);

    if (is_fragmented == CTC_RC_SUCCESS_FRAGMENTED)
    {
        json_result->is_fragmented = true;
    }
    else if (is_fragmented == CTC_RC_SUCCESS)
    {
        json_result->is_fragmented = false;
    }
    else
    {
        goto error;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int read_number_of_items (char **read_pos_p, int *number_of_items)
{
    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (number_of_items, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (*number_of_items > JSON_RESULT_MAX_COUNT)
    {
        goto error;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
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

    return CTC_FAILED;
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

    return CTC_FAILED;
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

    return CTC_FAILED;
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

    return CTC_FAILED;
}

int register_to_json_result (JSON_RESULT *json_result, char *json_buffer)
{
    char *json;

    json = strdup (json_buffer);
    if (IS_NULL (json))
    {
        goto error;
    }

    json_result->json[json_result->write_idx ++] = json;

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int convert_capture_transaction_to_json (JOB_SESSION *job_session, JSON_RESULT *json_result)
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

    if (IS_FAILED (read_data_header (&read_pos, json_result)))
    {
        goto error;
    }

    if (IS_FAILED (read_number_of_items (&read_pos, &number_of_items)))
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
        if (IS_FAILED (read_and_write_transaction_id (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* User name */
        if (IS_FAILED (read_and_write_user_name (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* Table name */
        if (IS_FAILED (read_and_write_table_name (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* Statement type */
        if (IS_FAILED (read_and_write_stmt_type (&read_pos, &write_pos)))
        {
            goto error;
        }

        /* Columns */
        if (IS_FAILED (read_and_write_columns (&read_pos, &write_pos)))
        {
            goto error;
        }

        if (IS_FAILED (register_to_json_result (json_result, temp)))
        {
            goto error;
        }
    }

    set_read_pos (job_session, read_pos);

end:

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int read_capture_transaction_in_json (JOB_SESSION *job_session, JSON_RESULT *json_result)
{
    if (IS_FAILED (reinit_json_result (json_result)))
    {
        goto error;
    }

    if (IS_FAILED (convert_capture_transaction_to_json (job_session, json_result)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILED;
}

int check_received_job_status (int job_status)
{
    if (job_status == CTC_JOB_WAITING ||
        job_status == CTC_JOB_PROCESSING ||
        job_status == CTC_JOB_READY_TO_FETCH ||
        job_status == CTC_JOB_CLOSING)
    {
        return CTC_SUCCESS;
    }
    else
    {
        return CTC_FAILED_RECEIVE_INVALID_STATUS;
    }
}

int request_job_status (CONTROL_SESSION *control_session, JOB_SESSION *job_session, int *job_status)
{
    int retval;

    retval = send_ctcp (CTCP_REQUEST_JOB_STATUS, 0, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp (CTCP_REQUEST_JOB_STATUS_RESULT, control_session, job_session, job_status);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = check_received_job_status (*job_status);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}
