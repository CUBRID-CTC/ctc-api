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
    if (data_size > CTCP_DATA_PAYLOAD_MAX_SIZE)
    {
        return CTC_FAILED_OVERFLOW_DATA_PAYLOAD_MAX_SIZE;
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
    int send_data_size = 0;
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

    send_data_size = CTCP_PACKET_HEADER_SIZE + data_payload_size;

    if (op_id != CTCP_CREATE_JOB_SESSION)
    {
        if (IS_FAILED (send_stream (control_session->sockfd, (char *)&ctcp, send_data_size)))
        {
            retval = CTC_FAILED_COMMUNICATE_CONTROL_SESSION;
            goto error;
        }
    }
    else
    {
        if (IS_FAILED (send_stream (job_session->sockfd, (char *)&ctcp.header, send_data_size)))
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
    switch (ctcp_header->op_param_or_result_code)
    {
        case CTC_RC_SUCCESS:
        case CTC_RC_SUCCESS_FRAGMENTED:
            return CTC_SUCCESS;

        case CTC_RC_FAILED:
            return CTC_SERVER_FAILED_UNKNOWN_ERROR;

        case CTC_RC_FAILED_WRONG_PACKET:
            return CTC_SERVER_FAILED_WRONG_PACKET;

        case CTC_RC_FAILED_UNKNOWN_OPERATION:
            return CTC_SERVER_FAILED_UNKNOWN_OPERATION;

        case CTC_RC_FAILED_OUT_OF_RANGE:
            return CTC_SERVER_FAILED_OUT_OF_RANGE;

        case CTC_RC_FAILED_INVALID_HANDLE:
            return CTC_SERVER_FAILED_INVALID_HANDLE;

        case CTC_RC_FAILED_INSUFFICIENT_SERVER_RESOURCE:
            return CTC_SERVER_FAILED_INSUFFICIENT_SERVER_RESOURCE;

        case CTC_RC_FAILED_CREATE_SESSION:
            return CTC_SERVER_FAILED_CREATE_SESSION;

        case CTC_RC_FAILED_SESSION_NOT_EXIST:
            return CTC_SERVER_FAILED_SESSION_NOT_EXIST;

        case CTC_RC_FAILED_SESSION_IS_BUSY:
            return CTC_SERVER_FAILED_SESSION_IS_BUSY;

        case CTC_RC_FAILED_SESSION_CLOSE:
            return CTC_SERVER_FAILED_SESSION_CLOSE;

        case CTC_RC_FAILED_NO_MORE_JOB_ALLOWED:
            return CTC_SERVER_FAILED_NO_MORE_JOB_ALLOWED;

        case CTC_RC_FAILED_INVALID_JOB:
            return CTC_SERVER_FAILED_INVALID_JOB;

        case CTC_RC_FAILED_INVALID_JOB_STATUS:
            return CTC_SERVER_FAILED_INVALID_JOB_STATUS;

        case CTC_RC_FAILED_INVALID_TABLE_NAME:
            return CTC_SERVER_FAILED_INVALID_TABLE_NAME;

        case CTC_RC_FAILED_TABLE_ALREADY_EXIST:
            return CTC_SERVER_FAILED_TABLE_ALREADY_EXIST;

        case CTC_RC_FAILED_UNREGISTERED_TABLE:
            return CTC_SERVER_FAILED_UNREGISTERED_TABLE;

        case CTC_RC_FAILED_JOB_ATTR_NOT_EXIST:
            return CTC_SERVER_FAILED_JOB_ATTR_NOT_EXIST;

        case CTC_RC_FAILED_INVALID_JOB_ATTR_VALUE:
            return CTC_SERVER_FAILED_INVALID_JOB_ATTR_VALUE;

        case CTC_RC_FAILED_NOT_SUPPORTED_FILTER:
            return CTC_SERVER_FAILED_NOT_SUPPORTED_FILTER;

        case CTC_RC_FAILED_JOB_ALREADY_STARTED:
            return CTC_SERVER_FAILED_JOB_ALREADY_STARTED;

        case CTC_RC_FAILED_JOB_ALREADY_STOPPED:
            return CTC_SERVER_FAILED_JOB_ALREADY_STOPPED;

        default:
            return CTC_FAILED_RECEIVE_INVALID_RESULT_CODE;
    }
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

void set_session_gid (CONTROL_SESSION *control_session, int session_gid)
{
#if defined(DEBUG)
    assert (session_gid != INITIAL_SESSION_GID);
#endif

    control_session->session_gid = session_gid;
}

void set_job_desc (JOB_SESSION *job_session, unsigned short job_desc)
{
#if defined(DEBUG)
    assert (job_desc != INITIAL_JOB_DESC);
#endif

    job_session->job_desc = job_desc;
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

        if (timeout <= 0 || timeout > POLL_TIMEOUT)
        {
            poll_timeout = POLL_TIMEOUT;
        }
        else
        {
            poll_timeout = timeout;
        }

        retval = poll (poll_fds, 1, poll_timeout);

        if (retval == 0) /* timeout */
        {
            if (timeout > 0)
            {
                timeout -= poll_timeout;
            }

            if (timeout <= 0)
            {
                return CTC_FAILED_POLL_TIMEOUT;
            }

            continue;
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
            if (read_size < 0)
            {
                return CTC_FAILED;
            }

            total_read_size += read_size;
        }
    }

    return CTC_SUCCESS;
}

int recv_ctcp_header (CTCP_OP_ID op_id, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int *header_data, char *is_fragmented)
{
    CTCP_HEADER ctcp_header;
    int retval;

    if (op_id == CTCP_CREATE_JOB_SESSION_RESULT ||
        op_id == CTCP_CAPTURED_DATA_RESULT)
    {
        retval = recv_stream (job_session->sockfd, (char *)&ctcp_header, CTCP_PACKET_HEADER_SIZE, POLL_TIMEOUT);
        if (IS_FAILED (retval))
        {
            if (retval != CTC_FAILED_POLL_TIMEOUT)
            {
                retval = CTC_FAILED_COMMUNICATE_JOB_SESSION;
            }

            goto error;
        }
    }
    else
    {
        retval = recv_stream (control_session->sockfd, (char *)&ctcp_header, CTCP_PACKET_HEADER_SIZE, POLL_TIMEOUT);
        if (IS_FAILED (retval))
        {
            if (retval != CTC_FAILED_POLL_TIMEOUT)
            {
                retval = CTC_FAILED_COMMUNICATE_CONTROL_SESSION;
            }

            goto error;
        }
    }

    /* Operation ID */
    retval = check_operation_id (&ctcp_header, op_id);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Result code */
    retval = check_result_code (&ctcp_header);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Job descriptor */
    retval = check_job_desc (&ctcp_header, job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Session group ID */
    retval = check_session_gid (&ctcp_header, control_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    /* Protocol version */
    retval = check_protocol_version (&ctcp_header);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    switch (ctcp_header.op_id)
    {
        case CTCP_CREATE_CONTROL_SESSION_RESULT:
            set_session_gid (control_session, ctcp_header.session_gid);

            break;
        case CTCP_CREATE_JOB_SESSION_RESULT:
            set_job_desc (job_session, ctcp_header.job_desc);

            break;
        case CTCP_REQUEST_JOB_STATUS_RESULT:
            retval = check_received_job_status (ctcp_header.header_data);
            if (IS_FAILED (retval))
            {
                goto error;
            }

            *header_data = ctcp_header.header_data;

            break;
        case CTCP_REQUEST_SERVER_STATUS_RESULT:
            retval = check_received_server_status (ctcp_header.header_data);
            if (IS_FAILED (retval))
            {
                goto error;
            }

            *header_data = ctcp_header.header_data;

            break;
        case CTCP_CAPTURED_DATA_RESULT:
            *header_data = ctcp_header.header_data;
            *is_fragmented = ctcp_header.op_param_or_result_code;

            break;
        default:
            break;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int recv_ctcp_data_payload (JOB_SESSION *job_session, char *buffer, int data_size)
{
    int retval;

    retval = recv_stream (job_session->sockfd, buffer, data_size, POLL_TIMEOUT);
    if (IS_FAILED (retval))
    {
        if (retval != CTC_FAILED_POLL_TIMEOUT)
        {
            retval = CTC_FAILED_COMMUNICATE_JOB_SESSION;
        }

        return retval;
    }

    return CTC_SUCCESS;
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

    retval = recv_ctcp_header (CTCP_CREATE_CONTROL_SESSION_RESULT, control_session, NULL, NULL, NULL);
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

    retval = recv_ctcp_header (CTCP_DESTROY_CONTROL_SESSION_RESULT, control_session, NULL, NULL, NULL);
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

    retval = recv_ctcp_header (CTCP_CREATE_JOB_SESSION_RESULT, control_session, job_session, NULL, NULL);
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

int close_job_session (CONTROL_SESSION *control_session, JOB_SESSION *job_session, bool is_send_ctcp)
{
    int retval;

    if (is_send_ctcp)
    {
        retval = send_ctcp (CTCP_DESTROY_JOB_SESSION, 0, control_session, job_session, 0, NULL);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        retval = recv_ctcp_header (CTCP_DESTROY_JOB_SESSION_RESULT, control_session, job_session, NULL, NULL);
        if (IS_FAILED (retval))
        {
            goto error;
        }
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

int request_server_status (CONTROL_SESSION *control_session, CTC_SERVER_STATUS *server_status)
{
    int retval;

    retval = send_ctcp (CTCP_REQUEST_SERVER_STATUS, 0, control_session, NULL, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp_header (CTCP_REQUEST_SERVER_STATUS_RESULT, control_session, NULL, (int *)server_status, NULL);
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
        return CTC_FAILED_OVERFLOW_DATA_PAYLOAD_MAX_SIZE;
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
    char data_payload[CTCP_DATA_PAYLOAD_MAX_SIZE];
    int data_payload_len = 0;
    int retval;

    retval = make_data_payload (user_name, table_name, data_payload, CTCP_DATA_PAYLOAD_MAX_SIZE, &data_payload_len);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = send_ctcp (CTCP_REGISTER_TABLE, 0, control_session, job_session, data_payload_len, data_payload);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp_header (CTCP_REGISTER_TABLE_RESULT, control_session, job_session, NULL, NULL);
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
    char data_payload[CTCP_DATA_PAYLOAD_MAX_SIZE];
    int data_payload_len = 0;
    int retval;

    retval = make_data_payload (user_name, table_name, data_payload, CTCP_DATA_PAYLOAD_MAX_SIZE, &data_payload_len);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = send_ctcp (CTCP_UNREGISTER_TABLE, 0, control_session, job_session, data_payload_len, data_payload);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp_header (CTCP_UNREGISTER_TABLE_RESULT, control_session, job_session, NULL, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

void init_capture_data (CAPTURE_DATA *capture_data)
{
    int i;

    for (i = 0; i < CAPTURE_DATA_BUFFER_COUNT; i ++)
    {
        capture_data->raw_data_buffer[i] = NULL;
        capture_data->buffer_data_limit[i] = NULL;
    }

    capture_data->raw_data_buffer_w_idx = 0;
    capture_data->raw_data_buffer_r_idx = 0;

    capture_data->buffer_w_pos = NULL;
    capture_data->buffer_r_pos = NULL;

    capture_data->remaining_buffer_size = 0;
}

void clear_capture_data (CAPTURE_DATA *capture_data)
{
    int i;

    for (i = 0; i < CAPTURE_DATA_BUFFER_COUNT; i ++)
    {
        if (IS_NOT_NULL (capture_data->raw_data_buffer[i]))
        {
            free ((void *)capture_data->raw_data_buffer[i]);
        }
    }
}

int alloc_data_buffer (CAPTURE_DATA *capture_data, int requested_size, char **data_buffer_p)
{
    char *data_buffer;
    int retval;

#if defined(DEBUG)
    int try_count = 0;
#endif

    if (requested_size <= 0 || requested_size > CAPTURE_DATA_BUFFER_SIZE)
    {
        retval = CTC_FAILED_INVALID_ARGS;
        goto error;
    }

    *data_buffer_p = NULL;

    do
    {
        data_buffer = (char *)capture_data->raw_data_buffer[capture_data->raw_data_buffer_w_idx];

        if (IS_NULL (data_buffer))
        {
            data_buffer = (char *)calloc (1, CAPTURE_DATA_BUFFER_SIZE);
            if (IS_NULL (data_buffer))
            {
                retval = CTC_FAILED;
                goto error;
            }

            capture_data->raw_data_buffer[capture_data->raw_data_buffer_w_idx] = data_buffer;

            capture_data->buffer_w_pos = data_buffer;
            capture_data->buffer_data_limit[capture_data->raw_data_buffer_w_idx] = data_buffer;

            capture_data->remaining_buffer_size = CAPTURE_DATA_BUFFER_SIZE - requested_size;

            *data_buffer_p = data_buffer;

            break;
        }
        else
        {
            if (requested_size <= capture_data->remaining_buffer_size)
            {
                capture_data->remaining_buffer_size -= requested_size;

                *data_buffer_p = capture_data->buffer_w_pos;

                break;
            }
            else
            {
                capture_data->raw_data_buffer_w_idx ++;

                if (capture_data->raw_data_buffer_w_idx == CAPTURE_DATA_BUFFER_COUNT)
                {
                    capture_data->raw_data_buffer_w_idx = 0;
                }

                if (capture_data->raw_data_buffer_w_idx == capture_data->raw_data_buffer_r_idx)
                {
                    retval = CTC_FAILED_EXCEED_RAW_DATA_BUFFER_COUNT;
                    goto error;
                }
            }
        }

#if defined(DEBUG)
        try_count ++;

        assert (try_count < 2);
#endif
    } while (1);

    return CTC_SUCCESS;

error:

    return retval;
}

void set_next_write_pos (CAPTURE_DATA *capture_data, int write_size)
{
#if defined(DEBUG)
    assert (capture_data->buffer_w_pos != NULL);
#endif

    capture_data->buffer_w_pos += write_size;
    capture_data->buffer_data_limit[capture_data->raw_data_buffer_w_idx] = capture_data->buffer_w_pos;
}

int read_received_data (JOB_SESSION *job_session, char *buffer, int buffer_size, int data_size, char is_fragmented)
{
    int retval;

    /* data info */
    memcpy (buffer, &buffer_size, sizeof (buffer_size));
    buffer += sizeof (buffer_size);

    /* data info */
    memcpy (buffer, &is_fragmented, sizeof (is_fragmented));
    buffer += sizeof (is_fragmented);

    retval = recv_ctcp_data_payload (job_session, buffer, data_size);
    if (IS_FAILED (retval))
    {
        return retval;
    }

    return CTC_SUCCESS;
}

int read_received_capture_transaction (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    char *data_buffer;
    int need_buffer_size;
    int data_payload_size;
    char is_fragmented;

    int retval;

    while (job_session->job_thread.is_thr_alive == true)
    {
        data_payload_size = 0;

        retval = recv_ctcp_header (CTCP_CAPTURED_DATA_RESULT, control_session, job_session, &data_payload_size, &is_fragmented);
        if (IS_FAILED (retval))
        {
            if (retval == CTC_FAILED_POLL_TIMEOUT)
            {
                continue;
            }

            goto error;
        }

#if defined(DEBUG)
        assert (data_payload_size != 0);
#endif

        need_buffer_size = sizeof (int) + sizeof (char) + data_payload_size;

        retval = alloc_data_buffer (&job_session->capture_data, need_buffer_size, &data_buffer);
        if (IS_FAILED (retval))
        {
            goto error;
        }

#if defined(DEBUG)
        assert (data_buffer != NULL);
#endif

        retval = read_received_data (job_session, data_buffer, need_buffer_size, data_payload_size, is_fragmented);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        set_next_write_pos (&job_session->capture_data, need_buffer_size);
    }

    return CTC_SUCCESS;

error:

    return retval;
}

void *job_thread_main (void *arg)
{
    JOB_THREAD_ARGS *job_thread_args = (JOB_THREAD_ARGS *)arg;

    CONTROL_SESSION *control_session = job_thread_args->control_session;
    JOB_SESSION *job_session = job_thread_args->job_session;

    job_session->job_thread.is_thr_alive = true;
    job_session->job_thread.thr_retval = CTC_SUCCESS;

    init_capture_data (&job_session->capture_data);

    job_session->job_thread.thr_retval = read_received_capture_transaction (control_session, job_session);

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

int destroy_job_thread (JOB_THREAD *job_thread)
{
    if (job_thread->is_thr_alive == true)
    {
        job_thread->is_thr_alive = false;

        if (IS_FAILED (pthread_join (job_thread->thr_id, NULL)))
        {
            return CTC_FAILED_DESTROY_JOB_THREAD;
        }
    }

    return job_thread->thr_retval;
}

int check_job_thread_status (JOB_THREAD *job_thread)
{
    if (job_thread->is_thr_alive == true &&
        job_thread->thr_retval == CTC_SUCCESS)
    {
        return CTC_SUCCESS;
    }
    else
    {
        return job_thread->thr_retval;
    }
}

int request_start_capture (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    int retval;

    int state = 0;

    retval = create_job_thread (control_session, job_session);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    state = 1;

    retval = send_ctcp (CTCP_START_CAPTURE, 0, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp_header (CTCP_START_CAPTURE_RESULT, control_session, job_session, NULL, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    if (state)
    {
        destroy_job_thread (&job_session->job_thread);
    }

    return retval;
}

int request_stop_capture (CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTC_JOB_CLOSE_CONDITION job_close_condition, bool is_send_ctcp)
{
    int retval;

    if (is_send_ctcp)
    {
        retval = send_ctcp (CTCP_STOP_CAPTURE, job_close_condition, control_session, job_session, 0, NULL);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        retval = recv_ctcp_header (CTCP_STOP_CAPTURE_RESULT, control_session, job_session, NULL, NULL);
        if (IS_FAILED (retval))
        {
            goto error;
        }
    }

    if (job_close_condition == CTC_JOB_CLOSE_IMMEDIATELY)
    {
        retval = destroy_job_thread (&job_session->job_thread);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        clear_capture_data (&job_session->capture_data);
    }

    return CTC_SUCCESS;

error:

    destroy_job_thread (&job_session->job_thread);
  
    clear_capture_data (&job_session->capture_data);

    return retval;
}

char *get_read_pos (CAPTURE_DATA *capture_data)
{
    volatile char *read_pos = NULL;

#if defined(DEBUG)
    int try_count = 0;
#endif

    do
    {
        if (IS_NULL (capture_data->buffer_r_pos))
        {
            read_pos = capture_data->raw_data_buffer[capture_data->raw_data_buffer_r_idx];
        }
        else
        {
            read_pos = capture_data->buffer_r_pos;
        }

        if (IS_NOT_NULL (read_pos) &&
            read_pos != capture_data->buffer_data_limit[capture_data->raw_data_buffer_r_idx])
        {
            capture_data->buffer_r_pos = (char *)read_pos;

            return (char *)read_pos;
        }
        else
        {
            if (capture_data->raw_data_buffer_r_idx != capture_data->raw_data_buffer_w_idx)
            {
                free ((void *)capture_data->raw_data_buffer[capture_data->raw_data_buffer_r_idx]);

                capture_data->raw_data_buffer[capture_data->raw_data_buffer_r_idx] = NULL;

                capture_data->buffer_r_pos = NULL;
                capture_data->buffer_data_limit[capture_data->raw_data_buffer_r_idx] = NULL;

                capture_data->raw_data_buffer_r_idx ++;
            }
            else
            {
                return NULL;
            }
        }

#if defined(DEBUG)
        try_count ++;

        assert (try_count < 2);
#endif
    } while (1);
}

int set_next_read_pos (CAPTURE_DATA *capture_data, int read_size, char *next_read_pos)
{
#if defined(DEBUG)
    assert (capture_data->buffer_r_pos != NULL);
#endif

    if (capture_data->buffer_r_pos + read_size != next_read_pos)
    {
        return CTC_FAILED_CONVERT_TO_JSON_FORMAT;
    }

    capture_data->buffer_r_pos = next_read_pos;

    if (capture_data->buffer_r_pos > capture_data->buffer_data_limit[capture_data->raw_data_buffer_r_idx])
    {
        return CTC_FAILED_CONVERT_TO_JSON_FORMAT;
    }

    return CTC_SUCCESS;
}

int read_data_info (char **read_pos_p, int *read_data_size, char *is_fragmented)
{
    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (read_data_size, read_pos, sizeof (int));
    read_pos += sizeof (int);

    memcpy (is_fragmented, read_pos, sizeof (char));
    read_pos += sizeof (char);

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

/*
int read_transaction_id (char **read_pos_p, int *tx_id)
{
    int tx_id;

    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (&tx_id, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (tx_id < 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    json_object_set_new (root, "Transaction ID", json_integer (tx_id));

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}
*/

int read_transaction_id (char **read_pos_p, int *tx_id)
{
    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (tx_id, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (*tx_id < 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

int read_number_of_items (char **read_pos_p, int *number_of_items)
{
    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (number_of_items, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (*number_of_items <= 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

/*
int read_user_name (char **read_pos_p, json_t *root)
{
    char user_name[128];
    int user_name_len;

    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (&user_name_len, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (user_name_len <= 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    memcpy (user_name, read_pos, user_name_len);
    read_pos += user_name_len;

    user_name[user_name_len] = '\0';

    json_object_set_new (root, "User", json_string (user_name));

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}
*/

int read_table_name (char **read_pos_p, json_t *root)
{
    char table_name[128];
    int table_name_len;

    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (&table_name_len, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (table_name_len <= 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    memcpy (table_name, read_pos, table_name_len);
    read_pos += table_name_len;

    table_name[table_name_len] = '\0';

    json_object_set_new (root, "Table", json_string (table_name));

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

int read_statement_type (char **read_pos_p, json_t *root, CTC_STMT_TYPE *stmt_type)
{
    char *read_pos;

    read_pos = *read_pos_p;

    memcpy (stmt_type, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (*stmt_type == CTC_STMT_TYPE_INSERT)
    {
        json_object_set_new (root, "Statement type", json_string ("insert"));
    }
    else if (*stmt_type == CTC_STMT_TYPE_UPDATE)
    {
        json_object_set_new (root, "Statement type", json_string ("update"));
    }
    else if (*stmt_type == CTC_STMT_TYPE_DELETE)
    {
        json_object_set_new (root, "Statement type", json_string ("delete"));
    }
    else
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

int read_key_columns (char **read_pos_p, json_t *root)
{
    char attr_name[128];
    int attr_name_len;

    char attr_str_val[128];
    int attr_num_val;
    int attr_val_len;

    char *read_pos;

    DB_TYPE db_type;

    json_t *key_columns;

    read_pos = *read_pos_p;

    key_columns = json_object ();
    if (IS_NULL (key_columns))
    {
        return CTC_FAILED_JANSSON_EXTERNAL_LIBRARY;
    }

    /* attribute name */
    memcpy (&attr_name_len, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (attr_name_len <= 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    memcpy (attr_name, read_pos, attr_name_len);
    read_pos += attr_name_len;

    attr_name[attr_name_len] = '\0';

    /* attribute type */
    memcpy (&db_type, read_pos, sizeof (DB_TYPE));
    read_pos += sizeof (DB_TYPE);

    /* attribute value */
    memcpy (&attr_val_len, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (attr_val_len <= 0 )
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    if (db_type == DB_TYPE_INTEGER)
    {
        memcpy (&attr_num_val, read_pos, attr_val_len);
        read_pos += attr_val_len;

        json_object_set_new (key_columns, attr_name, json_integer (attr_num_val));
    }
    else if (db_type == DB_TYPE_VARCHAR ||
             db_type == DB_TYPE_CHAR)
    {
        memcpy (attr_str_val, read_pos, attr_val_len);
        read_pos += attr_val_len;

        attr_str_val[attr_val_len] = '\0';

        json_object_set_new (key_columns, attr_name, json_string (attr_str_val));
    }
    else
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    json_object_set_new (root, "Key columns", key_columns);

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

int read_columns (char **read_pos_p, json_t *root)
{
    char attr_name[128];
    int attr_name_len;

    char attr_str_val[128];
    int attr_num_val;
    int attr_val_len;

    int number_of_attr;
    int i;

    char *read_pos;

    DB_TYPE db_type;

    json_t *columns;

    read_pos = *read_pos_p;

    memcpy (&number_of_attr, read_pos, sizeof (int));
    read_pos += sizeof (int);

    if (number_of_attr <= 0)
    {
        return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
    }

    columns = json_object ();
    if (IS_NULL (columns))
    {
        return CTC_FAILED_JANSSON_EXTERNAL_LIBRARY;
    }

    for (i = 0; i < number_of_attr; i ++)
    {
        /* attribute name */
        memcpy (&attr_name_len, read_pos, sizeof (int));
        read_pos += sizeof (int);

        if (attr_name_len <= 0)
        {
            return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
        }

        memcpy (attr_name, read_pos, attr_name_len);
        read_pos += attr_name_len;

        attr_name[attr_name_len] = '\0';

        /* attribute type */
        memcpy (&db_type, read_pos, sizeof (DB_TYPE));
        read_pos += sizeof (DB_TYPE);

        /* attribute value */
        memcpy (&attr_val_len, read_pos, sizeof (int));
        read_pos += sizeof (int);

        if (attr_val_len <= 0 )
        {
            return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
        }

        if (db_type == DB_TYPE_INTEGER)
        {
            memcpy (&attr_num_val, read_pos, attr_val_len);
            read_pos += attr_val_len;

            json_object_set_new (columns, attr_name, json_integer (attr_num_val));
        }
        else if (db_type == DB_TYPE_VARCHAR ||
                 db_type == DB_TYPE_CHAR)
        {
            memcpy (attr_str_val, read_pos, attr_val_len);
            read_pos += attr_val_len;

            attr_str_val[attr_val_len] = '\0';

            json_object_set_new (columns, attr_name, json_string (attr_str_val));
        }
        else
        {
            return CTC_FAILED_RECEIVE_INVALID_DATA_PAYLOAD;
        }

        json_object_set_new (columns, attr_name, json_string (attr_str_val));
    }

    json_object_set_new (root, "Columns", columns);

    *read_pos_p = read_pos;

    return CTC_SUCCESS;
}

int register_json (JSON_RESULT *json_result, int register_idx, json_t *json)
{
    if (IS_NOT_NULL (json_result->json[register_idx]))
    {
        return CTC_FAILED_CONVERT_TO_JSON_FORMAT;
    }

    json_result->json[register_idx] = json;

    return CTC_SUCCESS;
}

int convert_capture_transaction_to_json (CAPTURE_DATA *capture_data, JSON_RESULT *json_result, JOB_THREAD *job_thread)
{
    char *read_pos = NULL;
    int data_size;
    int number_of_items;
    int tx_id;
    int i;

    char is_fragmented;

    CTC_STMT_TYPE stmt_type;
    json_t *root;

    int retval;

    retval = check_job_thread_status (job_thread);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    read_pos = get_read_pos (capture_data);
    if (IS_NULL (read_pos))
    {
        return CTC_SUCCESS_NO_DATA;
    }

    retval = read_data_info (&read_pos, &data_size, &is_fragmented);
    if (IS_FAILED (retval))
    {
        goto error;
    }

#if defined(DEBUG)
    assert (data_size != 0);
    assert (((is_fragmented == CTC_SUCCESS) || (is_fragmented == CTC_SUCCESS_FRAGMENTED)));
#endif

    if (is_fragmented == CTC_RC_SUCCESS_FRAGMENTED)
    {
        json_result->is_fragmented = true;
    }
    else
    {
        json_result->is_fragmented = false;
    }

    /* Transaction ID */
    retval = read_transaction_id (&read_pos, &tx_id);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = read_number_of_items (&read_pos, &number_of_items);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    if (number_of_items > JSON_ARRAY_SIZE)
    {
        retval = CTC_FAILED_EXCEED_JSON_ARRAY_SIZE;
        goto error;
    }

    for (i = 0; i < number_of_items; i ++)
    {
        root = json_object ();
        if (IS_NULL (root))
        {
            retval = CTC_FAILED_JANSSON_EXTERNAL_LIBRARY;
            goto error;
        }
        
        /* Transaction ID */
        json_object_set_new (root, "Transaction ID", json_integer (tx_id));

        /* Table name */
        retval = read_table_name (&read_pos, root);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        /* Statement type */
        retval = read_statement_type (&read_pos, root, &stmt_type);
        if (IS_FAILED (retval))
        {
            goto error;
        }

        /* Key columns */
        if (stmt_type == CTC_STMT_TYPE_DELETE ||
            stmt_type == CTC_STMT_TYPE_UPDATE)
        {
            retval = read_key_columns (&read_pos, root);
            if (IS_FAILED (retval))
            {
                goto error;
            }
        }

        /* Columns */
        if (stmt_type == CTC_STMT_TYPE_INSERT ||
            stmt_type == CTC_STMT_TYPE_UPDATE)
        {
            retval = read_columns (&read_pos, root);
            if (IS_FAILED (retval))
            {
                goto error;
            }
        }

        retval = register_json (json_result, i, root);
        if (IS_FAILED (retval))
        {
            goto error;
        }
    }

    retval = set_next_read_pos (capture_data, data_size, read_pos);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}

int request_job_status (CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTC_JOB_STATUS *job_status)
{
    int retval;

    retval = send_ctcp (CTCP_REQUEST_JOB_STATUS, 0, control_session, job_session, 0, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    retval = recv_ctcp_header (CTCP_REQUEST_JOB_STATUS_RESULT, control_session, job_session, (int *)job_status, NULL);
    if (IS_FAILED (retval))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return retval;
}
