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
            if (IS_NOT_NULL (header_data))
            {
                *header_data = ctcp_header.header_data;
                job_session->result_code = ctcp_header.op_param_or_result_code;
            }

            break;
        default:
            goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int recv_ctcp_data_payload (JOB_SESSION *job_session, char *data_buffer, int data_size)
{
    int retval;

    retval = read (job_session->sockfd, data_buffer, data_size);

    if (retval == -1 || retval < data_size)
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

int make_send_data (char *user_name, char *table_name, char *data_buffer, int buffer_size, int *data_len)
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

    write_pos = data_buffer;

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
    char data_buffer[CTCP_MAX_DATA_PAYLOAD_SIZE];
    int data_len = 0;

    if (IS_FAILURE (make_send_data (user_name, table_name, data_buffer, CTCP_MAX_DATA_PAYLOAD_SIZE, &data_len)))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_REGISTER_TABLE, 0, control_session, job_session, data_len, data_buffer)))
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
    char data_buffer[CTCP_MAX_DATA_PAYLOAD_SIZE];
    int data_len = 0;

    if (IS_FAILURE (make_send_data (user_name, table_name, data_buffer, CTCP_MAX_DATA_PAYLOAD_SIZE, &data_len)))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_UNREGISTER_TABLE, 0, control_session, job_session, data_len, data_buffer)))
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

void init_captured_data_buffer (CAPTURED_DATA_BUFFER *captured_data_buffer)
{
    memset (captured_data_buffer->buffer, 0, CAPTURED_DATA_BUFFER_SIZE);
    captured_data_buffer->remaining_buffer_size = CAPTURED_DATA_BUFFER_SIZE;

    captured_data_buffer->write_offset = 0;
    captured_data_buffer->read_offset = 0;
}

int alloc_data_buffer (JOB_SESSION *job_session, int requested_buffer_size, char **data_buffer_p)
{
    CAPTURED_DATA_BUFFER *captured_data_buffer;
    char *data_buffer;

    if (requested_buffer_size <= 0 || requested_buffer_size > CAPTURED_DATA_BUFFER_SIZE ||
        IS_NULL (data_buffer_p))
    {
        goto error;
    }

    captured_data_buffer = job_session->captured_data_buffer_array[job_session->write_idx];

    while (1)
    {
        if (IS_NULL (captured_data_buffer))
        {
            captured_data_buffer = (CAPTURED_DATA_BUFFER *)malloc (sizeof (CAPTURED_DATA_BUFFER));
            if (IS_NULL (captured_data_buffer))
            {
                goto error;
            }

            init_captured_data_buffer (captured_data_buffer);

            job_session->captured_data_buffer_array[job_session->write_idx] = captured_data_buffer;

            captured_data_buffer->remaining_buffer_size -= requested_buffer_size;

            *data_buffer_p = captured_data_buffer->buffer;

            break;
        }
        else
        {
            if (captured_data_buffer->remaining_buffer_size < requested_buffer_size)
            {
                job_session->write_idx ++;

                if (job_session->write_idx == CAPTURED_DATA_BUFFER_ARRAY_SIZE)
                {
                    job_session->write_idx = 0;
                }

                if (job_session->write_idx == job_session->read_idx)
                {
                    // overflow
                    goto error;
                }

                captured_data_buffer = job_session->captured_data_buffer_array[job_session->write_idx];

                if (IS_NOT_NULL (captured_data_buffer))
                {
                    init_captured_data_buffer (captured_data_buffer);

                    captured_data_buffer->remaining_buffer_size -= requested_buffer_size;

                    *data_buffer_p = captured_data_buffer->buffer;

                    break;
                }
            }
            else
            {
                captured_data_buffer->remaining_buffer_size -= requested_buffer_size;

                *data_buffer_p = captured_data_buffer->buffer + captured_data_buffer->write_offset;

                break;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_captured_data (JOB_SESSION *job_session, char *data_buffer, int buffer_size, int data_size)
{
    int retval;

    CAPTURED_DATA_BUFFER *captured_data_buffer;

    /* header - is fragmented */
    memcpy (data_buffer, &job_session->result_code, sizeof (job_session->result_code));
    data_buffer += sizeof (job_session->result_code);

    if (IS_FAILURE (recv_ctcp_data_payload (job_session, data_buffer, data_size)))
    {
        goto error;
    }

    captured_data_buffer = job_session->captured_data_buffer_array[captured_data_buffer->write_idx];
    if (IS_NULL (captured_data_buffer))
    {
        goto error;
    }

    captured_data_buffer->write_offset += buffer_size;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int prepare_captured_data_read (JOB_SESSION *job_session)
{
    int i;

    for (i = 0; i < CAPTURED_DATA_BUFFER_ARRAY_SIZE; i ++)
    {
        job_session->captured_data_buffer_array[i] = NULL;
    }

    job_session->write_idx = 0;
    job_session->read_idx = 0;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int execute_captured_data_read (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    char *data_buffer;
    int data_buffer_size;

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
            data_buffer = NULL;
            data_buffer_size = sizeof (job_session->result_code) + data_payload_size;

            if (IS_FAILURE (alloc_data_buffer (job_session, data_buffer_size, &data_buffer)))
            {
                goto error;
            }

            if (IS_FAILURE (read_captured_data (job_session, data_buffer, data_buffer_size, data_payload_size)))
            {
                goto error;
            }
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

// 자원 할당과 write는 job thread가 수행
// 자원 해제와 read는 main thread에서 수행
void *job_thread_main (void *arg)
{
    JOB_THREAD_ARGS *job_thread_args = (JOB_THREAD_ARGS *)arg;

    CTC_HANDLE *control_session = job_thread_args->control_session;
    JOB_HANDLE *job_session = job_thread_args->job_session;

    job_session->job_thread_is_alive = true;

    if (IS_FAILURE (prepare_captured_data_read (job_session)))
    {
        goto error;
    }

    if (IS_FAILURE (execute_captured_data_read (control_session, job_session)))
    {
        goto error;
    }

    job_session->job_thread_is_alive = false;

    return CTC_SUCCESS;

error:

    job_session->job_thread_is_alive = false;

    return CTC_FAILURE;
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

int stop_capture_for_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    // op param 으로 close 컨디션 처리
    if (IS_FAILURE (send_ctcp (CTCP_STOP_CAPTURE, 0, control_session, job_session, 0, NULL)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_STOP_CAPTURE_RESULT, control_session, job_session, NULL)))
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

#if 0
    if (IS_FAILURE (
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}
#endif
