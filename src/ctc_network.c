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

int init_data_buffer_array (JOB_SESSION *job_session)
{
    int i;

    for (i = 0; i < MAX_DATA_BUFFER_COUNT; i ++)
    {
        job_session->data_buffer_array[i] = NULL;
    }

    job_session->write_idx = 0;
    job_session->read_idx = 0;

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

void init_data_buffer (DATA_BUFFER *data_buffer)
{
    memset (data_buffer->buffer, 0, DATA_BUFFER_SIZE);
    data_buffer->remaining_buffer_size = DATA_BUFFER_SIZE;

    data_buffer->write_pos = data_buffer->buffer;
    data_buffer->read_pos = data_buffer->buffer;
}

int alloc_data_buffer (JOB_SESSION *job_session, int requested_buffer_size, char **data_buffer_p)
{
    DATA_BUFFER *data_buffer;

    if (requested_buffer_size <= 0 || requested_buffer_size > DATA_BUFFER_SIZE ||
        IS_NULL (data_buffer_p))
    {
        goto error;
    }

    while (1)
    {
        data_buffer = job_session->data_buffer_array[job_session->write_idx];

        if (IS_NULL (data_buffer))
        {
            data_buffer = (DATA_BUFFER *)malloc (sizeof (DATA_BUFFER));
            if (IS_NULL (data_buffer))
            {
                goto error;
            }

            init_data_buffer (data_buffer);

            job_session->data_buffer_array[job_session->write_idx] = data_buffer;

            data_buffer->remaining_buffer_size -= requested_buffer_size;

            *data_buffer_p = data_buffer->write_pos;

            break;
        }
        else
        {
            if (data_buffer->remaining_buffer_size < requested_buffer_size)
            {
                job_session->write_idx ++;

                if (job_session->write_idx == MAX_DATA_BUFFER_COUNT)
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
                data_buffer->remaining_buffer_size -= requested_buffer_size;

                *data_buffer_p = data_buffer->write_pos;

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
    DATA_BUFFER *data_buffer;

    memcpy (buffer, &job_session->result_code, sizeof (job_session->result_code));
    buffer += sizeof (job_session->result_code);

    if (IS_FAILURE (recv_ctcp_data_payload (job_session, buffer, data_size)))
    {
        goto error;
    }

    data_buffer = job_session->data_buffer_array[data_buffer->write_idx];

    data_buffer->write_pos += buffer_size;

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

            if (IS_FAILURE (alloc_data_buffer (job_session, buffer_size, &buffer)))
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

    CTC_HANDLE *control_session = job_thread_args->arg_1;
    JOB_HANDLE *job_session = job_thread_args->arg_2;

    job_session->job_thread_is_alive = true;

    if (IS_FAILURE (init_data_buffer_array (job_session)))
    {
        goto error;
    }

    if (IS_FAILURE (fetch_capture_transaction (control_session, job_session)))
    {
        goto error;
    }

    job_session->job_thread_is_alive = false;

    // 소켓 정리

    return CTC_SUCCESS;

error:

    // 소켓 정리

    job_session->job_thread_is_alive = false;

    return CTC_FAILURE;
}

int create_job_thread (CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    job_session->job_thread_args.arg_1 = control_session;
    job_session->job_thread_args.arg_2 = job_session;

    if (IS_FAILURE (pthread_create (&job_session->job_thread, NULL, job_thread_main, (void *)&job_session->job_thread_args)))
    {
        goto error;
    }

    if (IS_FAILURE (pthread_detach (job_session->job_thread)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int destroy_job_thread (JOB_SESSION *job_session)
{
    job_session->job_thread_is_alive = false;

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
    }

    set_quit_job_condition (job_session, quit_job_condition);

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

bool is_exist_captured_data (JOB_SESSION *job_session)
{
    DATA_BUFFER *data_buffer;

    if (job_session->read_idx != job_session->write_idx)
    {
        return true;
    }
    else
    {
        data_buffer = job_session->data_buffer_array[job_session->read_idx];

        if (data_buffer->read_offset < data_buffer->write_offset)
        {
            return true;
        }
    }

    return false;
}

void init_json_type_result (JSON_TYPE_RESULT *json_type_result)
{
    memset (json_type_result->json_buffer, 0, JSON_BUFFER_SIZE);

    // 아래 두개는 초기화 안해도 됨
    //char *read_pos[100];
    //int  read_len[100];

    json_type_result->data_count = 0;

    json_type_result->cur_idx = 0;

    json_type_result->is_fragmented = false;
}
/*
 * {
 *     "Transaction ID": "12",
 *     "User": "dba",
 *     "Table": "tbl_01",
 *     "Statement type": "insert",
 *     "Columns": {
 *         "C1": "1",
 *         "C2": "Man",
 *         "C3": "SEOUL",
 *         "C4": "010-0000-0000"
 *     }
 * }
 *
 * => { "Transaction ID" : "12", "User" : "dba", "Table" : "tbl_01", "Statement type" : "insert", "Columns" : { "C1" : "1",
 */
int convert_captured_data_to_json (JOB_SESSION *job_session, JSON_TYPE_RESULT *json_type_result)
{
    // 매우매우 더티더티
    DATA_BUFFER *data_buffer;
    char *read_pos;
    char *write_pos;

    char is_fragmented;

    int number_of_items;
    int number_of_attr;

    char *tx_id = "{ \"Transaction ID\" : ";
    char *user = ", \"User\" : \"";
    char *table = "\", \"Table\" : \"";
    char *stmt_type_insert = "\", \"Statement type\" : \"insert\"";
    char *stmt_type_update = "\", \"Statement type\" : \"update\"";
    char *stmt_type_delete = "\", \"Statement type\" : \"delete\"";
    char *stmt_type_commit = "\", \"Statement type\" : \"commit\""; // 안오지만 일단
    char *columns = ", \"Columns\" : { ";

    char temp[4096];
    char name[4096];

    int trans_id;
    int name_len;

    int stmt_type;

    int i, j;
    

    data_buffer = job_session->data_buffer_array[job_session->read_idx];

    read_pos = data_buffer->buffer + data_buffer->read_offset;
    write_pos = json_type_result->json_buffer;

    memcpy (&is_fragmented, read_pos, sizeof (is_fragmented));
    read_pos += sizeof (is_fragmented);

    json_type_result->is_fragmented = is_fragmented;

    memcpy (&number_of_items, read_pos, sizeof (number_of_items));
    read_pos += sizeof (number_of_items);

    for (i = 0; i < number_of_items; i ++)
    {
        // "Transaction ID"
        memcpy (&trans_id, read_pos, sizeof (trans_id));
        read_pos += sizeof (trans_id);

        snprintf (temp, 4096, "%s%d", tx_id, trans_id);
        memcpy (write_pos, temp, strlen (temp));

        write_pos += strlen (temp);

        // "User"
        memcpy (&name_len, read_pos, sizeof (name_len));
        read_pos += sizeof (name_len);

        memcpy (temp, read_pos, name_len);
        read_pos += name_len;

        temp[name_len] = '\0';

        memcpy (write_pos, user, strlen (user));
        write_pos += strlen (user);

        memcpy (write_pos, temp, name_len);
        write_pos += name_len;

        // "Table"
        memcpy (&name_len, read_pos, sizeof (name_len));
        read_pos += sizeof (name_len);

        memcpy (temp, read_pos, name_len);
        read_pos += name_len;

        temp[name_len] = '\0';

        memcpy (write_pos, table, strlen (table));
        write_pos += strlen (table);

        memcpy (write_pos, temp, name_len);
        write_pos += name_len;

        // "Statement type"
        memcpy (&stmt_type, read_pos, sizeof (stmt_type));
        read_pos += sizeof (stmt_type);

        if (stmt_type == CTC_STMT_TYPE_INSERT)
        {
            memcpy (write_pos, stmt_type_insert, strlen (stmt_type_insert));
            write_pos += strlen (stmt_type_insert);
        }
        else if (stmt_type == CTC_STMT_TYPE_UPDATE)
        {
            memcpy (write_pos, stmt_type_update, strlen (stmt_type_update));
            write_pos += strlen (stmt_type_update);
        }
        else if (stmt_type == CTC_STMT_TYPE_DELETE)
        {
            memcpy (write_pos, stmt_type_delete, strlen (stmt_type_delete));
            write_pos += strlen (stmt_type_delete);
        }
        else if (stmt_type == CTC_STMT_TYPE_COMMIT)
        {
            // 만약 커밋이 온다면 뒷부분 못쓰게 막아야 한다.
            memcpy (write_pos, stmt_type_commit, strlen (stmt_type_commit));
            write_pos += strlen (stmt_type_commit);
        }
        else
        {
            goto error;
        }

        // number of attr
        memcpy (&number_of_attr, read_pos, sizeof (read_pos));
        read_pos += sizeof (number_of_attr);

        for (j = 0; j < number_of_attr; j ++)
        {
            // name
            memcpy (&name_len, read_pos, sizeof (name_len));
            read_pos += sizeof (name_len);

            memcpy (temp, read_pos, name_len);
            read_pos += name_len;

            temp[name_len] = 0;

            write_pos[0] = '\"';
            write_pos ++;

            memcpy (write_pos, temp, name_len);
            write_pos += name_len;

            write_pos[0] = '\"';
            write_pos ++;

            write_pos[0] = ' ';
            write_pos ++;

            write_pos[0] = ':';
            write_pos ++;

            write_pos[0] = ' ';
            write_pos ++;

            // value
            memcpy (&name_len, read_pos, sizeof (name_len));
            read_pos += sizeof (name_len);

            memcpy (temp, read_pos, name_len);
            read_pos += name_len;

            temp[name_len] = 0;

            write_pos[0] = '\"';
            write_pos ++;

            memcpy (write_pos, temp, name_len);
            write_pos += name_len;

            write_pos[0] = '\"';
            write_pos ++;

            write_pos[0] = ',';
            write_pos ++;

            write_pos[0] = '0';
            write_pos ++;
        }

        write_pos --;
        write_pos --;

        write_pos[0] = '}';
        write_pos ++;
        write_pos[0] = '}';

        write_pos ++;
        write_pos[0] = '\0';

        // printf


    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int read_captured_data_in_json_format (JOB_SESSION *job_session, JSON_TYPE_RESULT *json_type_result)
{
    if (is_exist_captured_data (job_session))
    {
        if (IS_FAILURE (init_json_type_result (json_type_result)))
        {
            goto error;
        }
        // json_type_result 초기화 되어 있어야 한다.
        if (IS_FAILURE (convert_captured_data_to_json (job_session, json_type_result)))
        {
            goto error;
        }

        // 다 읽고나면, 반드시 read_offset 옮겨줘야 하다.
        // offset 말고 pos으로 기억하고 있는게 더 좋을 것 같다 바로 쓰게
    }
    else
    {
        json_type_result->data_count = 0;
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
