#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ctc_network.h"

int make_ctcp_header (CTCP_OP ctcp_op, int ctcp_op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int header_data, CTCP_HEADER *ctcp_header)
{
    memset (ctcp_header, 0, sizeof (CTCP_HEADER));

    /* Operation ID */
    ctcp_header->op = ctcp_op;

    /* Operation specific param */
    ctcp_header->op_param_or_result_code = ctcp_op_param;

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

int make_ctcp_data (char *ctcp_data, char *data, int *data_len)
{
    int data_size;

    data_size = strlen (data);

    memcpy (ctcp_data, data, data_size);

    *data_len = data_size;

    return CTC_SUCCESS;
}

int send_ctcp (CTCP_OP ctcp_op, int ctcp_op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, int header_data, char *data)
{
    CTCP ctcp;
    CTCP_HEADER *ctcp_header;

    int data_len = 0;
    int retval;

    ctcp_header = &ctcp.ctcp_header;

    if (IS_FAILURE (make_ctcp_header (ctcp_op, ctcp_op_param, control_session, job_session, header_data, ctcp_header)))
    {
        goto error;
    }

    if (IS_NOT_NULL (data))
    {
        if (IS_FAILURE (make_ctcp_data (ctcp.ctcp_data, data, &data_len)))
        {
            goto error;
        }

        if (header_data != data_len)
        {
            goto error;
        }
    }

    if (ctcp_op != CTCP_CREATE_JOB_SESSION)
    {
        retval = write (control_session->sockfd, &ctcp, sizeof (CTCP_HEADER) + data_len);
        if (retval == -1 || retval < sizeof (CTCP_HEADER) + data_len)
        {
            goto error;
        }
    }
    else
    {
        retval = write (job_session->sockfd, &ctcp, sizeof (CTCP_HEADER));
        if (retval == -1 || retval < sizeof (CTCP_HEADER))
        {
            goto error;
        }
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_operation_id (CTCP_OP ctcp_op, CTCP_HEADER *ctcp_header)
{
    return ctcp_header->op == ctcp_op ? CTC_SUCCESS : CTC_FAILURE;
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

void set_session_gid (CONTROL_SESSION *control_session, int session_gid)
{
    control_session->session_gid = session_gid;
}

void set_job_desc (JOB_SESSION *job_session, unsigned short job_desc)
{
    job_session->job_desc = job_desc;
}

int recv_ctcp_header (CTCP_OP ctcp_op, CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTCP_HEADER *ctcp_header)
{
    int retval;

    if (ctcp_op != CTCP_CREATE_JOB_SESSION_RESULT)
    {
        retval = read (control_session->sockfd, ctcp_header, sizeof (CTCP_HEADER));
    }
    else
    {
        retval = read (job_session->sockfd, ctcp_header, sizeof (CTCP_HEADER));
    }

    if (retval == -1 || retval < sizeof (CTCP_HEADER))
    {
        goto error;
    }

    /* Operation ID */
    if (IS_FAILURE (check_operation_id (ctcp_op, ctcp_header)))
    {
        goto error;
    }

    /* Result code */
    if (IS_FAILURE (check_result_code (ctcp_header)))
    {
        goto error;
    }

    /* Job descriptor */
    if (job_session != NULL && job_session->job_desc != -1)
    {
        if (ctcp_header->job_desc != job_session->job_desc)
        {
            goto error;
        }
    }

    /* Session group ID */
    if (control_session->session_gid != -1)
    {
        if (ctcp_header->session_gid != control_session->session_gid)
        {
            goto error;
        }
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

int recv_ctcp (CTCP_OP ctcp_op, CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    CTCP_HEADER ctcp_header;

    if (IS_FAILURE (recv_ctcp_header (ctcp_op, control_session, job_session, &ctcp_header)))
    {
        goto error;
    }

    switch (ctcp_header.op)
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

            break;
        case CTCP_REQUEST_SERVER_STATUS_RESULT:

            break;
        case CTCP_REGISTER_TABLE_RESULT:
            /* nothing to do */

            break;
        case CTCP_UNREGISTER_TABLE_RESULT:
            /* nothing to do */

            break;
        case CTCP_SET_JOB_ATTRIBUTE_RESULT:

            break;
        case CTCP_START_CAPTURE_RESULT:

            break;
        case CTCP_STOP_CAPTURE_RESULT:

            break;
        default:
            goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int open_control_session (CONTROL_SESSION *control_session, int conn_type)
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

    if (IS_FAILURE (recv_ctcp (CTCP_CREATE_CONTROL_SESSION_RESULT, control_session, NULL)))
    {
        goto error;
    }

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

    if (IS_FAILURE (recv_ctcp (CTCP_DESTROY_CONTROL_SESSION_RESULT, control_session, NULL)))
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

    if (IS_FAILURE (recv_ctcp (CTCP_CREATE_JOB_SESSION_RESULT, control_session, job_session)))
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

    if (IS_FAILURE (recv_ctcp (CTCP_DESTROY_JOB_SESSION_RESULT, control_session, job_session)))
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

int register_table_to_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *db_user, char *table_name)
{
    char data[MAX_DATA_PAYLOAD_SIZE + 1];

    snprintf (data, MAX_DATA_PAYLOAD_SIZE + 1, "%d%s%d%s", strlen (db_user), db_user, strlen (table_name), table_name);

    if (IS_FAILURE (send_ctcp (CTCP_REGISTER_TABLE, 0, control_session, job_session, strlen (data), data)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_REGISTER_TABLE_RESULT, control_session, job_session)))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int unregister_table_from_job (CONTROL_SESSION *control_session, JOB_SESSION *job_session, char *db_user, char *table_name)
{
    char data[MAX_DATA_PAYLOAD_SIZE + 1];

    snprintf (data, MAX_DATA_PAYLOAD_SIZE + 1, "%d%s%d%s", strlen (db_user), db_user, strlen (table_name), table_name);

    if (IS_FAILURE (send_ctcp (CTCP_UNREGISTER_TABLE, 0, control_session, job_session, strlen (data), data)))
    {
        goto error;
    }

    if (IS_FAILURE (recv_ctcp (CTCP_UNREGISTER_TABLE_RESULT, control_session, job_session)))
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
