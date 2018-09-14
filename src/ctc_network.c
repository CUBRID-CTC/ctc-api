#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ctc_network.h"

int make_ctcp_header (CTCP_OP ctcp_op, int ctcp_op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTCP_HEADER *ctcp_header)
{
    memset (ctcp_header, 0, sizeof (CTCP_HEADER));

    /* Operation ID */
    ctcp_header->op = ctcp_op;

    /* Operation specific param */
    ctcp_header->op_param_or_result_code = ctcp_op_param;

    /* Job descriptor */
    if (job_session != NULL)
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

    /* etc */

    return CTC_SUCCESS;
}

int send_ctcp (CTCP_OP ctcp_op, int ctcp_op_param, CONTROL_SESSION *control_session, JOB_SESSION *job_session)
{
    CTCP_HEADER ctcp_header;
    int retval;

    if (IS_FAILURE (make_ctcp_header (ctcp_op, ctcp_op_param, control_session, job_session, &ctcp_header)))
    {
        goto error;
    }

    retval = write (control_session->sockfd, &ctcp_header, sizeof (CTCP_HEADER));
    if (retval == -1 || retval < sizeof (CTCP_HEADER))
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int check_op_code (CTCP_OP ctcp_op, CTCP_HEADER *ctcp_header)
{
    ctcp_header->op == ctcp_op ? return CTC_SUCCESS : return CTC_FAILURE;
}

int check_result_code (CTCP_HEADER *ctcp_header)
{

}

int recv_ctcp_header (CTCP_OP ctcp_op, CONTROL_SESSION *control_session, JOB_SESSION *job_session, CTCP_HEADER *ctcp_header)
{
    int retval;

    retval = read (control_session->sockfd, ctcp_header, sizeof (CTCP_HEADER));
    if (retval == -1 || retval < sizeof (CTCP_HEADER))
    {
        goto error;
    }

    if (IS_FAILURE (check_op_code (ctcp_op, ctcp_header)))
    {
        goto error;
    }

    if (IS_FAILURE (check_result_code (ctcp_header)))
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

    }

    switch (ctcp_op)
    {
        case CTCP_CREATE_CONTROL_SESSION_RESULT:

            break;
        case CTCP_DESTROY_CONTROL_SESSION_RESULT:

            break;
        case CTCP_CREATE_JOB_SESSION_RESULT:

            break;
        case CTCP_DESTROY_JOB_SESSION_RESULT:

            break;
        case CTCP_REQUEST_JOB_STATUS_RESULT:

            break;
        case CTCP_REQUEST_SERVER_STATUS_RESULT:

            break;
        case CTCP_REGISTER_TABLE_RESULT:

            break;
        case CTCP_UNREGISTER_TABLE_RESULT:

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

    if (IS_FAILURE (send_ctcp (CTCP_CREATE_CONTROL_SESSION, conn_type, control_session, NULL)))
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

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

#if 0
int open_job_session (ctc_handle, server_ip, server_port)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int close_job_session (ctc_handle)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

#endif
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
