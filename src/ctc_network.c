#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ctc_network.h"

int send_ctcp (CTCP_OP ctcp_op, int ctcp_op_param, CONTROL_SESSION* control_session, JOB_SESSION* job_session)
{
    char ctcp_header[16];

    memset (ctcp_header, 0, 16);

    /* Operation ID */
    memcpy (ctcp_header, &ctcp_op, 1);

    /* Operation specific param */
    memcpy (ctcp_header + 1, &ctcp_op_param, 1);

    if (job_session != NULL)
    {
        /* Job descriptor */
        unsigned short job_desc;

        job_desc = job_session->job_desc;

        memcpy (ctcp_header + 2, job_desc, 2);
    }

    if (control_session != NULL)
    {
        /* Session group ID */
        memcpy (ctcp_header + 4, control_session->session_gid);
    }

    /* Protocol version */





    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int recv_ctcp (CTCP_OP ctcp_op, CONTROL_SESSION* control_session, JOB_SESSION* job_session)
{
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

int open_control_session (CONTROL_SESSION* control_session, int conn_type)
{
    struct sockaddr_in server_addr;

    control_session->sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (control_session->sockfd == -1)
    {
        goto error;
    }

    memset (&server_addr, 0, sizeof (server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr (control_session->server_ip);
    server_addr.sin_port = htons (control_session->server_port);

    if (IS_FAILURE (connect (control_session->sockfd, (struct sockaddr *)&server_addr, sizeof (server_addr))))
    {
        goto error;
    }

    if (IS_FAILURE (send_ctcp (CTCP_CREATE_CONTROL_SESSION, conn_type, NULL, NULL)))
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

int close_control_session (CONTROL_SESSION* control_session)
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
