#include "ctc_network.h"

int open_control_session (ctc_handle, server_ip, server_port)
{
    ctc_handle->control_sd = socket(PF_INET, SOCK_STREAM, 0);
    if (ctc_handle->control_sd == -1)
    {
        goto error;
    }

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

int close_control_session (ctc_handle)
{

    return CTC_SUCCESS;

error:

    return CTC_FAILURE;
}

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

