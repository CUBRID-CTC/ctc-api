#include <stdio.h>

int main (void)
{
    int ctc_handle;
    int job_desc;
    int job_status = -1;
    int retval;

    ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.77:20000");
    if (ctc_handle == -1)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    job_desc = ctc_add_job (ctc_handle);
    if (job_desc == -1)
    {
        printf ("[ERROR] ctc_add_job ()\n");
        return -1;
    }

    retval = ctc_check_job_status (ctc_handle, job_desc, &job_status);
    if (retval == -1)
    {
        printf ("[ERROR] ctc_check_job_status ()\n");
        return -1;
    }

    switch (job_status)
    {
        case 0:
            printf ("[CTC_JOB_STATE] => CTC_JOB_NONE\n");
            break;
        case 1:
            printf ("[CTC_JOB_STATE] => CTC_JOB_WAITING\n");
            break;
        case 2:
            printf ("[CTC_JOB_STATE] => CTC_JOB_PROCESSING\n");
            break;
        case 3:
            printf ("[CTC_JOB_STATE] => CTC_JOB_READY_TO_FETCH\n");
            break;
        case 4:
            printf ("[CTC_JOB_STATE] => CTC_JOB_CLOSING\n");
            break;
        default:
            break;
    }

    retval = ctc_delete_job (ctc_handle, job_desc);
    if (retval == -1)
    {
        printf ("[ERROR] ctc_delete_job ()\n");
        return -1;
    }

    retval = ctc_close_connection (ctc_handle);
    if (retval == -1)
    {
        printf ("[ERROR] ctc_close_connection ()\n");
        return -1;
    }

    return 0;
}
