#include <stdio.h>
#include "ctc_api.h"

int main (void)
{
    int ctc_handle;
    int job_desc;
    int retval;

    ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.77:20000");
    if (ctc_handle == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    job_desc = ctc_add_job (ctc_handle);
    if (job_desc == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    retval = ctc_register_table (ctc_handle, job_desc, "dba1", "tbl1");
    if (retval == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_register_table ()\n");
        return -1;
    }

    retval = ctc_start_capture (ctc_handle, job_desc);
    if (retval == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_start_capture ()\n");
        return -1;
    }

    retval = ctc_stop_capture (ctc_handle, job_desc, 0);
    if (retval == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_stop_capture ()\n");
        return -1;
    }

    return 0;
}
