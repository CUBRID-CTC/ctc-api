#include <stdio.h>
#include "ctc_api.h"

int main (void)
{
    int ctc_handle;
    int job_desc;
    int retval;

    char result_buffer[4096];
    int  buffer_size = 4096;
    int  data_size   = 0;

    int dd = 1;

    ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.77:20000");
    //ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.77:20050");
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

    //while (dd == 1);

    while (1)
    {
        retval = ctc_fetch_capture_transaction (ctc_handle, job_desc, result_buffer, buffer_size, &data_size);
        if (retval == CTC_FAILURE)
        {
            printf ("[ERROR] ctc_fetch_transaction_capture ()\n");
            return -1;
        }
        else
        {
            if (retval == CTC_SUCCESS)
            {
                printf ("[recv] SUCCESS\n");
                break;
            }
            else if (retval == CTC_SUCCESS_FRAGMENTED)
            {
                printf ("[recv] FRAGMENTED\n");
                continue;
            }
            else if (retval == CTC_SUCCESS_NO_DATA)
            {
                printf ("[recv] NO_DATA\n");
                continue;
            }
            else
            {

            }
        }
    }

    retval = ctc_stop_capture (ctc_handle, job_desc, CTC_QUIT_JOB_IMMEDIATELY);
    if (retval == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_stop_capture ()\n");
        return -1;
    }

    retval = ctc_close_connection (ctc_handle);
    if (retval == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_close_connection ()\n");
        return -1;
    }

    return 0;
}
