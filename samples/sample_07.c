#include <stdio.h>
#include "ctc_api.h"

int main (void)
{
    int ctc_handle;
    int job_desc;
    int retval;

    char result_buffer[20000];
    int  buffer_size = 20000;
    int  data_size   = 0;

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
                break;
            }
            else if (retval == CTC_SUCCESS_FRAGMENTED)
            {
                continue;
            }
            else if (retval == CTC_SUCCESS_NO_DATA)
            {
                continue;
            }
            else
            {

            }
        }
    }

    result_buffer[data_size] = '\0';
    printf ("result ==> %s\n", result_buffer);
    printf ("data_size ==> %d\n", data_size);

    retval = ctc_close_connection (ctc_handle);
    if (retval == CTC_FAILURE)
    {
        printf ("[ERROR] ctc_close_connection ()\n");
        return -1;
    }

    return 0;
}
