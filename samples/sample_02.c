#include <stdio.h>

int main (void)
{
    int ctc_handle;
    int job_desc[10]; // 한 ctc_handle 당 10개 제약
    int retval;
    int i;

    ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.100:20000");
    if (ctc_handle == -1)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    for (i = 0; i < 10; i ++)
    {
        job_desc[i] = ctc_add_job (ctc_handle);
        if (job_desc[i] == -1)
        {
            printf ("[ERROR] ctc_open_connection ()\n");
            return -1;
        }
    }

    retval = ctc_close_connection (ctc_handle);
    if (retval == -1)
    {
        printf ("[ERROR] ctc_close_connection ()\n");
        return -1;
    }

    return 0;
}
