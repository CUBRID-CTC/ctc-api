#include <stdio.h>

int main (void)
{
    int ctc_handle;
    int job_desc;
    int retval;

    ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.100:20000");
    if (ctc_handle == -1)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    job_desc = ctc_add_job (ctc_handle);
    if (job_desc == -1)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    retval = ctc_register_table (ctc_handle, job_desc, "dba1", "tbl1");
    if (retval == -1)
    {
        printf ("[ERROR] ctc_register_table ()\n");
        return -1;
    }

    retval = ctc_unregister_table (ctc_handle, job_desc, "dba1", "tbl1");
    if (retval == -1)
    {
        printf ("[ERROR] ctc_unregister_table ()\n");
        return -1;
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
