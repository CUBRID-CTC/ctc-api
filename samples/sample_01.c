#include <stdio.h>

int main (void)
{
    int ctc_handle;
    int retval;
    int i;

    for (i = 0; i < 3000; i ++)
    {
        ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.77:20000");
        if (ctc_handle == -1)
        {
            printf ("[ERROR] ctc_open_connection ()\n");
            return -1;
        }

        retval = ctc_close_connection (ctc_handle);
        if (retval == -1)
        {
            printf ("[ERROR] ctc_close_connection ()\n");
            return -1;
        }
    }

    return 0;
}
