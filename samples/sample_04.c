#include <stdio.h>

int main (void)
{
    int ctc_handle;
    int retval;
    int server_status = -1;

    ctc_handle = ctc_open_connection (0, "ctc:cubrid:192.168.1.100:20000");
    if (ctc_handle == -1)
    {
        printf ("[ERROR] ctc_open_connection ()\n");
        return -1;
    }

    retval = ctc_check_server_status (ctc_handle, &server_status);
    if (retval == -1)
    {
        printf ("[ERROR] ctc_check_server_status ()\n");
        return -1;
    }

    switch (server_status)
    {
        case 0:
            printf ("[CTC_SERVER_STATE] => CTC_SERVER_NOT_READY\n");
            break;
        case 1:
            printf ("[CTC_SERVER_STATE] => CTC_SERVER_RUNNING\n");
            break;
        case 2:
            printf ("[CTC_SERVER_STATE] => CTC_SERVER_CLOSING\n");
            break;
        default:
            break;
    }

    retval = ctc_close_connection (ctc_handle);
    if (retval == -1)
    {
        printf ("[ERROR] ctc_close_connection ()\n");
        return -1;
    }

    return 0;
}
