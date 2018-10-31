#ifndef _CTC_API_H_
#define _CTC_API_H_

#define CTC_SUCCESS             0
#define CTC_SUCCESS_FRAGMENTED  1
#define CTC_FAILURE            -1

typedef enum ctc_conn_type CTC_CONN_TYPE;
enum ctc_conn_type
{
    CTC_CONN_TYPE_DEFAULT   = 0,
    CTC_CONN_TYPE_CTRL_ONLY = 1
};

typedef enum ctc_quit_job_condition CTC_QUIT_JOB_CONDITION;
enum ctc_quit_job_condition
{
    CTC_QUIT_JOB_IMMEDIATELY       = 0,
    CTC_QUIT_JOB_AFTER_TRANSACTION = 1
};

#endif
