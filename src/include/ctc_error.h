/*
 * error 구분
 *   - api 자체적으로 발생할 수 있는 에러
 *     1. ctc-api에 잘못된 인자를 전달
 *       - ctc_handle
 *       - job_desc
 *       - connection type
 *       - connection string
 *       - close condition 
 *     2. 리미티드에 걸림
 *       - ctc_handle -> MAX_CTC_HANDLE_COUNT(100) 넘어감
 *       - job_hanlde -> MAX_JOB_HANDLE_COUNT(10) 넘어감
 *     3. ctcp
 *       - send_ctcp
 *         - send data_payload 크기가 CTCP_MAX_DATA_PAYLOAD_SIZE(4080) 초가
 *         - 전송 실패 (소켓 문제겠지)
 *       - recv_ctcp
 *         - 수신 실패
 *           - 소켓 문제
 *           - 기대하는 수신 데이터 크기 안옴
 *           - 기대하는 result op 가 아님
 *           - result code가 error 계열
 *           - 기대하는 job_desc 아님
 *           - 기대하는 session_gid 아님
 *           - 프로토콜 버전 안맞음
 *           - close 컨디션이 정해진 값 이외의 값인 경우
 *           - 서버 상태 정보가 지원하지 않는 값인 경우
 *           - job 상태 정보가 지원하지 않는 값인 경우
 *         - 
 *     4. IP / PORT 정보 잘못
 *     5. job 쓰레드
 *       - 생성 실패
 *       - 수행 중 실패, 쓰레드 비정상 종료
 *       - 종료 실패
 *       - overflow
 *     6. fetch
 *       - 데이터 버퍼 크기 작은 경우
 *       - read / write inx 가 깨지는 경우
 *       - read / write pos 가 깨지는 경우
 *       - 한 패킷의 item 수가 json 버퍼 크기 MAX_JSON_TYPE_RESULT_COUNT 넘어가는 경우
 *
 *           
 *
 *     - api 전반에 리소스 적인 에러 (시스템)
 *       - 메모리 할당/반환 실패
 *       - 소켓 할당/반환 실패
 *       - 소켓 연결 실패
 *
 *
 *   - server에서 발생해서 알게되는 에러
 *     2. 서버에 전송한 session_gid 가 존재하지 않는 경우
 *     3. 서버에 전송한 job_desc 가 존재하지 않는 경우
 *     4. 중복된 테이블을 등록하는 경우
 *     5. 존재하지 않는 테이블을 등록하는 경우
 *     6. 등록하지 않는 테이블을 제거하는 경우
 *     7. 
 *
 *
