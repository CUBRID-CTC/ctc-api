
CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(test)

SET(CMAKE_C_COMPILER gcc)

ADD_COMPILE_OPTIONS(-g -Wall)

#SET(CMAKE_BUILD_TYPE Debug)

SET(CMAKE_VERBOSE_MAKEFILE true)

#FILE(COPY ../src/include/backup_api.h DESTINATION .)
#FILE(RENAME backup_api.h cubrid_backup_api.h)

INCLUDE_DIRECTORIES(.)

FILE(COPY ../src/libctcapi.so.1.0.0 DESTINATION .)
#FILE(RENAME libctcapi.so.1.0.0 libctcapi.so)

LINK_DIRECTORIES(/home/hornetmj/work/ctc-api/samples)

ADD_EXECUTABLE(sample_01 sample_01.c)
TARGET_LINK_LIBRARIES(sample_01 ctcapi pthread)

ADD_EXECUTABLE(sample_02 sample_02.c)
TARGET_LINK_LIBRARIES(sample_02 ctcapi pthread)

ADD_EXECUTABLE(sample_03 sample_03.c)
TARGET_LINK_LIBRARIES(sample_03 ctcapi pthread)

ADD_EXECUTABLE(sample_04 sample_04.c)
TARGET_LINK_LIBRARIES(sample_04 ctcapi pthread)

ADD_EXECUTABLE(sample_05 sample_05.c)
TARGET_LINK_LIBRARIES(sample_05 ctcapi pthread)

ADD_EXECUTABLE(sample_06 sample_06.c)
TARGET_LINK_LIBRARIES(sample_06 ctcapi pthread)

ADD_EXECUTABLE(sample_07 sample_07.c)
TARGET_LINK_LIBRARIES(sample_07 ctcapi pthread)

ADD_EXECUTABLE(sample_08 sample_08.c)
TARGET_LINK_LIBRARIES(sample_08 ctcapi pthread)
