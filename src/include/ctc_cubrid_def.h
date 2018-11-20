typedef enum
{
    DB_TYPE_FIRST = 0,      /* first for iteration */
    DB_TYPE_UNKNOWN = 0,
    DB_TYPE_NULL = 0,
    DB_TYPE_INTEGER = 1,
    DB_TYPE_FLOAT = 2,
    DB_TYPE_DOUBLE = 3,
    DB_TYPE_STRING = 4,
    DB_TYPE_OBJECT = 5,
    DB_TYPE_SET = 6,
    DB_TYPE_MULTISET = 7,
    DB_TYPE_SEQUENCE = 8,
    DB_TYPE_ELO = 9,        /* obsolete... keep for backward compatibility. maybe we can replace with something else */
    DB_TYPE_TIME = 10,
    DB_TYPE_TIMESTAMP = 11,
    DB_TYPE_DATE = 12,
    DB_TYPE_MONETARY = 13,
    DB_TYPE_VARIABLE = 14,  /* internal use only */
    DB_TYPE_SUB = 15,       /* internal use only */
    DB_TYPE_POINTER = 16,   /* method arguments only */
    DB_TYPE_ERROR = 17,     /* method arguments only */
    DB_TYPE_SHORT = 18,
    DB_TYPE_VOBJ = 19,      /* internal use only */
    DB_TYPE_OID = 20,       /* internal use only */
    DB_TYPE_DB_VALUE = 21,  /* special for esql */
    DB_TYPE_NUMERIC = 22,   /* SQL NUMERIC(p,s) values */
    DB_TYPE_BIT = 23,       /* SQL BIT(n) values */
    DB_TYPE_VARBIT = 24,    /* SQL BIT(n) VARYING values */
    DB_TYPE_CHAR = 25,      /* SQL CHAR(n) values */
    DB_TYPE_NCHAR = 26,     /* SQL NATIONAL CHAR(n) values */
    DB_TYPE_VARNCHAR = 27,  /* SQL NATIONAL CHAR(n) VARYING values */
    DB_TYPE_RESULTSET = 28, /* internal use only */
    DB_TYPE_MIDXKEY = 29,   /* internal use only */
    DB_TYPE_TABLE = 30,     /* internal use only */
    DB_TYPE_BIGINT = 31,
    DB_TYPE_DATETIME = 32,
    DB_TYPE_BLOB = 33,
    DB_TYPE_CLOB = 34,
    DB_TYPE_ENUMERATION = 35,
    DB_TYPE_TIMESTAMPTZ = 36,
    DB_TYPE_TIMESTAMPLTZ = 37,
    DB_TYPE_DATETIMETZ = 38,
    DB_TYPE_DATETIMELTZ = 39,
    DB_TYPE_JSON = 40,

    /* aliases */
    DB_TYPE_LIST = DB_TYPE_SEQUENCE,
    DB_TYPE_SMALLINT = DB_TYPE_SHORT,   /* SQL SMALLINT */
    DB_TYPE_VARCHAR = DB_TYPE_STRING,   /* SQL CHAR(n) VARYING values */
    DB_TYPE_UTIME = DB_TYPE_TIMESTAMP,  /* SQL TIMESTAMP */

    DB_TYPE_LAST = DB_TYPE_JSON
} DB_TYPE;
