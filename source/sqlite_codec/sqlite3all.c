#ifdef _WINDLL
#define SQLITE_API __declspec(dllexport)
#endif
#include "sqlite3.c"
#include "sqlcodec.c"
