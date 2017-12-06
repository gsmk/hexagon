
#ifdef TRACELOG
FILE *g_log;
#define hextracelog(...)  do { if (g_log) qfprintf(g_log, __VA_ARGS__); } while (0)
#define dbgprintf(...)  do { if (g_log) qfprintf(g_log, __VA_ARGS__); } while (0)
#define errprintf(...)  do { if (g_log) qfprintf(g_log, "ERROR: " __VA_ARGS__); } while (0)
#else
#define hextracelog(...)  // msg("hexagon: " __VA_ARGS__)
#define dbgprintf(...)  // msg("hexagon: " __VA_ARGS__)
#define errprintf(...)  msg("hexagon: " __VA_ARGS__)
#endif


