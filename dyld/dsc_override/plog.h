#ifndef PLOG_H
#define PLOG_H

#include <stdio.h>
#include <stdbool.h>

# define LOG(x, ...) \
do { \
printf("[haxx:log] "x"\n", ##__VA_ARGS__); \
} while(0)

# define ERR(x, ...) \
do { \
printf("[haxx:error] "x"\n", ##__VA_ARGS__); \
} while(0)

# ifdef DEVBUILD
#  define DEVLOG(x, ...) \
do { \
printf("[haxx:debug] "x"\n", ##__VA_ARGS__); \
} while(0)
# else
#  define DEVLOG(...)
# endif

#endif /* PLOG_H */
