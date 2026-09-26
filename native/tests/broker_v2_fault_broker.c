#ifndef PLAMEN_BROKER_V2_FAULT_TEST_ONLY
#error "TEST_ONLY fault broker must never enter a production build"
#endif

#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_NOFOLLOW
#error "TEST_ONLY fault broker requires O_NOFOLLOW"
#endif
#ifndef O_CLOEXEC
#error "TEST_ONLY fault broker requires O_CLOEXEC"
#endif

/* Simulates power loss after O_EXCL creation but before a complete durable record. */
int
main(int argc, char **argv)
{
    static const uint8_t partial[] = "PLMJRN2\0\0\2\0\1\0\0\0\300";
    int parent = -1, directory = -1, record = -1;
    if (argc != 3) return 64;
    parent = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (parent < 0 || mkdirat(parent, argv[2], 0700) != 0) return 65;
    directory = openat(parent, argv[2],
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) return 66;
    record = openat(directory, "00000000000000000001.rec",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0400);
    if (record < 0 || write(record, partial, sizeof(partial) - 1)
        != (ssize_t)(sizeof(partial) - 1) || fsync(record) != 0)
        return 67;
    close(record); fsync(directory); close(directory); close(parent);
    _exit(0);
}
