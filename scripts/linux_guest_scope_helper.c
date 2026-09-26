/*
 * Plamen Linux/arm64 OCI guest confinement helper.
 *
 * Linux kernel ABI operations intentionally live here rather than in Python
 * ctypes.  The protocol accepts retained descriptors and bounded scalars only;
 * A pinned ELF Python interpreter executes with fexecve(3); a separately
 * pinned driver script survives at one fixed procfd argument.  Script bytes
 * are never passed directly to fexecve(), and no shell or PATH lookup exists.
 * The exact admission profile is arm64-only.  x86_64 is recognized and
 * rejected with ARCHITECTURE_POLICY_UNAVAILABLE rather than generalized.
 *
 * Primary specifications:
 * https://docs.kernel.org/admin-guide/cgroup-v2.html
 * https://docs.kernel.org/userspace-api/landlock.html
 * https://man7.org/linux/man-pages/man2/pr_set_no_new_privs.2const.html
 * https://man7.org/linux/man-pages/man3/fexecve.3.html
 * https://man7.org/linux/man-pages/man2/close_range.2.html
 * https://docs.kernel.org/filesystems/overlayfs.html
 */

#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __linux__
int
main(void)
{
    (void)fprintf(stderr,
        "PLAMEN_LINUX_SCOPE_ERROR stage=HOST_UNSUPPORTED errno=0\n");
    return 74;
}
#else

#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_PATH
#define O_PATH 010000000
#endif
#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule 445
#define __NR_landlock_restrict_self 446
#endif
#ifndef __NR_close_range
#define __NR_close_range 436
#endif

#define EXIT_USAGE 64
#define EXIT_UNSUPPORTED 74
#define EXIT_FAILED 75
#define EXIT_RECOVERY 76
#define MAX_ROOTS 64
#define MAX_RUNTIME_ROOTS 16
#define MAX_ARGS 128
#define MAX_ARG_BYTES 65536
#define MAX_CONTROL 4096
#define MAX_MOUNTINFO 65536
#define MAX_TOPOLOGY_DEPTH 256
#define MAX_RUNTIME_MANIFEST_DEPTH 64
#define MAX_RUNTIME_ENTRIES 100000
#define MAX_RUNTIME_DIRECTORY_ENTRIES 16384
#define MAX_RUNTIME_RELATIVE 16384
#define MAX_RUNTIME_FILE_BYTES UINT64_C(536870912)
#define MAX_RUNTIME_TOTAL_BYTES UINT64_C(4294967296)
#define AUTH_BYTES 32
#define HEX256 64
#define LANDLOCK_MIN_ABI 6
#define MAX_INTERPRETER_BYTES UINT64_C(134217728)
#define MAX_DRIVER_BYTES UINT64_C(16777216)
#define EXEC_STATUS_FD 196
#define INTERPRETER_EXEC_FD 197
#define DRIVER_SCRIPT_EXEC_FD 198
#ifndef FS_VERITY_FL
#define FS_VERITY_FL 0x00100000
#endif
#define RUNTIME_SAFE_INODE_FLAGS ((uint32_t)(FS_IMMUTABLE_FL|FS_NODUMP_FL|\
    FS_NOATIME_FL|FS_INDEX_FL|FS_EXTENT_FL|FS_VERITY_FL))
#define RUNTIME_UNSAFE_MODE (S_ISUID|S_ISGID|S_ISVTX|0022)
#define LL_CREATE_VERSION 1U
#define LL_RULE_PATH_BENEATH 1
#define LL_FS_EXECUTE (UINT64_C(1) << 0)
#define LL_FS_WRITE_FILE (UINT64_C(1) << 1)
#define LL_FS_READ_FILE (UINT64_C(1) << 2)
#define LL_FS_READ_DIR (UINT64_C(1) << 3)
#define LL_FS_REMOVE_DIR (UINT64_C(1) << 4)
#define LL_FS_REMOVE_FILE (UINT64_C(1) << 5)
#define LL_FS_MAKE_CHAR (UINT64_C(1) << 6)
#define LL_FS_MAKE_DIR (UINT64_C(1) << 7)
#define LL_FS_MAKE_REG (UINT64_C(1) << 8)
#define LL_FS_MAKE_SOCK (UINT64_C(1) << 9)
#define LL_FS_MAKE_FIFO (UINT64_C(1) << 10)
#define LL_FS_MAKE_BLOCK (UINT64_C(1) << 11)
#define LL_FS_MAKE_SYM (UINT64_C(1) << 12)
#define LL_FS_REFER (UINT64_C(1) << 13)
#define LL_FS_TRUNCATE (UINT64_C(1) << 14)
#define LL_FS_IOCTL_DEV (UINT64_C(1) << 15)
#define LL_FS_RESOLVE_UNIX (UINT64_C(1) << 16)
#define LL_NET_BIND_TCP (UINT64_C(1) << 0)
#define LL_NET_CONNECT_TCP (UINT64_C(1) << 1)
#define LL_NET_BIND_UDP (UINT64_C(1) << 2)
#define LL_NET_CONNECT_SEND_UDP (UINT64_C(1) << 3)
#define LL_SCOPE_ABSTRACT_UNIX_SOCKET (UINT64_C(1) << 0)
#define LL_SCOPE_SIGNAL (UINT64_C(1) << 1)

struct ll_ruleset_attr {
    uint64_t handled_access_fs;
    uint64_t handled_access_net;
    uint64_t scoped;
};

struct ll_path_beneath_attr {
    uint64_t allowed_access;
    int32_t parent_fd;
} __attribute__((packed));

struct sha256_state {
    uint32_t state[8];
    uint64_t bits;
    unsigned char block[64];
    size_t used;
};

struct pinned_file {
    struct stat row;
    int access_mode;
    unsigned char digest[32];
    char digest_hex[65];
};

struct request {
    int auth_fd, status_fd, gate_fd, cgroup_fd, overlay_storage_fd;
    int interpreter_fd, driver_fd;
    uid_t uid;
    gid_t gid;
    uint64_t pids_max, memory_max, cpu_quota, cpu_period, wall_ms;
    const char *attempt;
    const char *binding;
    const char *expected_interpreter;
    const char *expected_driver;
    const char *expected_runtime;
    int runtime_count, ro_count, rw_count, driver_argc;
    int runtime_fds[MAX_RUNTIME_ROOTS];
    int ro_fds[MAX_ROOTS];
    int rw_fds[MAX_ROOTS];
    char **driver_argv;
};

struct cgroup_scope {
    char name[80];
    int directory_fd, procs_fd, events_fd, kill_fd;
    uint64_t parent_device, parent_inode, device, inode;
    int created;
};

struct overlay_scope {
    char root_name[80];
    int lower_fd, upper_fd, work_fd, merged_fd, visible_fd;
    uint64_t lower_dev, lower_ino, upper_dev, upper_ino;
    uint64_t work_dev, work_ino, merged_dev, merged_ino;
    uint64_t lower_mnt, upper_mnt, work_mnt, merged_mnt;
    uint64_t storage_dev, storage_ino, storage_mnt;
    int created;
};

struct child_ready {
    uint32_t magic;
    int32_t landlock_abi;
    uint32_t uid, gid;
    uint32_t no_new_privs, mount_private;
    uint64_t effective_caps, permitted_caps, inheritable_caps, ambient_caps;
    uint64_t handled_access_fs, handled_access_net;
    struct overlay_scope overlay;
};

static volatile sig_atomic_t interrupted;

static uint32_t
ror32(uint32_t value, unsigned int count)
{
    return (value >> count) | (value << (32U - count));
}

static void
sha_transform(struct sha256_state *ctx, const unsigned char block[64])
{
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
        0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
        0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
        0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
        0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
        0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
        0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
        0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
        0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t w[64], a, b, c, d, e, f, g, h;
    size_t i;
    for (i = 0; i < 16; i++) {
        size_t n = i * 4;
        w[i] = ((uint32_t)block[n] << 24) |
            ((uint32_t)block[n + 1] << 16) |
            ((uint32_t)block[n + 2] << 8) | block[n + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0; i < 64; i++) {
        uint32_t s1=ror32(e,6)^ror32(e,11)^ror32(e,25);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+s1+ch+k[i]+w[i];
        uint32_t s0=ror32(a,2)^ror32(a,13)^ror32(a,22);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=s0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
    memset(w, 0, sizeof(w));
}

static void
sha_init(struct sha256_state *ctx)
{
    static const uint32_t initial[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    memcpy(ctx->state, initial, sizeof(initial));
    ctx->bits=0; ctx->used=0; memset(ctx->block,0,sizeof(ctx->block));
}

static void
sha_update(struct sha256_state *ctx, const unsigned char *data, size_t size)
{
    while (size > 0) {
        size_t room=sizeof(ctx->block)-ctx->used;
        size_t amount=size < room ? size : room;
        memcpy(ctx->block+ctx->used,data,amount);
        ctx->used+=amount; data+=amount; size-=amount;
        if (ctx->used==64) {
            sha_transform(ctx,ctx->block); ctx->bits+=512; ctx->used=0;
        }
    }
}

static void
sha_final(struct sha256_state *ctx, unsigned char out[32])
{
    uint64_t bits=ctx->bits+(uint64_t)ctx->used*8U;
    size_t i;
    ctx->block[ctx->used++]=0x80;
    if (ctx->used>56) {
        memset(ctx->block+ctx->used,0,64-ctx->used);
        sha_transform(ctx,ctx->block); ctx->used=0;
    }
    memset(ctx->block+ctx->used,0,56-ctx->used);
    for (i=0;i<8;i++) ctx->block[63-i]=(unsigned char)(bits>>(i*8));
    sha_transform(ctx,ctx->block);
    for (i=0;i<8;i++) {
        out[i*4]=(unsigned char)(ctx->state[i]>>24);
        out[i*4+1]=(unsigned char)(ctx->state[i]>>16);
        out[i*4+2]=(unsigned char)(ctx->state[i]>>8);
        out[i*4+3]=(unsigned char)ctx->state[i];
    }
    memset(ctx,0,sizeof(*ctx));
}

static void
hmac_sha256(const unsigned char key[32], const unsigned char *data,
    size_t size, unsigned char out[32])
{
    unsigned char inner_key[64], outer_key[64], inner[32];
    struct sha256_state ctx;
    size_t i;
    memset(inner_key,0x36,sizeof(inner_key));
    memset(outer_key,0x5c,sizeof(outer_key));
    for (i=0;i<32;i++) { inner_key[i]^=key[i]; outer_key[i]^=key[i]; }
    sha_init(&ctx); sha_update(&ctx,inner_key,64); sha_update(&ctx,data,size);
    sha_final(&ctx,inner);
    sha_init(&ctx); sha_update(&ctx,outer_key,64); sha_update(&ctx,inner,32);
    sha_final(&ctx,out);
    memset(inner_key,0,sizeof(inner_key));
    memset(outer_key,0,sizeof(outer_key));
    memset(inner,0,sizeof(inner));
}

static void
digest_hex(const unsigned char digest[32], char output[65])
{
    static const char hex[]="0123456789abcdef";
    size_t i;
    for (i=0;i<32;i++) {
        output[i*2]=hex[digest[i]>>4];
        output[i*2+1]=hex[digest[i]&15];
    }
    output[64]='\0';
}

static int
same_file_stat(const struct stat *left, const struct stat *right)
{
    return left->st_dev==right->st_dev&&left->st_ino==right->st_ino&&
        left->st_mode==right->st_mode&&left->st_uid==right->st_uid&&
        left->st_gid==right->st_gid&&left->st_nlink==right->st_nlink&&
        left->st_size==right->st_size&&
        left->st_mtim.tv_sec==right->st_mtim.tv_sec&&
        left->st_mtim.tv_nsec==right->st_mtim.tv_nsec&&
        left->st_ctim.tv_sec==right->st_ctim.tv_sec&&
        left->st_ctim.tv_nsec==right->st_ctim.tv_nsec;
}

static int
observe_pinned_file(int fd, uint64_t maximum, int require_elf,
    struct pinned_file *result)
{
    struct stat after;
    struct sha256_state hash;
    unsigned char buffer[65536], prefix[4];
    uint64_t offset=0;
    ssize_t amount;
    int before_flags,after_flags;
    memset(result,0,sizeof(*result));
    memset(prefix,0,sizeof(prefix));
    before_flags=fcntl(fd,F_GETFL);
    if (before_flags<0||(before_flags&O_ACCMODE)!=O_RDONLY||
        fstat(fd,&result->row)!=0||!S_ISREG(result->row.st_mode)||
        result->row.st_nlink!=1||result->row.st_uid!=0||
        (result->row.st_mode&0022)!=0||result->row.st_size<=0||
        (uint64_t)result->row.st_size>maximum||
        (require_elf&&(result->row.st_mode&0111)==0)) return -1;
    sha_init(&hash);
    while (offset<(uint64_t)result->row.st_size) {
        size_t wanted=sizeof(buffer);
        if ((uint64_t)wanted>(uint64_t)result->row.st_size-offset)
            wanted=(size_t)((uint64_t)result->row.st_size-offset);
        do { amount=pread(fd,buffer,wanted,(off_t)offset); }
        while (amount<0&&errno==EINTR);
        if (amount<=0) { memset(buffer,0,sizeof(buffer)); return -1; }
        if (offset==0) memcpy(prefix,buffer,
            (size_t)amount<sizeof(prefix)?(size_t)amount:sizeof(prefix));
        sha_update(&hash,buffer,(size_t)amount);
        offset+=(uint64_t)amount;
    }
    sha_final(&hash,result->digest);
    memset(buffer,0,sizeof(buffer));
    after_flags=fcntl(fd,F_GETFL);
    if (after_flags<0||(after_flags&O_ACCMODE)!=O_RDONLY||
        (before_flags&O_ACCMODE)!=(after_flags&O_ACCMODE)||
        fstat(fd,&after)!=0||!same_file_stat(&result->row,&after)||
        (require_elf&&memcmp(prefix,"\177ELF",4)!=0)) {
        memset(result,0,sizeof(*result));
        return -1;
    }
    result->access_mode=O_RDONLY;
    digest_hex(result->digest,result->digest_hex);
    return 0;
}

static int
same_pinned_file(const struct pinned_file *left,
    const struct pinned_file *right)
{
    return same_file_stat(&left->row,&right->row)&&
        left->access_mode==O_RDONLY&&right->access_mode==O_RDONLY&&
        memcmp(left->digest,right->digest,sizeof(left->digest))==0;
}

static int mount_id_for_fd(int fd, uint64_t *mount_id);

static int
runtime_native_proof(int fd, uint64_t expected_mount, uint64_t *mount_id,
    uint32_t *inode_flags)
{
    struct statvfs filesystem;
    int flags=0;
    ssize_t xattr_size;
    if (fstatvfs(fd,&filesystem)!=0||(filesystem.f_flag&ST_RDONLY)==0||
        mount_id_for_fd(fd,mount_id)!=0||
        (expected_mount!=0&&*mount_id!=expected_mount)) return -1;
    do { xattr_size=flistxattr(fd,NULL,0); }
    while (xattr_size<0&&errno==EINTR);
    if (xattr_size!=0||ioctl(fd,FS_IOC_GETFLAGS,&flags)!=0||flags<0||
        ((uint32_t)flags&~RUNTIME_SAFE_INODE_FLAGS)!=0) {
        errno=ENOTSUP;
        return -1;
    }
    *inode_flags=(uint32_t)flags;
    return 0;
}

struct runtime_manifest_state {
    struct sha256_state *hash;
    uint64_t entries;
    uint64_t bytes;
    uint64_t root_mount_id;
    int root_index;
};

static int
manifest_field(struct sha256_state *hash, const void *value, size_t length)
{
    char prefix[32];
    int size=snprintf(prefix,sizeof(prefix),"%zu:",length);
    if (size<=0||size>=(int)sizeof(prefix)) return -1;
    sha_update(hash,(const unsigned char *)prefix,(size_t)size);
    sha_update(hash,(const unsigned char *)value,length);
    sha_update(hash,(const unsigned char *)";",1);
    return 0;
}

static int
manifest_uint(struct sha256_state *hash, uintmax_t value)
{
    char number[32];
    int size=snprintf(number,sizeof(number),"%ju",value);
    return size>0&&size<(int)sizeof(number)?
        manifest_field(hash,number,(size_t)size):-1;
}

static int
manifest_stat(struct sha256_state *hash, const struct stat *row)
{
    uintmax_t mtime_ns,ctime_ns;
    if (row->st_mtim.tv_sec<0||row->st_ctim.tv_sec<0||
        (uintmax_t)row->st_mtim.tv_sec>UINTMAX_MAX/UINTMAX_C(1000000000)||
        (uintmax_t)row->st_ctim.tv_sec>UINTMAX_MAX/UINTMAX_C(1000000000))
        return -1;
    mtime_ns=(uintmax_t)row->st_mtim.tv_sec*UINTMAX_C(1000000000)+
        (uintmax_t)row->st_mtim.tv_nsec;
    ctime_ns=(uintmax_t)row->st_ctim.tv_sec*UINTMAX_C(1000000000)+
        (uintmax_t)row->st_ctim.tv_nsec;
    return manifest_uint(hash,(uintmax_t)row->st_dev)==0&&
        manifest_uint(hash,(uintmax_t)row->st_ino)==0&&
        manifest_uint(hash,(uintmax_t)row->st_mode)==0&&
        manifest_uint(hash,(uintmax_t)row->st_uid)==0&&
        manifest_uint(hash,(uintmax_t)row->st_gid)==0&&
        manifest_uint(hash,(uintmax_t)row->st_nlink)==0&&
        manifest_uint(hash,(uintmax_t)row->st_size)==0&&
        manifest_uint(hash,mtime_ns)==0&&manifest_uint(hash,ctime_ns)==0?0:-1;
}

static int
compare_names(const void *left, const void *right)
{
    const char *const *a=left;
    const char *const *b=right;
    return strcmp(*a,*b);
}

static void
free_names(char **names, size_t count)
{
    size_t i;
    if (names==NULL) return;
    for (i=0;i<count;i++) free(names[i]);
    free(names);
}

static int
manifest_regular_file(int directory_fd, const char *name,
    const struct stat *expected, struct runtime_manifest_state *state,
    char output[65], uint32_t *inode_flags)
{
    struct sha256_state hash;
    struct stat before,after;
    unsigned char buffer[65536],digest[32];
    uint64_t offset=0;
    ssize_t amount;
    int fd=openat(directory_fd,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    uint64_t mount_id;
    if (fd<0||fstat(fd,&before)!=0||!same_file_stat(expected,&before)||
        before.st_nlink!=1||
        runtime_native_proof(fd,state->root_mount_id,&mount_id,inode_flags)!=0||
        before.st_size<0||(uint64_t)before.st_size>MAX_RUNTIME_FILE_BYTES) {
        if (fd>=0) close(fd);
        return -1;
    }
    sha_init(&hash);
    while (offset<(uint64_t)before.st_size) {
        size_t wanted=sizeof(buffer);
        if ((uint64_t)wanted>(uint64_t)before.st_size-offset)
            wanted=(size_t)((uint64_t)before.st_size-offset);
        do { amount=pread(fd,buffer,wanted,(off_t)offset); }
        while (amount<0&&errno==EINTR);
        if (amount<=0) {
            memset(buffer,0,sizeof(buffer));
            close(fd);
            return -1;
        }
        sha_update(&hash,buffer,(size_t)amount);
        offset+=(uint64_t)amount;
    }
    sha_final(&hash,digest);
    memset(buffer,0,sizeof(buffer));
    if (fstat(fd,&after)!=0||!same_file_stat(&before,&after)) {
        memset(digest,0,sizeof(digest));
        close(fd);
        return -1;
    }
    close(fd);
    if (state->bytes>MAX_RUNTIME_TOTAL_BYTES-offset) {
        memset(digest,0,sizeof(digest));
        errno=EOVERFLOW;
        return -1;
    }
    state->bytes+=offset;
    digest_hex(digest,output);
    memset(digest,0,sizeof(digest));
    return 0;
}

static int
manifest_directory(int directory_fd, char relative[MAX_RUNTIME_RELATIVE],
    size_t relative_size, int depth, struct runtime_manifest_state *state)
{
    struct stat before,after;
    char **names=NULL;
    DIR *stream=NULL;
    size_t count=0,i;
    int duplicate=-1,result=-1;
    if (depth>=MAX_RUNTIME_MANIFEST_DEPTH||
        fstat(directory_fd,&before)!=0||!S_ISDIR(before.st_mode)) {
        errno=EOVERFLOW;
        return -1;
    }
    names=calloc(MAX_RUNTIME_DIRECTORY_ENTRIES,sizeof(*names));
    duplicate=dup(directory_fd);
    if (names==NULL||duplicate<0) goto done;
    stream=fdopendir(duplicate);
    if (stream==NULL) goto done;
    duplicate=-1;
    for (;;) {
        struct dirent *entry;
        errno=0;
        entry=readdir(stream);
        if (entry==NULL) {
            if (errno!=0) goto done;
            break;
        }
        if (strcmp(entry->d_name,".")==0||strcmp(entry->d_name,"..")==0)
            continue;
        if (count>=MAX_RUNTIME_DIRECTORY_ENTRIES) {
            errno=EOVERFLOW;
            goto done;
        }
        names[count]=strdup(entry->d_name);
        if (names[count]==NULL) goto done;
        count++;
    }
    if (closedir(stream)!=0) { stream=NULL; goto done; }
    stream=NULL;
    qsort(names,count,sizeof(*names),compare_names);
    for (i=0;i<count;i++) {
        struct stat row,replayed;
        char kind,content[65];
        size_t name_size=strlen(names[i]), path_size;
        int child=-1;
        uint32_t inode_flags=0;
        uint64_t mount_id;
        if (++state->entries>MAX_RUNTIME_ENTRIES||name_size==0||
            name_size>NAME_MAX||
            relative_size+(relative_size==0?0:1)+name_size>=
                MAX_RUNTIME_RELATIVE) {
            errno=EOVERFLOW;
            goto done;
        }
        path_size=relative_size;
        if (path_size!=0) relative[path_size++]='/';
        memcpy(relative+path_size,names[i],name_size);
        path_size+=name_size;
        relative[path_size]='\0';
        if (fstatat(directory_fd,names[i],&row,AT_SYMLINK_NOFOLLOW)!=0)
            goto done;
        if ((row.st_mode&RUNTIME_UNSAFE_MODE)!=0||row.st_uid!=0) {
            errno=EPERM;
            goto done;
        }
        memset(content,0,sizeof(content));
        if (S_ISDIR(row.st_mode)) {
            kind='D';
            content[0]='-'; content[1]='\0';
            child=openat(directory_fd,names[i],
                O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            if (child<0||fstat(child,&replayed)!=0||
                !same_file_stat(&row,&replayed)||
                runtime_native_proof(child,state->root_mount_id,&mount_id,
                    &inode_flags)!=0) {
                if (child>=0) close(child);
                goto done;
            }
        } else if (S_ISREG(row.st_mode)) {
            kind='F';
            if (manifest_regular_file(directory_fd,names[i],&row,state,
                    content,&inode_flags)!=0) goto done;
        } else if (S_ISLNK(row.st_mode)) {
            errno=ELOOP;
            goto done;
        } else {
            errno=ENOTSUP;
            goto done;
        }
        if (manifest_field(state->hash,"E",1)!=0||
            manifest_uint(state->hash,(uintmax_t)state->root_index)!=0||
            manifest_field(state->hash,relative,path_size)!=0||
            manifest_field(state->hash,&kind,1)!=0||
            manifest_stat(state->hash,&row)!=0||
            manifest_uint(state->hash,(uintmax_t)inode_flags)!=0||
            manifest_uint(state->hash,0)!=0||
            manifest_field(state->hash,content,strlen(content))!=0) {
            if (child>=0) close(child);
            goto done;
        }
        if (kind=='D') {
            if (manifest_directory(child,relative,path_size,depth+1,state)!=0) {
                if (child>=0) close(child);
                goto done;
            }
            close(child);
        }
        relative[relative_size]='\0';
    }
    if (fstat(directory_fd,&after)!=0||!same_file_stat(&before,&after))
        goto done;
    result=0;
done:
    if (stream!=NULL) closedir(stream);
    if (duplicate>=0) close(duplicate);
    free_names(names,count);
    return result;
}

static int
runtime_roster(const struct request *r, char output[65])
{
    struct sha256_state hash;
    unsigned char digest[32];
    char relative[MAX_RUNTIME_RELATIVE];
    struct runtime_manifest_state state;
    int i;
    sha_init(&hash);
    memset(&state,0,sizeof(state));
    state.hash=&hash;
    memset(relative,0,sizeof(relative));
    for (i=0;i<r->runtime_count;i++) {
        struct stat observed,replayed;
        uint64_t mount_id;
        uint32_t inode_flags;
        if (fstat(r->runtime_fds[i],&observed)!=0||
            !S_ISDIR(observed.st_mode)||observed.st_nlink<1||
            observed.st_uid!=0||(observed.st_mode&RUNTIME_UNSAFE_MODE)!=0||
            runtime_native_proof(r->runtime_fds[i],0,&mount_id,
                &inode_flags)!=0) return -1;
        state.root_index=i;
        state.root_mount_id=mount_id;
        if (manifest_field(&hash,"R",1)!=0||
            manifest_uint(&hash,(uintmax_t)i)!=0||
            manifest_stat(&hash,&observed)!=0||
            manifest_uint(&hash,(uintmax_t)inode_flags)!=0||
            manifest_uint(&hash,0)!=0||
            manifest_directory(r->runtime_fds[i],relative,0,0,&state)!=0||
            fstat(r->runtime_fds[i],&replayed)!=0||
            !same_file_stat(&observed,&replayed)) return -1;
    }
    sha_final(&hash,digest);
    digest_hex(digest,output);
    memset(digest,0,sizeof(digest));
    memset(relative,0,sizeof(relative));
    return 0;
}

static int
hash_one_argument(struct sha256_state *hash, const char *argument)
{
    char prefix[32];
    size_t length=strlen(argument);
    int size=snprintf(prefix,sizeof(prefix),"%zu:",length);
    if (size<=0||size>=(int)sizeof(prefix)) return -1;
    sha_update(hash,(const unsigned char *)prefix,(size_t)size);
    sha_update(hash,(const unsigned char *)argument,length);
    sha_update(hash,(const unsigned char *)";",1);
    return 0;
}

static int
invocation_digest(const struct request *r, char output[65])
{
    static const char *fixed[]={"/proc/self/fd/197","-I","-B","-P",
        "/proc/self/fd/198"};
    struct sha256_state hash;
    unsigned char digest[32];
    size_t i;
    int j;
    sha_init(&hash);
    for (i=0;i<sizeof(fixed)/sizeof(fixed[0]);i++)
        if (hash_one_argument(&hash,fixed[i])!=0) return -1;
    for (j=0;j<r->driver_argc;j++)
        if (hash_one_argument(&hash,r->driver_argv[j])!=0) return -1;
    sha_final(&hash,digest);
    digest_hex(digest,output);
    memset(digest,0,sizeof(digest));
    return 0;
}

static int
parse_u64(const char *text, uint64_t minimum, uint64_t maximum,
    uint64_t *result)
{
    char *end=NULL;
    unsigned long long value;
    if (text==NULL || text[0]=='\0' || text[0]=='+' || text[0]=='-') return -1;
    errno=0; value=strtoull(text,&end,10);
    if (errno!=0 || end==text || *end!='\0' || value<minimum || value>maximum)
        return -1;
    *result=(uint64_t)value;
    return 0;
}

static int
parse_fd(const char *text, int *result)
{
    uint64_t value;
    if (parse_u64(text,3,INT32_MAX,&value)!=0) return -1;
    *result=(int)value;
    return 0;
}

static int
is_hex256(const char *text)
{
    size_t i;
    if (text==NULL || strlen(text)!=HEX256) return 0;
    for (i=0;i<HEX256;i++)
        if (!((text[i]>='0'&&text[i]<='9')||(text[i]>='a'&&text[i]<='f')))
            return 0;
    return 1;
}

static int
write_all(int fd, const void *buffer, size_t size)
{
    const unsigned char *cursor=buffer;
    while (size>0) {
        ssize_t amount=write(fd,cursor,size);
        if (amount<0 && errno==EINTR) continue;
        if (amount<=0) return -1;
        cursor+=(size_t)amount; size-=(size_t)amount;
    }
    return 0;
}

static int
read_exact(int fd, void *buffer, size_t size)
{
    unsigned char *cursor=buffer;
    while (size>0) {
        ssize_t amount=read(fd,cursor,size);
        if (amount<0 && errno==EINTR) continue;
        if (amount<=0) return -1;
        cursor+=(size_t)amount; size-=(size_t)amount;
    }
    return 0;
}

static int
read_bounded_at(int fd, char *buffer, size_t capacity)
{
    ssize_t amount;
    do { amount=pread(fd,buffer,capacity-1,0); } while (amount<0&&errno==EINTR);
    if (amount<0 || (size_t)amount>=capacity-1) {
        if (amount>=0) errno=EOVERFLOW;
        return -1;
    }
    buffer[amount]='\0';
    return (int)amount;
}

static int
has_word(const char *buffer, const char *word)
{
    const char *cursor=buffer;
    size_t size=strlen(word);
    while (*cursor!='\0') {
        while (*cursor==' '||*cursor=='\n'||*cursor=='\t') cursor++;
        if (strncmp(cursor,word,size)==0 &&
            (cursor[size]=='\0'||cursor[size]==' '||cursor[size]=='\n'||
             cursor[size]=='\t')) return 1;
        while (*cursor!='\0'&&*cursor!=' '&&*cursor!='\n'&&*cursor!='\t')
            cursor++;
    }
    return 0;
}

static int
open_control(int directory_fd, const char *name, int flags)
{
    int fd=openat(directory_fd,name,flags|O_CLOEXEC|O_NOFOLLOW);
    struct stat row;
    if (fd<0) return -1;
    if (fstat(fd,&row)!=0 || !S_ISREG(row.st_mode)) {
        int saved=errno==0?ESTALE:errno; close(fd); errno=saved; return -1;
    }
    return fd;
}

static int
directory_fd_valid(int fd)
{
    struct stat row;
    return fstat(fd,&row)==0 && S_ISDIR(row.st_mode) && row.st_nlink>=1;
}

static int
pipe_fd_valid(int fd)
{
    struct stat row;
    return fstat(fd,&row)==0 && (S_ISFIFO(row.st_mode)||S_ISSOCK(row.st_mode));
}

static int
reserved_exec_fd(int fd)
{
    return fd==EXEC_STATUS_FD||fd==INTERPRETER_EXEC_FD||
        fd==DRIVER_SCRIPT_EXEC_FD;
}

static int
fd_set_unique(const struct request *r)
{
    int all[MAX_ROOTS*2+MAX_RUNTIME_ROOTS+7], used=0, i, j;
    struct stat objects[MAX_ROOTS*2+MAX_RUNTIME_ROOTS+4];
    int object_fds[MAX_ROOTS*2+MAX_RUNTIME_ROOTS+4], object_count=0;
    all[used++]=r->auth_fd; all[used++]=r->status_fd;
    all[used++]=r->gate_fd; all[used++]=r->cgroup_fd;
    all[used++]=r->overlay_storage_fd;
    all[used++]=r->interpreter_fd; all[used++]=r->driver_fd;
    for (i=0;i<r->runtime_count;i++) all[used++]=r->runtime_fds[i];
    for (i=0;i<r->ro_count;i++) all[used++]=r->ro_fds[i];
    for (i=0;i<r->rw_count;i++) all[used++]=r->rw_fds[i];
    for (i=0;i<used;i++) {
        if (reserved_exec_fd(all[i])) return 0;
        for (j=i+1;j<used;j++) if (all[i]==all[j]) return 0;
    }
    object_fds[object_count++]=r->cgroup_fd;
    object_fds[object_count++]=r->overlay_storage_fd;
    object_fds[object_count++]=r->interpreter_fd;
    object_fds[object_count++]=r->driver_fd;
    for (i=0;i<r->runtime_count;i++)
        object_fds[object_count++]=r->runtime_fds[i];
    for (i=0;i<r->ro_count;i++) object_fds[object_count++]=r->ro_fds[i];
    for (i=0;i<r->rw_count;i++) object_fds[object_count++]=r->rw_fds[i];
    for (i=0;i<object_count;i++) {
        if (fstat(object_fds[i],&objects[i])!=0) return 0;
        for (j=0;j<i;j++)
            if (objects[i].st_dev==objects[j].st_dev &&
                objects[i].st_ino==objects[j].st_ino) return 0;
    }
    return 1;
}

static int
directory_contains_fd(int ancestor_fd, int descendant_fd)
{
    struct stat ancestor, current_row, parent_row;
    int current=-1, parent=-1, depth;
    if (fstat(ancestor_fd,&ancestor)!=0||!S_ISDIR(ancestor.st_mode)) return -1;
    current=dup(descendant_fd);
    if (current<0) return -1;
    for (depth=0;depth<MAX_TOPOLOGY_DEPTH;depth++) {
        if (fstat(current,&current_row)!=0||!S_ISDIR(current_row.st_mode))
            goto unavailable;
        if (current_row.st_dev==ancestor.st_dev&&
            current_row.st_ino==ancestor.st_ino) {
            close(current);
            return 1;
        }
        parent=openat(current,"..",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (parent<0||fstat(parent,&parent_row)!=0||
            !S_ISDIR(parent_row.st_mode)) goto unavailable;
        if (parent_row.st_dev==current_row.st_dev&&
            parent_row.st_ino==current_row.st_ino) {
            close(parent);
            close(current);
            return 0;
        }
        close(current);
        current=parent;
        parent=-1;
    }
unavailable:
    if (parent>=0) close(parent);
    if (current>=0) close(current);
    errno=ESTALE;
    return -1;
}

static int
root_topology_disjoint(const struct request *r)
{
    int roots[MAX_ROOTS*2+MAX_RUNTIME_ROOTS+1], count=0, i, j;
    roots[count++]=r->overlay_storage_fd;
    for (i=0;i<r->runtime_count;i++) roots[count++]=r->runtime_fds[i];
    for (i=0;i<r->ro_count;i++) roots[count++]=r->ro_fds[i];
    for (i=0;i<r->rw_count;i++) roots[count++]=r->rw_fds[i];
    for (i=0;i<count;i++) {
        for (j=i+1;j<count;j++) {
            int forward=directory_contains_fd(roots[i],roots[j]);
            int reverse;
            if (forward!=0) return -1;
            reverse=directory_contains_fd(roots[j],roots[i]);
            if (reverse!=0) return -1;
        }
    }
    return 0;
}

static int
parse_request(int argc, char **argv, struct request *r)
{
    uint64_t value;
    size_t total=0;
    int index=1, i;
    struct stat interpreter, driver;
    memset(r,0,sizeof(*r));
    if (argc<28 || argc>MAX_ARGS || strcmp(argv[index++],"--v1")!=0) return -1;
    for (i=0;i<argc;i++) {
        size_t length=strlen(argv[i]);
        if (length>4096 || total>MAX_ARG_BYTES-length-1) return -1;
        total+=length+1;
    }
    if (parse_fd(argv[index++],&r->auth_fd)!=0 ||
        parse_fd(argv[index++],&r->status_fd)!=0 ||
        parse_fd(argv[index++],&r->gate_fd)!=0 ||
        parse_fd(argv[index++],&r->cgroup_fd)!=0 ||
        parse_fd(argv[index++],&r->overlay_storage_fd)!=0 ||
        parse_fd(argv[index++],&r->interpreter_fd)!=0 ||
        parse_fd(argv[index++],&r->driver_fd)!=0 ||
        parse_u64(argv[index++],1,UINT32_MAX-1U,&value)!=0) return -1;
    r->uid=(uid_t)value;
    if (parse_u64(argv[index++],1,UINT32_MAX-1U,&value)!=0) return -1;
    r->gid=(gid_t)value;
    if (parse_u64(argv[index++],1,4096,&r->pids_max)!=0 ||
        parse_u64(argv[index++],UINT64_C(16777216),UINT64_C(1099511627776),
            &r->memory_max)!=0 ||
        parse_u64(argv[index++],1000,UINT64_C(1000000000),&r->cpu_quota)!=0 ||
        parse_u64(argv[index++],1000,UINT64_C(1000000000),&r->cpu_period)!=0 ||
        r->cpu_quota>r->cpu_period ||
        parse_u64(argv[index++],100,UINT64_C(86400000),&r->wall_ms)!=0)
        return -1;
    r->attempt=argv[index++]; r->binding=argv[index++];
    r->expected_interpreter=argv[index++];
    r->expected_driver=argv[index++];
    r->expected_runtime=argv[index++];
    if (!is_hex256(r->attempt)||!is_hex256(r->binding)||
        !is_hex256(r->expected_interpreter)||
        !is_hex256(r->expected_driver)||!is_hex256(r->expected_runtime)||
        parse_u64(argv[index++],1,MAX_RUNTIME_ROOTS,&value)!=0) return -1;
    r->runtime_count=(int)value;
    if (index+r->runtime_count>=argc) return -1;
    for (i=0;i<r->runtime_count;i++)
        if (parse_fd(argv[index++],&r->runtime_fds[i])!=0) return -1;
    if (
        parse_u64(argv[index++],1,MAX_ROOTS,&value)!=0) return -1;
    r->ro_count=(int)value;
    if (index+r->ro_count>=argc) return -1;
    for (i=0;i<r->ro_count;i++)
        if (parse_fd(argv[index++],&r->ro_fds[i])!=0) return -1;
    if (parse_u64(argv[index++],1,MAX_ROOTS,&value)!=0) return -1;
    r->rw_count=(int)value;
    if (index+r->rw_count>=argc) return -1;
    for (i=0;i<r->rw_count;i++)
        if (parse_fd(argv[index++],&r->rw_fds[i])!=0) return -1;
    if (strcmp(argv[index++],"--")!=0) return -1;
    r->driver_argv=&argv[index];
    r->driver_argc=argc-index;
    if (!fd_set_unique(r)||!pipe_fd_valid(r->auth_fd)||
        !pipe_fd_valid(r->status_fd)||!pipe_fd_valid(r->gate_fd)||
        !directory_fd_valid(r->cgroup_fd)||
        !directory_fd_valid(r->overlay_storage_fd)||
        fstat(r->interpreter_fd,&interpreter)!=0||
        !S_ISREG(interpreter.st_mode)||(interpreter.st_mode&0111)==0||
        fstat(r->driver_fd,&driver)!=0||!S_ISREG(driver.st_mode)) return -1;
    for (i=0;i<r->runtime_count;i++)
        if (!directory_fd_valid(r->runtime_fds[i])) return -1;
    for (i=0;i<r->ro_count;i++) if (!directory_fd_valid(r->ro_fds[i])) return -1;
    for (i=0;i<r->rw_count;i++) if (!directory_fd_valid(r->rw_fds[i])) return -1;
    return 0;
}

static int
admit_linux_architecture(void)
{
    struct utsname host;
    if (uname(&host)!=0||strcmp(host.sysname,"Linux")!=0||
        sizeof(void *)!=8||geteuid()!=0) {
        errno=ENOTSUP;
        return -1;
    }
    if (strcmp(host.machine,"aarch64")==0||strcmp(host.machine,"arm64")==0)
        return 0;
    if (strcmp(host.machine,"x86_64")==0||strcmp(host.machine,"amd64")==0) {
        errno=EOPNOTSUPP;
        return 1;
    }
    errno=ENOTSUP;
    return -1;
}

static int
write_control_exact(int directory_fd, const char *name, const char *value)
{
    int fd=open_control(directory_fd,name,O_RDWR);
    char observed[128];
    size_t size=strlen(value);
    int amount, result=-1;
    if (fd<0 || size==0 || size>=sizeof(observed)-2) {
        if (fd>=0) close(fd);
        errno=EINVAL;
        return -1;
    }
    if (write_all(fd,value,size)!=0) goto done;
    amount=read_bounded_at(fd,observed,sizeof(observed));
    if (amount<0) goto done;
    while (amount>0&&(observed[amount-1]=='\n'||observed[amount-1]==' '))
        observed[--amount]='\0';
    if ((size_t)amount!=size||memcmp(observed,value,size)!=0) {
        errno=ESTALE;
        goto done;
    }
    result=0;
done:
    memset(observed,0,sizeof(observed));
    close(fd);
    return result;
}

static int
setup_parent_controllers(int parent_fd)
{
    struct statfs filesystem;
    int controllers=-1, subtree=-1, result=-1;
    char observed[MAX_CONTROL];
    const char enable[]="+cpu +memory +pids";
    if (fstatfs(parent_fd,&filesystem)!=0 ||
        (unsigned long)filesystem.f_type!=(unsigned long)CGROUP2_SUPER_MAGIC) {
        errno=ENOTSUP;
        return -1;
    }
    controllers=open_control(parent_fd,"cgroup.controllers",O_RDONLY);
    subtree=open_control(parent_fd,"cgroup.subtree_control",O_RDWR);
    if (controllers<0||subtree<0||
        read_bounded_at(controllers,observed,sizeof(observed))<0||
        !has_word(observed,"cpu")||!has_word(observed,"memory")||
        !has_word(observed,"pids")) goto done;
    if (write_all(subtree,enable,strlen(enable))!=0 ||
        read_bounded_at(subtree,observed,sizeof(observed))<0 ||
        !has_word(observed,"cpu")||!has_word(observed,"memory")||
        !has_word(observed,"pids")) goto done;
    result=0;
done:
    memset(observed,0,sizeof(observed));
    if (controllers>=0) close(controllers);
    if (subtree>=0) close(subtree);
    return result;
}

static int
setup_cgroup(const struct request *r, struct cgroup_scope *scope)
{
    struct statfs filesystem;
    struct stat row;
    char value[128];
    memset(scope,0,sizeof(*scope));
    scope->directory_fd=scope->procs_fd=scope->events_fd=scope->kill_fd=-1;
    if (fstat(r->cgroup_fd,&row)!=0||!S_ISDIR(row.st_mode)) return -1;
    scope->parent_device=(uint64_t)row.st_dev;
    scope->parent_inode=(uint64_t)row.st_ino;
    if (setup_parent_controllers(r->cgroup_fd)!=0 ||
        snprintf(scope->name,sizeof(scope->name),"plamen-%s",r->attempt)>=
            (int)sizeof(scope->name) ||
        mkdirat(r->cgroup_fd,scope->name,0700)!=0) return -1;
    scope->created=1;
    scope->directory_fd=openat(r->cgroup_fd,scope->name,
        O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (scope->directory_fd<0||fstatfs(scope->directory_fd,&filesystem)!=0||
        (unsigned long)filesystem.f_type!=(unsigned long)CGROUP2_SUPER_MAGIC||
        fstat(scope->directory_fd,&row)!=0||!S_ISDIR(row.st_mode)) return -1;
    scope->device=(uint64_t)row.st_dev;
    scope->inode=(uint64_t)row.st_ino;
    if (snprintf(value,sizeof(value),"%" PRIu64,r->pids_max)<0 ||
        write_control_exact(scope->directory_fd,"pids.max",value)!=0 ||
        snprintf(value,sizeof(value),"%" PRIu64,r->memory_max)<0 ||
        write_control_exact(scope->directory_fd,"memory.max",value)!=0 ||
        snprintf(value,sizeof(value),"%" PRIu64 " %" PRIu64,
            r->cpu_quota,r->cpu_period)<0 ||
        write_control_exact(scope->directory_fd,"cpu.max",value)!=0) return -1;
    scope->procs_fd=open_control(scope->directory_fd,"cgroup.procs",O_RDWR);
    scope->events_fd=open_control(scope->directory_fd,"cgroup.events",O_RDONLY);
    scope->kill_fd=open_control(scope->directory_fd,"cgroup.kill",O_WRONLY);
    return scope->procs_fd>=0&&scope->events_fd>=0&&scope->kill_fd>=0?0:-1;
}

static int
move_pid_to_cgroup(const struct cgroup_scope *scope, pid_t pid)
{
    char value[32];
    int size=snprintf(value,sizeof(value),"%jd",(intmax_t)pid);
    if (size<=0||size>=(int)sizeof(value)) return -1;
    return write_all(scope->procs_fd,value,(size_t)size);
}

static int
mount_id_for_fd(int fd, uint64_t *mount_id)
{
    char path[64], buffer[MAX_CONTROL];
    int info_fd, amount;
    char *line, *end;
    if (snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",fd)>=
        (int)sizeof(path)) return -1;
    info_fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (info_fd<0) return -1;
    amount=read_bounded_at(info_fd,buffer,sizeof(buffer));
    close(info_fd);
    if (amount<0) return -1;
    line=strstr(buffer,"mnt_id:");
    if (line==NULL) { errno=ENOTSUP; return -1; }
    line+=7;
    while (*line==' '||*line=='\t') line++;
    errno=0;
    *mount_id=strtoull(line,&end,10);
    if (errno!=0||end==line||(*end!='\n'&&*end!='\0')) return -1;
    memset(buffer,0,sizeof(buffer));
    return *mount_id>0?0:-1;
}

static int
stat_overlay_fd(int fd, uint64_t *device, uint64_t *inode, uint64_t *mount_id)
{
    struct stat row;
    if (fstat(fd,&row)!=0||!S_ISDIR(row.st_mode)||row.st_nlink<1||
        mount_id_for_fd(fd,mount_id)!=0) return -1;
    *device=(uint64_t)row.st_dev;
    *inode=(uint64_t)row.st_ino;
    return 0;
}

static int
mount_is_private(uint64_t mount_id)
{
    char buffer[MAX_MOUNTINFO], prefix[64];
    char *cursor, *line_end, *separator;
    int fd, used=0, prefix_size, result=-1;
    fd=open("/proc/self/mountinfo",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd<0) return -1;
    while (used<(int)sizeof(buffer)-1) {
        ssize_t amount=read(fd,buffer+used,sizeof(buffer)-1-(size_t)used);
        if (amount<0&&errno==EINTR) continue;
        if (amount<0) { close(fd); return -1; }
        if (amount==0) break;
        used+=(int)amount;
    }
    close(fd);
    if (used==(int)sizeof(buffer)-1) { errno=EOVERFLOW; return -1; }
    buffer[used]='\0';
    prefix_size=snprintf(prefix,sizeof(prefix),"%" PRIu64 " ",mount_id);
    if (prefix_size<=0||prefix_size>=(int)sizeof(prefix)) return -1;
    cursor=buffer;
    while (*cursor!='\0') {
        line_end=strchr(cursor,'\n');
        if (line_end!=NULL) *line_end='\0';
        if (strncmp(cursor,prefix,(size_t)prefix_size)==0) {
            separator=strstr(cursor," - ");
            if (separator!=NULL) {
                *separator='\0';
                result=(strstr(cursor," shared:")==NULL&&
                    strstr(cursor," master:")==NULL&&
                    strstr(cursor," propagate_from:")==NULL)?1:0;
            }
            break;
        }
        if (line_end==NULL) break;
        cursor=line_end+1;
    }
    memset(buffer,0,sizeof(buffer));
    return result;
}

static int
fd_mount_readonly(int fd)
{
    struct statvfs row;
    return fstatvfs(fd,&row)==0&&(row.f_flag&ST_RDONLY)!=0;
}

static int
make_fd_path(char *buffer, size_t size, int fd, const char *suffix)
{
    int amount=snprintf(buffer,size,"/proc/self/fd/%d%s",fd,suffix);
    return amount>0&&(size_t)amount<size?0:-1;
}

static int
verify_procfs_fixed_descriptors(const struct pinned_file *interpreter,
    const struct pinned_file *driver)
{
    struct statfs filesystem;
    struct stat interpreter_row, driver_row;
    int directory=open("/proc/self/fd",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (directory<0||fstatfs(directory,&filesystem)!=0||
        (unsigned long)filesystem.f_type!=(unsigned long)PROC_SUPER_MAGIC||
        stat("/proc/self/fd/197",&interpreter_row)!=0||
        stat("/proc/self/fd/198",&driver_row)!=0) {
        if (directory>=0) close(directory);
        errno=ENOTSUP;
        return -1;
    }
    close(directory);
    if (interpreter_row.st_dev!=interpreter->row.st_dev||
        interpreter_row.st_ino!=interpreter->row.st_ino||
        driver_row.st_dev!=driver->row.st_dev||
        driver_row.st_ino!=driver->row.st_ino) {
        errno=ESTALE;
        return -1;
    }
    return 0;
}

static int
setup_overlay(const struct request *r, struct overlay_scope *scope)
{
    char root_suffix[96], lower_suffix[112], upper_suffix[112];
    char work_suffix[112], merged_suffix[112];
    char source[160], lower[160], upper[160], work[160], merged[160];
    char visible[64], options[600];
    struct stat upper_row, work_row;
    memset(scope,0,sizeof(*scope));
    scope->lower_fd=scope->upper_fd=scope->work_fd=-1;
    scope->merged_fd=scope->visible_fd=-1;
    if (snprintf(scope->root_name,sizeof(scope->root_name),
        "plamen-overlay-%s",r->attempt)>=(int)sizeof(scope->root_name) ||
        snprintf(root_suffix,sizeof(root_suffix),"/%s",scope->root_name)>=
            (int)sizeof(root_suffix) ||
        snprintf(lower_suffix,sizeof(lower_suffix),"%s/lower",root_suffix)>=
            (int)sizeof(lower_suffix) ||
        snprintf(upper_suffix,sizeof(upper_suffix),"%s/upper",root_suffix)>=
            (int)sizeof(upper_suffix) ||
        snprintf(work_suffix,sizeof(work_suffix),"%s/work",root_suffix)>=
            (int)sizeof(work_suffix) ||
        snprintf(merged_suffix,sizeof(merged_suffix),"%s/merged",root_suffix)>=
            (int)sizeof(merged_suffix)) return -1;
    if (mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL)!=0 ||
        mkdirat(r->overlay_storage_fd,scope->root_name,0700)!=0) return -1;
    scope->created=1;
    {
        int root=openat(r->overlay_storage_fd,scope->root_name,
            O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (root<0||mkdirat(root,"lower",0700)!=0||mkdirat(root,"upper",0700)!=0||
            mkdirat(root,"work",0700)!=0||mkdirat(root,"merged",0700)!=0) {
            if (root>=0) close(root);
            return -1;
        }
        close(root);
    }
    if (make_fd_path(source,sizeof(source),r->ro_fds[0],"")!=0 ||
        make_fd_path(lower,sizeof(lower),r->overlay_storage_fd,lower_suffix)!=0 ||
        make_fd_path(upper,sizeof(upper),r->overlay_storage_fd,upper_suffix)!=0 ||
        make_fd_path(work,sizeof(work),r->overlay_storage_fd,work_suffix)!=0 ||
        make_fd_path(merged,sizeof(merged),r->overlay_storage_fd,merged_suffix)!=0 ||
        make_fd_path(visible,sizeof(visible),r->ro_fds[0],"")!=0) return -1;
    if (mount(source,lower,NULL,MS_BIND|MS_REC,NULL)!=0 ||
        mount(NULL,lower,NULL,MS_BIND|MS_REMOUNT|MS_RDONLY|MS_NOSUID|MS_NODEV,
            NULL)!=0) return -1;
    if (snprintf(options,sizeof(options),
        "lowerdir=%s,upperdir=%s,workdir=%s,redirect_dir=nofollow,"
        "index=off,metacopy=off,xino=off",lower,upper,work)>=
        (int)sizeof(options) ||
        mount("overlay",merged,"overlay",MS_NOSUID|MS_NODEV,options)!=0 ||
        mount(merged,visible,NULL,MS_BIND|MS_REC,NULL)!=0) return -1;
    scope->lower_fd=open(lower,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    scope->upper_fd=open(upper,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    scope->work_fd=open(work,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    scope->merged_fd=open(merged,O_PATH|O_CLOEXEC|O_NOFOLLOW);
    /*
     * visible is the procfs magic-link for an already-authenticated retained
     * project descriptor.  Following exactly that descriptor is intentional;
     * every user-supplied filesystem root remains path-free.
     */
    scope->visible_fd=open(visible,O_PATH|O_CLOEXEC);
    if (scope->lower_fd<0||scope->upper_fd<0||scope->work_fd<0||
        scope->merged_fd<0||scope->visible_fd<0 ||
        stat_overlay_fd(r->overlay_storage_fd,&scope->storage_dev,
            &scope->storage_ino,&scope->storage_mnt)!=0 ||
        stat_overlay_fd(scope->lower_fd,&scope->lower_dev,&scope->lower_ino,
            &scope->lower_mnt)!=0 ||
        stat_overlay_fd(scope->upper_fd,&scope->upper_dev,&scope->upper_ino,
            &scope->upper_mnt)!=0 ||
        stat_overlay_fd(scope->work_fd,&scope->work_dev,&scope->work_ino,
            &scope->work_mnt)!=0 ||
        stat_overlay_fd(scope->visible_fd,&scope->merged_dev,&scope->merged_ino,
            &scope->merged_mnt)!=0 ||
        fstat(scope->upper_fd,&upper_row)!=0||fstat(scope->work_fd,&work_row)!=0||
        upper_row.st_dev!=work_row.st_dev||upper_row.st_ino==work_row.st_ino||
        !fd_mount_readonly(scope->lower_fd)||
        mount_is_private(scope->storage_mnt)!=1||
        mount_is_private(scope->lower_mnt)!=1||
        mount_is_private(scope->merged_mnt)!=1) {
        return -1;
    }
    return 0;
}

static int
landlock_abi(void)
{
    return (int)syscall(__NR_landlock_create_ruleset,NULL,0,LL_CREATE_VERSION);
}

static int
landlock_path(int ruleset_fd, int parent_fd, uint64_t allowed)
{
    struct ll_path_beneath_attr path={.allowed_access=allowed,
        .parent_fd=parent_fd};
    return (int)syscall(__NR_landlock_add_rule,ruleset_fd,
        LL_RULE_PATH_BENEATH,&path,0);
}

static int
install_landlock(const struct request *r, int merged_fd,
    uint64_t *handled_fs, uint64_t *handled_net)
{
    struct ll_ruleset_attr ruleset;
    uint64_t fs, read_only, writable, net;
    int fd, abi=landlock_abi(), i;
    if (abi<LANDLOCK_MIN_ABI) { errno=ENOTSUP; return -1; }
    fs=LL_FS_EXECUTE|LL_FS_WRITE_FILE|LL_FS_READ_FILE|LL_FS_READ_DIR|
        LL_FS_REMOVE_DIR|LL_FS_REMOVE_FILE|LL_FS_MAKE_CHAR|LL_FS_MAKE_DIR|
        LL_FS_MAKE_REG|LL_FS_MAKE_SOCK|LL_FS_MAKE_FIFO|LL_FS_MAKE_BLOCK|
        LL_FS_MAKE_SYM|LL_FS_REFER|LL_FS_TRUNCATE|LL_FS_IOCTL_DEV;
    if (abi>=9) fs|=LL_FS_RESOLVE_UNIX;
    net=LL_NET_BIND_TCP|LL_NET_CONNECT_TCP;
    if (abi>=10) net|=LL_NET_BIND_UDP|LL_NET_CONNECT_SEND_UDP;
    memset(&ruleset,0,sizeof(ruleset));
    ruleset.handled_access_fs=fs;
    ruleset.handled_access_net=net;
    ruleset.scoped=LL_SCOPE_ABSTRACT_UNIX_SOCKET|LL_SCOPE_SIGNAL;
    fd=(int)syscall(__NR_landlock_create_ruleset,&ruleset,sizeof(ruleset),0);
    if (fd<0) return -1;
    read_only=LL_FS_EXECUTE|LL_FS_READ_FILE|LL_FS_READ_DIR;
    writable=fs&~LL_FS_EXECUTE;
    if (landlock_path(fd,INTERPRETER_EXEC_FD,
        LL_FS_EXECUTE|LL_FS_READ_FILE)!=0) { close(fd); return -1; }
    if (landlock_path(fd,DRIVER_SCRIPT_EXEC_FD,LL_FS_READ_FILE)!=0) {
        close(fd); return -1;
    }
    for (i=0;i<r->runtime_count;i++)
        if (landlock_path(fd,r->runtime_fds[i],read_only)!=0) {
            close(fd); return -1;
        }
    if (landlock_path(fd,merged_fd,read_only)!=0) { close(fd); return -1; }
    for (i=1;i<r->ro_count;i++)
        if (landlock_path(fd,r->ro_fds[i],read_only)!=0) {
            close(fd); return -1;
        }
    for (i=0;i<r->rw_count;i++)
        if (landlock_path(fd,r->rw_fds[i],writable)!=0) {
            close(fd); return -1;
        }
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 ||
        prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1 ||
        syscall(__NR_landlock_restrict_self,fd,0)!=0) {
        close(fd); return -1;
    }
    close(fd);
    *handled_fs=fs;
    *handled_net=net;
    return abi;
}

static int
drop_privileges(uid_t uid, gid_t gid, struct child_ready *ready)
{
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct data[2];
    uid_t ru, eu, su;
    gid_t rg, eg, sg;
    int cap, group_count;
    for (cap=0;cap<64;cap++) {
        if (prctl(PR_CAPBSET_DROP,cap,0,0,0)!=0 && errno!=EINVAL) return -1;
    }
    if (setgroups(0,NULL)!=0||prctl(PR_SET_KEEPCAPS,0,0,0,0)!=0||
        setresgid(gid,gid,gid)!=0||setresuid(uid,uid,uid)!=0||
        prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_CLEAR_ALL,0,0,0)!=0||
        prctl(PR_SET_DUMPABLE,0,0,0,0)!=0||
        getresuid(&ru,&eu,&su)!=0||getresgid(&rg,&eg,&sg)!=0||
        ru!=uid||eu!=uid||su!=uid||rg!=gid||eg!=gid||sg!=gid) return -1;
    group_count=getgroups(0,NULL);
    if (group_count!=0) return -1;
    memset(&header,0,sizeof(header));
    memset(data,0,sizeof(data));
    header.version=_LINUX_CAPABILITY_VERSION_3;
    header.pid=0;
    if (syscall(SYS_capget,&header,data)!=0 ||
        data[0].effective!=0||data[0].permitted!=0||data[0].inheritable!=0||
        data[1].effective!=0||data[1].permitted!=0||data[1].inheritable!=0)
        return -1;
    for (cap=0;cap<64;cap++) {
        int ambient=prctl(PR_CAP_AMBIENT,PR_CAP_AMBIENT_IS_SET,cap,0,0);
        if (ambient>0||(ambient<0&&errno!=EINVAL)) return -1;
    }
    ready->effective_caps=((uint64_t)data[1].effective<<32)|data[0].effective;
    ready->permitted_caps=((uint64_t)data[1].permitted<<32)|data[0].permitted;
    ready->inheritable_caps=((uint64_t)data[1].inheritable<<32)|
        data[0].inheritable;
    ready->ambient_caps=0;
    ready->uid=(uint32_t)eu;
    ready->gid=(uint32_t)eg;
    memset(data,0,sizeof(data));
    return 0;
}

static int
poll_readable(int fd, int timeout_ms)
{
    struct pollfd row={.fd=fd,.events=POLLIN|POLLHUP};
    int result;
    do {
        result=poll(&row,1,timeout_ms);
    } while (result<0&&errno==EINTR&&!interrupted);
    if (result<=0||!(row.revents&(POLLIN|POLLHUP))) {
        if (result==0) errno=ETIMEDOUT;
        return -1;
    }
    return 0;
}

static void
close_cgroup_child_copy(const struct request *r,
    const struct cgroup_scope *scope)
{
    if (scope->procs_fd>=0) close(scope->procs_fd);
    if (scope->events_fd>=0) close(scope->events_fd);
    if (scope->kill_fd>=0) close(scope->kill_fd);
    if (scope->directory_fd>=0) close(scope->directory_fd);
    close(r->cgroup_fd);
    close(r->status_fd);
    close(r->gate_fd);
}

static int
child_enter_scope(const struct request *r, const struct cgroup_scope *cgroup,
    int start_fd, int ready_fd, const struct pinned_file *expected_interpreter,
    const struct pinned_file *expected_driver, const char expected_runtime[65])
{
    struct child_ready ready;
    struct overlay_scope overlay;
    struct pinned_file observed_interpreter, observed_driver;
    char observed_runtime[65];
    char *exec_argv[MAX_ARGS];
    char gate;
    int abi, i, used=0, flags;
    char *environment[]={"LANG=C","LC_ALL=C",NULL};
    memset(&ready,0,sizeof(ready));
    if (prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)!=0||getppid()==1||
        ptrace(PTRACE_TRACEME,0,NULL,NULL)!=0||raise(SIGSTOP)!=0||
        poll_readable(start_fd,5000)!=0||read_exact(start_fd,&gate,1)!=0||
        gate!='1') return 111;
    close_cgroup_child_copy(r,cgroup);
    if (unshare(CLONE_NEWNS)!=0||setup_overlay(r,&overlay)!=0||
        close(r->overlay_storage_fd)!=0||
        drop_privileges(r->uid,r->gid,&ready)!=0)
        return 112;
    abi=install_landlock(r,overlay.visible_fd,&ready.handled_access_fs,
        &ready.handled_access_net);
    if (abi<0||fchdir(overlay.visible_fd)!=0||
        observe_pinned_file(INTERPRETER_EXEC_FD,MAX_INTERPRETER_BYTES,1,
            &observed_interpreter)!=0||
        observe_pinned_file(DRIVER_SCRIPT_EXEC_FD,MAX_DRIVER_BYTES,0,
            &observed_driver)!=0||
        !same_pinned_file(expected_interpreter,&observed_interpreter)||
        !same_pinned_file(expected_driver,&observed_driver)||
        runtime_roster(r,observed_runtime)!=0||
        strcmp(expected_runtime,observed_runtime)!=0) return 113;
    ready.magic=UINT32_C(0x504c5343);
    ready.landlock_abi=abi;
    ready.no_new_privs=(uint32_t)prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0);
    ready.mount_private=1;
    ready.overlay=overlay;
    if (write_all(ready_fd,&ready,sizeof(ready))!=0) return 114;
    if (poll_readable(start_fd,30000)!=0||read_exact(start_fd,&gate,1)!=0||
        gate!='2') {
        (void)write_all(ready_fd,"F",1);
        return 114;
    }
    if (dup3(ready_fd,EXEC_STATUS_FD,O_CLOEXEC)<0) {
        (void)write_all(ready_fd,"F",1);
        return 115;
    }
    close(ready_fd);
    if (observe_pinned_file(INTERPRETER_EXEC_FD,MAX_INTERPRETER_BYTES,1,
            &observed_interpreter)!=0||
        observe_pinned_file(DRIVER_SCRIPT_EXEC_FD,MAX_DRIVER_BYTES,0,
            &observed_driver)!=0||
        !same_pinned_file(expected_interpreter,&observed_interpreter)||
        !same_pinned_file(expected_driver,&observed_driver)||
        runtime_roster(r,observed_runtime)!=0||
        strcmp(expected_runtime,observed_runtime)!=0) goto exec_failure;
    exec_argv[used++]="/proc/self/fd/197";
    exec_argv[used++]="-I";
    exec_argv[used++]="-B";
    exec_argv[used++]="-P";
    exec_argv[used++]="/proc/self/fd/198";
    for (i=0;i<r->driver_argc;i++) exec_argv[used++]=r->driver_argv[i];
    exec_argv[used]=NULL;
    if (close(start_fd)!=0||
        syscall(__NR_close_range,3U,(unsigned int)EXEC_STATUS_FD-1U,0U)!=0||
        syscall(__NR_close_range,(unsigned int)DRIVER_SCRIPT_EXEC_FD+1U,
            UINT_MAX,0U)!=0) goto exec_failure;
    flags=fcntl(INTERPRETER_EXEC_FD,F_GETFD);
    if (flags<0||fcntl(INTERPRETER_EXEC_FD,F_SETFD,flags&~FD_CLOEXEC)!=0)
        goto exec_failure;
    flags=fcntl(DRIVER_SCRIPT_EXEC_FD,F_GETFD);
    if (flags<0||fcntl(DRIVER_SCRIPT_EXEC_FD,F_SETFD,flags&~FD_CLOEXEC)!=0)
        goto exec_failure;
    if (signal(SIGPIPE,SIG_DFL)==SIG_ERR) goto exec_failure;
    fexecve(INTERPRETER_EXEC_FD,exec_argv,environment);
exec_failure:
    (void)write_all(EXEC_STATUS_FD,"F",1);
    return 115;
}

static int
emit_receipt(int fd, const unsigned char key[32], const char *payload)
{
    static const char hex[]="0123456789abcdef";
    unsigned char mac[32];
    char line[MAX_CONTROL];
    size_t payload_size=strlen(payload), i;
    int prefix;
    if (payload_size>3000) return -1;
    hmac_sha256(key,(const unsigned char *)payload,payload_size,mac);
    prefix=snprintf(line,sizeof(line),"PLAMEN_LINUX_SCOPE %s;mac=",payload);
    if (prefix<0||(size_t)prefix+65>sizeof(line)) {
        memset(mac,0,sizeof(mac)); return -1;
    }
    for (i=0;i<32;i++) {
        line[prefix+i*2]=hex[mac[i]>>4];
        line[prefix+i*2+1]=hex[mac[i]&15];
    }
    line[prefix+64]='\n';
    if (write_all(fd,line,(size_t)prefix+65)!=0) {
        memset(mac,0,sizeof(mac)); memset(line,0,sizeof(line)); return -1;
    }
    memset(mac,0,sizeof(mac)); memset(line,0,sizeof(line));
    return 0;
}

static uint64_t
elapsed_ms(const struct timespec *start, const struct timespec *now)
{
    int64_t seconds=(int64_t)now->tv_sec-(int64_t)start->tv_sec;
    int64_t nanos=(int64_t)now->tv_nsec-(int64_t)start->tv_nsec;
    if (nanos<0) { seconds--; nanos+=1000000000L; }
    if (seconds<0) return 0;
    return (uint64_t)seconds*1000U+(uint64_t)nanos/1000000U;
}

static int
wait_child_bounded(pid_t child, uint64_t wall_ms, int *status)
{
    struct timespec start,now,pause={.tv_sec=0,.tv_nsec=10000000};
    if (clock_gettime(CLOCK_MONOTONIC,&start)!=0) return -1;
    for (;;) {
        pid_t observed=waitpid(child,status,WNOHANG);
        if (observed==child) return 0;
        if (observed<0&&errno!=EINTR) return -1;
        if (interrupted) { errno=EINTR; return 1; }
        if (clock_gettime(CLOCK_MONOTONIC,&now)!=0) return -1;
        if (elapsed_ms(&start,&now)>=wall_ms) { errno=ETIMEDOUT; return 1; }
        (void)nanosleep(&pause,NULL);
    }
}

static int
wait_trace_event_bounded(pid_t child, uint64_t wall_ms, int *status)
{
    struct timespec start,now,pause={.tv_sec=0,.tv_nsec=10000000};
    if (clock_gettime(CLOCK_MONOTONIC,&start)!=0) return -1;
    for (;;) {
        pid_t observed=waitpid(child,status,WNOHANG|WUNTRACED);
        if (observed==child) return 0;
        if (observed<0&&errno!=EINTR) return -1;
        if (interrupted) { errno=EINTR; return -1; }
        if (clock_gettime(CLOCK_MONOTONIC,&now)!=0) return -1;
        if (elapsed_ms(&start,&now)>=wall_ms) { errno=ETIMEDOUT; return -1; }
        (void)nanosleep(&pause,NULL);
    }
}

static int
cgroup_populated(const struct cgroup_scope *scope)
{
    char observed[MAX_CONTROL];
    int result;
    if (read_bounded_at(scope->events_fd,observed,sizeof(observed))<0)
        return -1;
    if (strstr(observed,"populated 0")!=NULL) result=0;
    else if (strstr(observed,"populated 1")!=NULL) result=1;
    else result=-1;
    memset(observed,0,sizeof(observed));
    return result;
}

static int
cleanup_cgroup(const struct request *r, struct cgroup_scope *scope)
{
    struct timespec pause={.tv_sec=0,.tv_nsec=10000000};
    int i,result=0;
    if (!scope->created) return 0;
    if (scope->kill_fd>=0&&write_all(scope->kill_fd,"1",1)!=0&&errno!=ENOENT)
        result=-1;
    if (scope->events_fd>=0) {
        for (i=0;i<200;i++) {
            int populated=cgroup_populated(scope);
            if (populated==0) break;
            if (populated<0) { result=-1; break; }
            (void)nanosleep(&pause,NULL);
        }
        if (i==200) result=-1;
    }
    if (scope->procs_fd>=0) close(scope->procs_fd);
    if (scope->events_fd>=0) close(scope->events_fd);
    if (scope->kill_fd>=0) close(scope->kill_fd);
    if (scope->directory_fd>=0) close(scope->directory_fd);
    scope->procs_fd=scope->events_fd=scope->kill_fd=scope->directory_fd=-1;
    if (unlinkat(r->cgroup_fd,scope->name,AT_REMOVEDIR)!=0&&errno!=ENOENT)
        result=-1;
    if (result==0) scope->created=0;
    return result;
}

static int
cleanup_overlay(const struct request *r, const struct child_ready *ready)
{
    char root_name[80];
    int root,result=0;
    if (ready->magic==UINT32_C(0x504c5343)&&ready->overlay.created) {
        if (snprintf(root_name,sizeof(root_name),"%s",ready->overlay.root_name)>=
            (int)sizeof(root_name)) return -1;
    } else if (snprintf(root_name,sizeof(root_name),"plamen-overlay-%s",
        r->attempt)>=(int)sizeof(root_name)) {
        return -1;
    }
    root=openat(r->overlay_storage_fd,root_name,
        O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if (root<0) return errno==ENOENT?0:-1;
    if (unlinkat(root,"lower",AT_REMOVEDIR)!=0&&errno!=ENOENT) result=-1;
    if (unlinkat(root,"merged",AT_REMOVEDIR)!=0&&errno!=ENOENT) result=-1;
    if (unlinkat(root,"work",AT_REMOVEDIR)!=0&&errno!=ENOENT) result=-1;
    if (unlinkat(root,"upper",AT_REMOVEDIR)!=0&&errno!=ENOENT) result=-1;
    close(root);
    if (unlinkat(r->overlay_storage_fd,root_name,AT_REMOVEDIR)!=0&&
        errno!=ENOENT) result=-1;
    return result;
}

static void
handle_signal(int number)
{
    (void)number;
    interrupted=1;
}

static int
run_request(const struct request *r, unsigned char auth_key[32])
{
    struct cgroup_scope cgroup;
    struct child_ready ready;
    struct pinned_file interpreter, driver;
    int start_pipe[2]={-1,-1}, ready_pipe[2]={-1,-1};
    int child_status=0, trace_status=0, wait_result=-1;
    int cleanup_result=-1, overlay_cleanup=-1;
    char payload[3000], external_gate, exec_status;
    char runtime_digest[65], argv_digest[65];
    pid_t child=-1;
    int result=EXIT_FAILED;
    ssize_t exec_amount;
    memset(&cgroup,0,sizeof(cgroup));
    cgroup.directory_fd=cgroup.procs_fd=cgroup.events_fd=cgroup.kill_fd=-1;
    memset(&ready,0,sizeof(ready));
    if (root_topology_disjoint(r)!=0||
        observe_pinned_file(r->interpreter_fd,MAX_INTERPRETER_BYTES,1,
            &interpreter)!=0||
        observe_pinned_file(r->driver_fd,MAX_DRIVER_BYTES,0,&driver)!=0||
        runtime_roster(r,runtime_digest)!=0||
        strcmp(interpreter.digest_hex,r->expected_interpreter)!=0||
        strcmp(driver.digest_hex,r->expected_driver)!=0||
        strcmp(runtime_digest,r->expected_runtime)!=0||
        invocation_digest(r,argv_digest)!=0||
        dup3(r->driver_fd,EXEC_STATUS_FD,O_CLOEXEC)<0||
        dup3(r->interpreter_fd,INTERPRETER_EXEC_FD,O_CLOEXEC)<0||
        dup3(r->driver_fd,DRIVER_SCRIPT_EXEC_FD,O_CLOEXEC)<0||
        verify_procfs_fixed_descriptors(&interpreter,&driver)!=0||
        setup_cgroup(r,&cgroup)!=0||pipe2(start_pipe,O_CLOEXEC)!=0||
        pipe2(ready_pipe,O_CLOEXEC)!=0) goto failure;
    child=fork();
    if (child<0) goto failure;
    if (child==0) {
        int child_result;
        close(start_pipe[1]); close(ready_pipe[0]);
        child_result=child_enter_scope(r,&cgroup,start_pipe[0],ready_pipe[1],
            &interpreter,&driver,runtime_digest);
        _exit(child_result);
    }
    close(EXEC_STATUS_FD);
    close(INTERPRETER_EXEC_FD);
    close(DRIVER_SCRIPT_EXEC_FD);
    close(start_pipe[0]); start_pipe[0]=-1;
    close(ready_pipe[1]); ready_pipe[1]=-1;
    if (move_pid_to_cgroup(&cgroup,child)!=0||
        wait_trace_event_bounded(child,5000,&trace_status)!=0||
        !WIFSTOPPED(trace_status)||WSTOPSIG(trace_status)!=SIGSTOP||
        ((unsigned int)trace_status>>16)!=0||
        ptrace(PTRACE_SETOPTIONS,child,NULL,
            (void *)(uintptr_t)PTRACE_O_TRACEEXEC)!=0||
        ptrace(PTRACE_CONT,child,NULL,NULL)!=0||
        write_all(start_pipe[1],"1",1)!=0||
        poll_readable(ready_pipe[0],10000)!=0||
        read_exact(ready_pipe[0],&ready,sizeof(ready))!=0||
        ready.magic!=UINT32_C(0x504c5343)||
        ready.uid!=(uint32_t)r->uid||ready.gid!=(uint32_t)r->gid||
        ready.no_new_privs!=1||ready.mount_private!=1||
        ready.effective_caps!=0||ready.permitted_caps!=0||
        ready.inheritable_caps!=0||ready.ambient_caps!=0||
        ready.landlock_abi<LANDLOCK_MIN_ABI) goto failure;
    {
        int payload_size=snprintf(payload,sizeof(payload),
        "schema=plamen.linux_guest_scope.v1;phase=READY;attempt=%s;binding=%s;"
        "child=%jd;cgroup_name=%s;cgroup_parent_device=%" PRIu64 ";"
        "cgroup_parent_inode=%" PRIu64 ";cgroup_device=%" PRIu64 ";"
        "cgroup_inode=%" PRIu64 ";pids_max=%" PRIu64 ";memory_max=%" PRIu64 ";"
        "cpu_quota=%" PRIu64 ";cpu_period=%" PRIu64 ";landlock_abi=%d;"
        "handled_fs=%" PRIu64 ";handled_net=%" PRIu64 ";uid=%u;gid=%u;"
        "caps_effective=0;caps_permitted=0;caps_inheritable=0;caps_ambient=0;"
        "no_new_privs=1;mount_propagation=PRIVATE;"
        "procfs=VERIFIED;path_lookup=0;direct_shebang_exec=0;"
        "interpreter_exec_fd=197;driver_script_fd=198;"
        "surviving_fds=0:1:2:197:198;"
        "interpreter_device=%ju;interpreter_inode=%ju;interpreter_mode=%ju;"
        "interpreter_owner_uid=%ju;interpreter_owner_gid=%ju;"
        "interpreter_link_count=%ju;interpreter_access_mode=O_RDONLY;"
        "interpreter_size=%ju;interpreter_sha256=%s;"
        "driver_device=%ju;driver_inode=%ju;driver_mode=%ju;"
        "driver_owner_uid=%ju;driver_owner_gid=%ju;driver_link_count=%ju;"
        "driver_access_mode=O_RDONLY;"
        "driver_size=%ju;driver_sha256=%s;runtime_count=%d;"
        "runtime_mounts_read_only=1;runtime_roster_sha256=%s;argv_sha256=%s;"
        "overlay_storage_device=%" PRIu64 ";overlay_storage_inode=%" PRIu64 ";"
        "overlay_storage_mount=%" PRIu64 ";"
        "lower_device=%" PRIu64 ";lower_inode=%" PRIu64 ";lower_mount=%" PRIu64 ";"
        "upper_device=%" PRIu64 ";upper_inode=%" PRIu64 ";upper_mount=%" PRIu64 ";"
        "work_device=%" PRIu64 ";work_inode=%" PRIu64 ";work_mount=%" PRIu64 ";"
        "merged_device=%" PRIu64 ";merged_inode=%" PRIu64 ";merged_mount=%" PRIu64,
        r->attempt,r->binding,(intmax_t)child,cgroup.name,
        cgroup.parent_device,cgroup.parent_inode,cgroup.device,cgroup.inode,
        r->pids_max,r->memory_max,r->cpu_quota,r->cpu_period,
        ready.landlock_abi,ready.handled_access_fs,ready.handled_access_net,
        ready.uid,ready.gid,
        (uintmax_t)interpreter.row.st_dev,(uintmax_t)interpreter.row.st_ino,
        (uintmax_t)interpreter.row.st_mode,(uintmax_t)interpreter.row.st_uid,
        (uintmax_t)interpreter.row.st_gid,(uintmax_t)interpreter.row.st_nlink,
        (uintmax_t)interpreter.row.st_size,interpreter.digest_hex,
        (uintmax_t)driver.row.st_dev,
        (uintmax_t)driver.row.st_ino,(uintmax_t)driver.row.st_mode,
        (uintmax_t)driver.row.st_uid,(uintmax_t)driver.row.st_gid,
        (uintmax_t)driver.row.st_nlink,(uintmax_t)driver.row.st_size,
        driver.digest_hex,r->runtime_count,
        runtime_digest,argv_digest,
        ready.overlay.storage_dev,ready.overlay.storage_ino,
        ready.overlay.storage_mnt,
        ready.overlay.lower_dev,ready.overlay.lower_ino,ready.overlay.lower_mnt,
        ready.overlay.upper_dev,ready.overlay.upper_ino,ready.overlay.upper_mnt,
        ready.overlay.work_dev,ready.overlay.work_ino,ready.overlay.work_mnt,
        ready.overlay.merged_dev,ready.overlay.merged_ino,
        ready.overlay.merged_mnt);
        if (payload_size<0||payload_size>=(int)sizeof(payload)||
            emit_receipt(r->status_fd,auth_key,payload)!=0||
            poll_readable(r->gate_fd,30000)!=0||
            read_exact(r->gate_fd,&external_gate,1)!=0||external_gate!='1'||
            write_all(start_pipe[1],"2",1)!=0||
            wait_trace_event_bounded(child,5000,&trace_status)!=0||
            !WIFSTOPPED(trace_status)||WSTOPSIG(trace_status)!=SIGTRAP||
            ((unsigned int)trace_status>>16)!=PTRACE_EVENT_EXEC||
            poll_readable(ready_pipe[0],5000)!=0) goto failure;
        do { exec_amount=read(ready_pipe[0],&exec_status,1); }
        while (exec_amount<0&&errno==EINTR&&!interrupted);
        if (exec_amount!=0||ptrace(PTRACE_DETACH,child,NULL,NULL)!=0)
            goto failure;
        close(ready_pipe[0]); ready_pipe[0]=-1;
    }
    wait_result=wait_child_bounded(child,r->wall_ms,&child_status);
    if (wait_result!=0) {
        if (cgroup.kill_fd>=0) (void)write_all(cgroup.kill_fd,"1",1);
        (void)kill(child,SIGKILL);
        while (waitpid(child,&child_status,0)<0&&errno==EINTR) { }
    }
    child=-1;
    cleanup_result=cleanup_cgroup(r,&cgroup);
    overlay_cleanup=cleanup_overlay(r,&ready);
    {
        int payload_size=snprintf(payload,sizeof(payload),
        "schema=plamen.linux_guest_scope.v1;phase=FINAL;attempt=%s;binding=%s;"
        "interpreter_access_mode=O_RDONLY;driver_access_mode=O_RDONLY;"
        "wait_status=%d;timed_out=%d;exec_verified=1;cleanup=%s",
        r->attempt,r->binding,child_status,wait_result==1?1:0,
        cleanup_result==0&&overlay_cleanup==0?
            "COMPLETE":"RECOVERY_REQUIRED");
        if (payload_size<0||payload_size>=(int)sizeof(payload)||
            emit_receipt(r->status_fd,auth_key,payload)!=0) return EXIT_FAILED;
    }
    if (cleanup_result!=0||overlay_cleanup!=0) return EXIT_RECOVERY;
    if (WIFEXITED(child_status)) result=WEXITSTATUS(child_status);
    else if (WIFSIGNALED(child_status)) result=128+WTERMSIG(child_status);
    return result;

failure:
    (void)close(EXEC_STATUS_FD);
    (void)close(INTERPRETER_EXEC_FD);
    (void)close(DRIVER_SCRIPT_EXEC_FD);
    if (cgroup.kill_fd>=0) (void)write_all(cgroup.kill_fd,"1",1);
    if (child>0) {
        (void)kill(child,SIGKILL);
        while (waitpid(child,&child_status,0)<0&&errno==EINTR) { }
    }
    cleanup_result=cleanup_cgroup(r,&cgroup);
    overlay_cleanup=cleanup_overlay(r,&ready);
    (void)snprintf(payload,sizeof(payload),
        "schema=plamen.linux_guest_scope.v1;phase=ERROR;attempt=%s;binding=%s;"
        "exec_verified=0;cleanup=%s",r->attempt,r->binding,
        cleanup_result==0&&overlay_cleanup==0?"COMPLETE":"RECOVERY_REQUIRED");
    (void)emit_receipt(r->status_fd,auth_key,payload);
    if (start_pipe[0]>=0) close(start_pipe[0]);
    if (start_pipe[1]>=0) close(start_pipe[1]);
    if (ready_pipe[0]>=0) close(ready_pipe[0]);
    if (ready_pipe[1]>=0) close(ready_pipe[1]);
    return cleanup_result==0&&overlay_cleanup==0?EXIT_FAILED:EXIT_RECOVERY;
}

int
main(int argc, char **argv)
{
    struct request request;
    struct sigaction action;
    unsigned char key[AUTH_BYTES], extra;
    int result;
    memset(key,0,sizeof(key));
    if (parse_request(argc,argv,&request)!=0) {
        (void)fprintf(stderr,
            "PLAMEN_LINUX_SCOPE_ERROR stage=PROTOCOL errno=%d\n",EINVAL);
        return EXIT_USAGE;
    }
    result=admit_linux_architecture();
    if (result!=0) {
        (void)fprintf(stderr,
            "PLAMEN_LINUX_SCOPE_ERROR stage=%s errno=%d\n",
            result==1?"ARCHITECTURE_POLICY_UNAVAILABLE":"ADMISSION",errno);
        return EXIT_UNSUPPORTED;
    }
    if (poll_readable(request.auth_fd,5000)!=0||
        read_exact(request.auth_fd,key,sizeof(key))!=0||
        poll_readable(request.auth_fd,5000)!=0||
        read(request.auth_fd,&extra,1)!=0) {
        memset(key,0,sizeof(key));
        return EXIT_USAGE;
    }
    close(request.auth_fd);
    memset(&action,0,sizeof(action));
    action.sa_handler=handle_signal;
    sigemptyset(&action.sa_mask);
    if (signal(SIGPIPE,SIG_IGN)==SIG_ERR) {
        memset(key,0,sizeof(key));
        return EXIT_FAILED;
    }
    (void)sigaction(SIGTERM,&action,NULL);
    (void)sigaction(SIGINT,&action,NULL);
    (void)sigaction(SIGHUP,&action,NULL);
    result=run_request(&request,key);
    memset(key,0,sizeof(key));
    return result;
}

#endif
