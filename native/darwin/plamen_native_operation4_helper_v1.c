#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_operation4_helper_v1.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <dlfcn.h>
#include <libproc.h>
#include <mach-o/dyld.h>
#include <mach/vm_prot.h>
#include <sys/proc_info.h>
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define OP4_GROUP_HEADER_SIZE 256U
#define OP4_GROUP_ROW_SIZE 256U
#define OP4_GROUP_ROW_COUNT 23U
#define OP4_GROUP_MAX_BYTES (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define OP4_DOCUMENT_MAX_BYTES (64ULL * 1024ULL * 1024ULL)
#define OP4_CHILD_TIMEOUT_SECONDS 7200U
#define OP4_CHILD_ROOT_FD 3
#define OP4_CHILD_GROUP_FD 4
#define OP4_CHILD_OUTPUT_FD 5
#define OP4_CHILD_SCRATCH_FD 10
#define OP4_CHILD_TRANSFORM_FD 34
#define OP4_CHILD_NATIVE_TRANSFORM_FD 35
#define OP4_CHILD_MATERIALIZER_FD 36
#define OP4_CHILD_ARCHIVE_TRANSFORM_FD 37
#define OP4_CHILD_VALIDATOR_FD 38
#define OP4_CHILD_VERIFIER_KEY_FD 39
#define OP4_CHILD_PRODUCER_RECEIPT_FD 40
#define OP4_TERMINAL_MAC_OFFSET \
    (PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE - 32U)

static const uint8_t group_magic[8] = {'P','L','M','R','H','G','1',0};
static const uint8_t terminal_magic[8] = {'P','L','M','O','P','4','T','1'};
static const uint8_t producer_magic[8] = {'P','L','M','O','P','4','R','1'};
static const char terminal_mac_domain[] =
    "PLAMEN-NATIVE-OPERATION4-TERMINAL-MAC-V1";
static const char transform_closure_domain[] =
    "PLAMEN-OP4-TRANSFORM-CLOSURE-V1";
static const char policy_roster_domain[] =
    "PLAMEN-NATIVE-OPERATION4-POLICY-ROSTER-V1";
static const char *const group_paths[] = {
    "control/runtime-composition-manifest.json",
    "runtime-inputs/00-base_rootfs.payload",
    "runtime-inputs/00-base_rootfs.source-manifest.json",
    "runtime-inputs/01-debian_package_state.payload",
    "runtime-inputs/01-debian_package_state.source-manifest.json",
    "runtime-inputs/02-plamen_guest.payload",
    "runtime-inputs/02-plamen_guest.source-manifest.json",
    "runtime-inputs/03-cpython.payload",
    "runtime-inputs/03-cpython.source-manifest.json",
    "runtime-inputs/04-plamen_package.payload",
    "runtime-inputs/04-plamen_package.source-manifest.json",
    "runtime-inputs/05-codex.payload",
    "runtime-inputs/05-codex.source-manifest.json",
    "runtime-inputs/06-claude.payload",
    "runtime-inputs/06-claude.source-manifest.json",
    "runtime-inputs/07-foundry.payload",
    "runtime-inputs/07-foundry.source-manifest.json",
    "runtime-inputs/08-medusa.payload",
    "runtime-inputs/08-medusa.source-manifest.json",
    "runtime-inputs/09-solc_amd64.payload",
    "runtime-inputs/09-solc_amd64.source-manifest.json",
    "runtime-inputs/10-amd64_compat.payload",
    "runtime-inputs/10-amd64_compat.source-manifest.json"
};
static const char *const transform_closure_names[] = {
    "plamen_transform_bundle",
    "native_runtime_grouped_transform",
    "runtime_image_materializer",
    "oci_retained_archive_transform",
    "native_operation4_acquisition_validation"
};
static const char *const transform_closure_relatives[] = {
    "plamen_transform_bundle.py",
    "native_runtime_grouped_transform.py",
    "runtime_image_materializer.py",
    "oci_retained_archive_transform.py",
    "native_operation4_acquisition_validation.py"
};

struct sha256_context {
    uint32_t state[8]; uint64_t total; uint8_t block[64]; size_t used;
};

struct retained_identity {
    dev_t device; ino_t inode; mode_t mode; uid_t uid; gid_t gid;
    nlink_t links; off_t size; uint32_t generation;
    struct timespec mtime; struct timespec ctime;
};

struct plamen_native_operation4_context_v1 {
    uid_t owner_uid;
    int runtime_root_fd, python_fd, transform_fd;
    int transform_dependency_fds[4];
    int install_verifier_public_key_fd;
    int producer_receipt_fds[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    int grouped_writer_fd, grouped_reader_fd;
    int terminal_writer_fd, terminal_reader_fd;
    struct retained_identity runtime_root, python, transform, grouped, terminal;
    struct retained_identity transform_dependencies[4];
    struct retained_identity install_verifier_public_key;
    struct retained_identity producer_receipts[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT];
    struct plamen_native_operation4_fixed_policy_v1 policy;
    uint8_t policy_roster_sha256[32];
    uint8_t executable_sha256[32];
    uint8_t python_sha256[32];
    uint8_t transform_sha256[32];
    uint8_t transform_closure_sha256[32];
    uint8_t install_verifier_public_key_sha256[32];
    uint8_t terminal_mac_key[32];
    int consumed;
    int testing;
};

/* A generated strong definition replaces this fail-closed value at release. */
#if defined(__GNUC__)
__attribute__((weak))
#endif
const struct plamen_native_operation4_fixed_policy_v1
    plamen_native_operation4_generated_policy_v1 = {0};

static uint32_t rotate_right(uint32_t v, unsigned int n)
{ return (v >> n) | (v << (32U - n)); }

static void sha256_transform(struct sha256_context *c, const uint8_t b[64])
{
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t w[64],a,d,e,f,g,h,i,j,t1,t2,bb,cc;
    for (i=0;i<16U;++i) { const uint8_t *p=b+i*4U; w[i]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
    for (i=16U;i<64U;++i) { uint32_t s0=rotate_right(w[i-15U],7)^rotate_right(w[i-15U],18)^(w[i-15U]>>3); uint32_t s1=rotate_right(w[i-2U],17)^rotate_right(w[i-2U],19)^(w[i-2U]>>10); w[i]=w[i-16U]+s0+w[i-7U]+s1; }
    a=c->state[0]; bb=c->state[1]; cc=c->state[2]; d=c->state[3]; e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
    for (i=0;i<64U;++i) { uint32_t s1=rotate_right(e,6)^rotate_right(e,11)^rotate_right(e,25); uint32_t ch=(e&f)^((~e)&g); t1=h+s1+ch+k[i]+w[i]; uint32_t s0=rotate_right(a,2)^rotate_right(a,13)^rotate_right(a,22); uint32_t maj=(a&bb)^(a&cc)^(bb&cc); t2=s0+maj; h=g;g=f;f=e;e=d+t1;d=cc;cc=bb;bb=a;a=t1+t2; }
    c->state[0]+=a;c->state[1]+=bb;c->state[2]+=cc;c->state[3]+=d;c->state[4]+=e;c->state[5]+=f;c->state[6]+=g;c->state[7]+=h;
    memset(w,0,sizeof(w)); j=0U; (void)j;
}

static void sha256_init(struct sha256_context *c)
{
    static const uint32_t s[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    memcpy(c->state,s,sizeof(s)); c->total=0U;c->used=0U;memset(c->block,0,sizeof(c->block));
}
static void sha256_update(struct sha256_context *c,const uint8_t *p,size_t n)
{
    while(n){size_t room=64U-c->used,amount=n<room?n:room;memcpy(c->block+c->used,p,amount);c->used+=amount;c->total+=amount;p+=amount;n-=amount;if(c->used==64U){sha256_transform(c,c->block);c->used=0U;}}
}
static void sha256_final(struct sha256_context *c,uint8_t out[32])
{
    uint64_t bits=c->total*8U;size_t i;c->block[c->used++]=0x80U;if(c->used>56U){memset(c->block+c->used,0,64U-c->used);sha256_transform(c,c->block);c->used=0U;}memset(c->block+c->used,0,56U-c->used);for(i=0;i<8U;++i)c->block[63U-i]=(uint8_t)(bits>>(i*8U));sha256_transform(c,c->block);for(i=0;i<8U;++i){out[i*4U]=(uint8_t)(c->state[i]>>24);out[i*4U+1]=(uint8_t)(c->state[i]>>16);out[i*4U+2]=(uint8_t)(c->state[i]>>8);out[i*4U+3]=(uint8_t)c->state[i];}memset(c,0,sizeof(*c));
}
static void sha256_bytes(const void *p,size_t n,uint8_t out[32]){struct sha256_context c;sha256_init(&c);sha256_update(&c,p,n);sha256_final(&c,out);}
static void hmac_sha256(const uint8_t key[32],const uint8_t *p,size_t n,uint8_t out[32])
{
    uint8_t inner_key[64],outer_key[64],inner[32];struct sha256_context c;size_t i;
    memset(inner_key,0x36,sizeof(inner_key));memset(outer_key,0x5c,sizeof(outer_key));for(i=0;i<32U;++i){inner_key[i]^=key[i];outer_key[i]^=key[i];}
    sha256_init(&c);sha256_update(&c,inner_key,sizeof(inner_key));sha256_update(&c,p,n);sha256_final(&c,inner);
    sha256_init(&c);sha256_update(&c,outer_key,sizeof(outer_key));sha256_update(&c,inner,sizeof(inner));sha256_final(&c,out);
    memset(inner_key,0,sizeof(inner_key));memset(outer_key,0,sizeof(outer_key));memset(inner,0,sizeof(inner));
}

static void store_u16(uint8_t *p,uint16_t v){p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static void store_u32(uint8_t *p,uint32_t v){p[0]=(uint8_t)(v>>24);p[1]=(uint8_t)(v>>16);p[2]=(uint8_t)(v>>8);p[3]=(uint8_t)v;}
static void store_u64(uint8_t *p,uint64_t v){size_t i;for(i=0;i<8U;++i)p[7U-i]=(uint8_t)(v>>(i*8U));}
static uint16_t load_u16(const uint8_t *p){return (uint16_t)(((uint16_t)p[0]<<8)|p[1]);}
static uint32_t load_u32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static uint64_t load_u64(const uint8_t *p){uint64_t v=0;size_t i;for(i=0;i<8U;++i)v=(v<<8)|p[i];return v;}
static int nonzero(const uint8_t *p,size_t n){uint8_t v=0;size_t i;for(i=0;i<n;++i)v|=p[i];return v!=0U;}
static int secure_equal(const uint8_t *a,const uint8_t *b,size_t n){uint8_t v=0;size_t i;for(i=0;i<n;++i)v|=(uint8_t)(a[i]^b[i]);return v==0U;}

static int random_bytes(uint8_t *p,size_t n)
{
#if defined(__APPLE__)
    arc4random_buf(p,n); return 0;
#else
    int fd=open("/dev/urandom",O_RDONLY|O_CLOEXEC);size_t off=0;if(fd<0)return -1;while(off<n){ssize_t got=read(fd,p+off,n-off);if(got<=0){int e=errno;close(fd);errno=e==0?EIO:e;return -1;}off+=(size_t)got;}close(fd);return 0;
#endif
}

static void observed_times(const struct stat *s,struct timespec *m,struct timespec *c)
{
#if defined(__APPLE__)
    *m=s->st_mtimespec;*c=s->st_ctimespec;
#else
    *m=s->st_mtim;*c=s->st_ctim;
#endif
}
static int identity_fd(int fd,struct retained_identity *out)
{
    struct stat s;if(fd<0||out==NULL||fstat(fd,&s)!=0)return -1;out->device=s.st_dev;out->inode=s.st_ino;out->mode=s.st_mode;out->uid=s.st_uid;out->gid=s.st_gid;out->links=s.st_nlink;out->size=s.st_size;
#if defined(__APPLE__)
    out->generation=s.st_gen;
#else
    out->generation=0U;
#endif
    observed_times(&s,&out->mtime,&out->ctime);return 0;
}
static int same_identity(const struct retained_identity *a,const struct retained_identity *b)
 {return a->device==b->device&&a->inode==b->inode&&a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid&&a->links==b->links&&a->size==b->size&&a->generation==b->generation&&a->mtime.tv_sec==b->mtime.tv_sec&&a->mtime.tv_nsec==b->mtime.tv_nsec&&a->ctime.tv_sec==b->ctime.tv_sec&&a->ctime.tv_nsec==b->ctime.tv_nsec;}
static int same_vnode(const struct retained_identity *a,const struct retained_identity *b)
{return a->device==b->device&&a->inode==b->inode&&a->uid==b->uid&&a->gid==b->gid&&a->links==b->links;}
static int duplicate_fd(int fd){int v=fcntl(fd,F_DUPFD_CLOEXEC,3);return v;}
static int access_mode(int fd){int f=fcntl(fd,F_GETFL);return f<0?-1:(f&O_ACCMODE);}

static int hash_fd(int fd,uint64_t size,uint8_t out[32])
{
    struct sha256_context c;uint8_t b[65536];uint64_t off=0;sha256_init(&c);
    while(off<size){size_t want=(size-off)<sizeof(b)?(size_t)(size-off):sizeof(b);ssize_t got=pread(fd,b,want,(off_t)off);if(got<=0){memset(&c,0,sizeof(c));errno=EIO;return -1;}sha256_update(&c,b,(size_t)got);off+=(uint64_t)got;}
    sha256_final(&c,out);memset(b,0,sizeof(b));return 0;
}

static int ascii_field_exact(const char *p,size_t n)
{
    size_t i;int ended=0;if(n==0U)return 0;for(i=0;i<n;++i){unsigned char b=(unsigned char)p[i];if(ended){if(b!=0U)return 0;}else if(b==0U)ended=1;else if(b<0x21U||b>0x7eU)return 0;}return ended&&p[0]!='\0';
}
static int ascii_field_optional(const char *p,size_t n)
{
    size_t i;int ended=0;if(n==0U)return 0;for(i=0;i<n;++i){unsigned char b=(unsigned char)p[i];if(ended){if(b!=0U)return 0;}else if(b==0U)ended=1;else if(b<0x21U||b>0x7eU)return 0;}return ended;
}

int plamen_native_operation4_producer_footer_decode_exact_v1(
    const uint8_t bytes[PLAMEN_NATIVE_OPERATION4_PRODUCER_FOOTER_V1_SIZE],
    struct plamen_native_operation4_producer_footer_v1 *f)
{
    uint8_t digest[32];
    if(bytes==NULL||f==NULL||memcmp(bytes,producer_magic,8U)!=0
        ||load_u16(bytes+8U)!=1U||load_u16(bytes+10U)!=512U
        ||load_u16(bytes+12U)>=PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
        ||load_u16(bytes+14U)<PLAMEN_NATIVE_OPERATION4_STATIC_PAYLOAD_V1
        ||load_u16(bytes+14U)>PLAMEN_NATIVE_OPERATION4_FROZEN_SOURCE_PROJECTION_V1
        ||load_u16(bytes+16U)<PLAMEN_NATIVE_OPERATION4_DEBIAN_RECEIPT_V1
        ||load_u16(bytes+16U)>PLAMEN_NATIVE_OPERATION4_AMD64_COMPAT_RECEIPT_V1
        ||load_u16(bytes+18U)!=0U||load_u64(bytes+20U)==0U
        ||load_u64(bytes+28U)==0U||load_u64(bytes+36U)==0U
        ||load_u64(bytes+36U)>PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX-512U
        ||!nonzero(bytes+44U,128U)
        ||!ascii_field_exact((const char *)(bytes+172U),96U)
        ||!ascii_field_optional((const char *)(bytes+268U),128U)
        ||nonzero(bytes+396U,84U)) {errno=EINVAL;return -1;}
    sha256_bytes(bytes,480U,digest);
    if(!secure_equal(digest,bytes+480U,32U)){memset(digest,0,sizeof(digest));errno=EINVAL;return -1;}
    memset(f,0,sizeof(*f));f->role=load_u16(bytes+12U);f->identity_mode=load_u16(bytes+14U);f->receipt_validator=load_u16(bytes+16U);f->payload_size=load_u64(bytes+20U);f->source_manifest_size=load_u64(bytes+28U);f->semantic_receipt_size=load_u64(bytes+36U);memcpy(f->policy_sha256,bytes+44U,32U);memcpy(f->payload_sha256,bytes+76U,32U);memcpy(f->source_manifest_sha256,bytes+108U,32U);memcpy(f->semantic_receipt_sha256,bytes+140U,32U);memcpy(f->receipt_schema,bytes+172U,96U);memcpy(f->resolved_version,bytes+268U,128U);memcpy(f->footer_sha256,bytes+480U,32U);memset(digest,0,sizeof(digest));return 0;
}

static int expected_mode(size_t role)
{
    if(role==PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1||role==PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1)
        return PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1;
    if(role==PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1||role==PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1)
        return PLAMEN_NATIVE_OPERATION4_FROZEN_SOURCE_PROJECTION_V1;
    return PLAMEN_NATIVE_OPERATION4_STATIC_PAYLOAD_V1;
}

static int expected_validator(size_t role)
{
    switch(role){
    case PLAMEN_SOURCE_BOOTSTRAP_BASE_ROOTFS_V1:
    case PLAMEN_SOURCE_BOOTSTRAP_DEBIAN_PACKAGE_STATE_V1:return PLAMEN_NATIVE_OPERATION4_DEBIAN_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_GUEST_V1:
    case PLAMEN_SOURCE_BOOTSTRAP_PLAMEN_PACKAGE_V1:return PLAMEN_NATIVE_OPERATION4_PLAMEN_SOURCE_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_CPYTHON_V1:return PLAMEN_NATIVE_OPERATION4_CPYTHON_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1:
    case PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1:return PLAMEN_NATIVE_OPERATION4_BACKEND_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_FOUNDRY_V1:return PLAMEN_NATIVE_OPERATION4_FOUNDRY_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1:return PLAMEN_NATIVE_OPERATION4_MEDUSA_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_SOLC_AMD64_V1:return PLAMEN_NATIVE_OPERATION4_SOLC_RECEIPT_V1;
    case PLAMEN_SOURCE_BOOTSTRAP_AMD64_COMPAT_V1:return PLAMEN_NATIVE_OPERATION4_AMD64_COMPAT_RECEIPT_V1;
    default:return 0;
    }
}

static void policy_roster_hash(const struct plamen_native_operation4_fixed_policy_v1 *p,uint8_t out[32])
{
    struct sha256_context c;uint8_t scalar[32];size_t i,sz;
    sha256_init(&c);sha256_update(&c,(const uint8_t *)policy_roster_domain,sizeof(policy_roster_domain));
    memset(scalar,0,sizeof(scalar));store_u32(scalar,p->version);store_u32(scalar+4U,p->role_count);sha256_update(&c,scalar,8U);
    for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i){const struct plamen_native_operation4_policy_row_v1 *r=&p->rows[i];memset(scalar,0,sizeof(scalar));store_u16(scalar,r->role);store_u16(scalar+2U,r->identity_mode);store_u16(scalar+4U,r->receipt_validator);store_u16(scalar+6U,r->reserved);store_u64(scalar+8U,r->payload_size);store_u64(scalar+16U,r->source_manifest_size);store_u64(scalar+24U,r->semantic_receipt_size);sha256_update(&c,scalar,sizeof(scalar));sha256_update(&c,r->payload_sha256,32U);sha256_update(&c,r->source_manifest_sha256,32U);sha256_update(&c,r->semantic_receipt_sha256,32U);sha256_update(&c,r->policy_sha256,32U);sz=strnlen(r->receipt_schema,sizeof(r->receipt_schema));store_u16(scalar,(uint16_t)sz);sha256_update(&c,scalar,2U);sha256_update(&c,(const uint8_t *)r->receipt_schema,sz);}
    sha256_final(&c,out);memset(scalar,0,sizeof(scalar));
}

static int validate_policy(const struct plamen_native_operation4_fixed_policy_v1 *p)
{
    uint8_t digest[32];size_t i;
    if(p==NULL||p->version!=1U||p->role_count!=PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT)return 0;
    for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i){const struct plamen_native_operation4_policy_row_v1 *r=&p->rows[i];int mode=expected_mode(i);if(r->role!=i||r->reserved!=0U||r->identity_mode!=mode||r->receipt_validator!=expected_validator(i)||!nonzero(r->policy_sha256,32U)||!ascii_field_exact(r->receipt_schema,sizeof(r->receipt_schema)))return 0;if(mode==PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1){if(r->payload_size!=0U||r->source_manifest_size!=0U||r->semantic_receipt_size!=0U||nonzero(r->payload_sha256,32U)||nonzero(r->source_manifest_sha256,32U)||nonzero(r->semantic_receipt_sha256,32U))return 0;}else if(r->payload_size==0U||r->source_manifest_size==0U||r->semantic_receipt_size==0U||!nonzero(r->payload_sha256,32U)||!nonzero(r->source_manifest_sha256,32U)||!nonzero(r->semantic_receipt_sha256,32U))return 0;}
    policy_roster_hash(p,digest);i=secure_equal(digest,p->roster_sha256,32U);memset(digest,0,sizeof(digest));return (int)i;
}

#if defined(PLAMEN_NATIVE_OPERATION4_TESTING)
int plamen_native_operation4_policy_finalize_for_testing_v1(
    struct plamen_native_operation4_fixed_policy_v1 *p)
{
    if (p == NULL) { errno = EINVAL; return -1; }
    policy_roster_hash(p, p->roster_sha256);
    if (!validate_policy(p)) { errno = EINVAL; return -1; }
    return 0;
}
#endif

static int regular_readonly(int fd,uid_t owner,struct retained_identity *id)
{
    if(identity_fd(fd,id)!=0||!S_ISREG(id->mode)||id->uid!=owner||id->links!=1||id->size<=0||access_mode(fd)!=O_RDONLY||(fcntl(fd,F_GETFD)&FD_CLOEXEC)==0){errno=EINVAL;return -1;}return 0;
}
static int directory_readonly(int fd,uid_t owner,struct retained_identity *id)
{
    if(identity_fd(fd,id)!=0||!S_ISDIR(id->mode)||id->uid!=owner||access_mode(fd)!=O_RDONLY||(fcntl(fd,F_GETFD)&FD_CLOEXEC)==0){errno=EINVAL;return -1;}return 0;
}
static int empty_pair(int writer,int reader,uid_t owner,struct retained_identity *id)
{
    struct retained_identity a,b;if(identity_fd(writer,&a)!=0||identity_fd(reader,&b)!=0||!same_identity(&a,&b)||!S_ISREG(a.mode)||a.uid!=owner||a.size!=0||a.links!=0||access_mode(writer)!=O_RDWR||access_mode(reader)!=O_RDONLY||(fcntl(writer,F_GETFD)&FD_CLOEXEC)==0||(fcntl(reader,F_GETFD)&FD_CLOEXEC)==0){errno=EINVAL;return -1;}*id=a;return 0;
}

/*
 * Count every same-UID vnode descriptor, not merely this process's table.
 * Private stores are already unlinked, so after a complete census no later
 * pathname open can introduce an alias.  A malformed/incomplete census fails
 * closed; descriptors which disappeared while being inspected are harmless.
 */
static int private_store_aliases_exact(int fd,uid_t owner,unsigned total_expected,unsigned writable_expected)
{
#if defined(__APPLE__)
    struct stat target,before_after;pid_t *pids=NULL;int pid_bytes,listed;
    unsigned total=0U,writable=0U;size_t pi;
    if(fstat(fd,&target)!=0||target.st_uid!=owner||target.st_nlink!=0){errno=EINVAL;return -1;}
    pid_bytes=proc_listpids(PROC_UID_ONLY,(uint32_t)owner,NULL,0);
    if(pid_bytes<=0){errno=EACCES;return -1;}
    pid_bytes+=(int)(64U*sizeof(pid_t));pids=calloc(1U,(size_t)pid_bytes);
    if(pids==NULL)return -1;
    listed=proc_listpids(PROC_UID_ONLY,(uint32_t)owner,pids,pid_bytes);
    if(listed<=0||listed>=pid_bytes||(size_t)listed%sizeof(pid_t)!=0U){free(pids);errno=EACCES;return -1;}
    for(pi=0U;pi<(size_t)listed/sizeof(pid_t);++pi){
        struct proc_bsdinfo bsd;struct proc_fdinfo *fds=NULL;int fd_bytes,fd_listed;size_t fi;
        if(pids[pi]<=0)continue;
        memset(&bsd,0,sizeof(bsd));
        if(proc_pidinfo(pids[pi],PROC_PIDTBSDINFO,0,&bsd,(int)sizeof(bsd))!=(int)sizeof(bsd))continue;
        if(bsd.pbi_uid!=owner)continue;
        fd_bytes=proc_pidinfo(pids[pi],PROC_PIDLISTFDS,0,NULL,0);
        if(fd_bytes<=0){if(bsd.pbi_nfiles!=0U){free(pids);errno=EACCES;return -1;}continue;}
        if(fd_bytes>INT_MAX-(int)(32U*sizeof(struct proc_fdinfo))){free(pids);errno=EOVERFLOW;return -1;}
        fd_bytes+=(int)(32U*sizeof(struct proc_fdinfo));fds=calloc(1U,(size_t)fd_bytes);
        if(fds==NULL){free(pids);return -1;}
        fd_listed=proc_pidinfo(pids[pi],PROC_PIDLISTFDS,0,fds,fd_bytes);
        if(fd_listed<0||fd_listed>=fd_bytes||(size_t)fd_listed%sizeof(*fds)!=0U){free(fds);free(pids);errno=EACCES;return -1;}
        for(fi=0U;fi<(size_t)fd_listed/sizeof(*fds);++fi){
            struct vnode_fdinfowithpath vnode;int amount;
            if(fds[fi].proc_fdtype!=PROX_FDTYPE_VNODE)continue;
            memset(&vnode,0,sizeof(vnode));
            amount=proc_pidfdinfo(pids[pi],fds[fi].proc_fd,
                PROC_PIDFDVNODEPATHINFO,&vnode,(int)sizeof(vnode));
            if(amount!=(int)sizeof(vnode))continue;
            if((dev_t)vnode.pvip.vip_vi.vi_stat.vst_dev==target.st_dev
                    &&(ino_t)vnode.pvip.vip_vi.vi_stat.vst_ino==target.st_ino){
                ++total;
                if((vnode.pfi.fi_openflags&FWRITE)!=0U)++writable;
            }
        }
        free(fds);
    }
    free(pids);
    if(fstat(fd,&before_after)!=0||before_after.st_dev!=target.st_dev
            ||before_after.st_ino!=target.st_ino||before_after.st_nlink!=0){errno=ESTALE;return -1;}
    if(total!=total_expected||writable!=writable_expected){
#if defined(PLAMEN_NATIVE_OPERATION4_TESTING)
        fprintf(stderr,"private-store aliases total=%u/%u writable=%u/%u\n",total,total_expected,writable,writable_expected);
#endif
        errno=EBUSY;return -1;
    }
    return 0;
#else
    struct stat target,candidate;int limit,current;unsigned total=0U,writable=0U;
    if(fstat(fd,&target)!=0||target.st_uid!=owner||target.st_nlink!=0||(limit=getdtablesize())<=0)return -1;
    for(current=0;current<limit;++current){int flags;if(fstat(current,&candidate)!=0||candidate.st_dev!=target.st_dev||candidate.st_ino!=target.st_ino)continue;flags=fcntl(current,F_GETFL);if(flags<0)continue;++total;if((flags&O_ACCMODE)!=O_RDONLY)++writable;}
    return total==total_expected&&writable==writable_expected?0:(errno=EBUSY,-1);
#endif
}

static int path_from_fd(int fd,char *out,size_t capacity)
{
#if defined(__APPLE__)
    if(fcntl(fd,F_GETPATH,out)!=0)return -1;if(strnlen(out,capacity)>=capacity){errno=ENAMETOOLONG;return -1;}return 0;
#else
    char link[64];ssize_t n;int written=snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);if(written<=0||(size_t)written>=sizeof(link)){errno=EINVAL;return -1;}n=readlink(link,out,capacity-1U);if(n<=0||(size_t)n>=capacity-1U){errno=ENAMETOOLONG;return -1;}out[n]='\0';return 0;
#endif
}
static int fixed_member_path(int root_fd,int member_fd,const char *relative)
{
    char root[PATH_MAX],member[PATH_MAX],expected[PATH_MAX];int n;if(path_from_fd(root_fd,root,sizeof(root))!=0||path_from_fd(member_fd,member,sizeof(member))!=0)return 0;n=snprintf(expected,sizeof(expected),"%s/%s",root,relative);return n>0&&(size_t)n<sizeof(expected)&&strcmp(expected,member)==0;
}
static int self_executable_hash(uid_t owner,uint8_t out[32])
{
    char path[PATH_MAX];int fd=-1;struct retained_identity id;uint32_t sz=(uint32_t)sizeof(path);
#if defined(__APPLE__)
    if(_NSGetExecutablePath(path,&sz)!=0){errno=ENAMETOOLONG;return -1;}
#else
    ssize_t n=readlink("/proc/self/exe",path,sizeof(path)-1U);if(n<=0||(size_t)n>=sizeof(path)-1U){errno=EINVAL;return -1;}path[n]='\0';
#endif
    fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;if(regular_readonly(fd,owner,&id)!=0||hash_fd(fd,(uint64_t)id.size,out)!=0){int e=errno;close(fd);errno=e;return -1;}close(fd);return 0;
}

static void context_close(struct plamen_native_operation4_context_v1 *c)
{
    size_t i;
    if(c->runtime_root_fd>=0)close(c->runtime_root_fd);
    if(c->python_fd>=0)close(c->python_fd);
    if(c->transform_fd>=0)close(c->transform_fd);
    for(i=0;i<4U;++i)if(c->transform_dependency_fds[i]>=0)close(c->transform_dependency_fds[i]);
    if(c->install_verifier_public_key_fd>=0)close(c->install_verifier_public_key_fd);
    for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i)if(c->producer_receipt_fds[i]>=0)close(c->producer_receipt_fds[i]);
    if(c->grouped_writer_fd>=0)close(c->grouped_writer_fd);
    if(c->grouped_reader_fd>=0)close(c->grouped_reader_fd);
    if(c->terminal_writer_fd>=0)close(c->terminal_writer_fd);
    if(c->terminal_reader_fd>=0)close(c->terminal_reader_fd);
    memset(c->terminal_mac_key,0,sizeof(c->terminal_mac_key));
}
void plamen_native_operation4_context_dispose_v1(struct plamen_native_operation4_context_v1 *c){if(c!=NULL){context_close(c);memset(c,0,sizeof(*c));free(c);}}

static int context_create(uid_t owner,int root,int python,int transform,int verifier_key,int gw,int gr,int tw,int tr,const struct plamen_native_operation4_fixed_policy_v1 *policy,int enforce_paths,struct plamen_native_operation4_context_v1 **out)
{
    struct plamen_native_operation4_context_v1 *c=NULL;size_t i;char relative[PATH_MAX];struct retained_identity dependency;struct sha256_context closure_hash;uint8_t source_hash[32],scalar[16];int amount;
    if(out==NULL||*out!=NULL||owner!=getuid()||!validate_policy(policy)){errno=EINVAL;return -1;}
    c=calloc(1U,sizeof(*c));if(c==NULL)return -1;c->owner_uid=owner;c->runtime_root_fd=c->python_fd=c->transform_fd=c->install_verifier_public_key_fd=c->grouped_writer_fd=c->grouped_reader_fd=c->terminal_writer_fd=c->terminal_reader_fd=-1;for(i=0;i<4U;++i)c->transform_dependency_fds[i]=-1;for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i)c->producer_receipt_fds[i]=-1;c->testing=!enforce_paths;
    if(directory_readonly(root,owner,&c->runtime_root)!=0||regular_readonly(python,owner,&c->python)!=0||regular_readonly(transform,owner,&c->transform)!=0||regular_readonly(verifier_key,owner,&c->install_verifier_public_key)!=0||c->install_verifier_public_key.size!=32||(enforce_paths&&(!fixed_member_path(root,python,"bin/python3.12")||!fixed_member_path(root,transform,"lib/plamen/runtime/scripts/plamen_transform_bundle.py"))))goto fail;
    if(empty_pair(gw,gr,owner,&c->grouped)!=0||empty_pair(tw,tr,owner,&c->terminal)!=0||same_vnode(&c->grouped,&c->terminal)){errno=EINVAL;goto fail;}
    c->runtime_root_fd=duplicate_fd(root);c->python_fd=duplicate_fd(python);c->transform_fd=duplicate_fd(transform);c->install_verifier_public_key_fd=duplicate_fd(verifier_key);c->grouped_writer_fd=duplicate_fd(gw);c->grouped_reader_fd=duplicate_fd(gr);c->terminal_writer_fd=duplicate_fd(tw);c->terminal_reader_fd=duplicate_fd(tr);if(c->runtime_root_fd<0||c->python_fd<0||c->transform_fd<0||c->install_verifier_public_key_fd<0||c->grouped_writer_fd<0||c->grouped_reader_fd<0||c->terminal_writer_fd<0||c->terminal_reader_fd<0)goto fail;
    c->policy=*policy;policy_roster_hash(policy,c->policy_roster_sha256);if(hash_fd(c->python_fd,(uint64_t)c->python.size,c->python_sha256)!=0||hash_fd(c->transform_fd,(uint64_t)c->transform.size,c->transform_sha256)!=0||self_executable_hash(owner,c->executable_sha256)!=0||random_bytes(c->terminal_mac_key,32U)!=0)goto fail;
    sha256_init(&closure_hash);sha256_update(&closure_hash,(const uint8_t *)transform_closure_domain,sizeof(transform_closure_domain));
    sha256_update(&closure_hash,(const uint8_t *)transform_closure_names[0],strlen(transform_closure_names[0]));memset(scalar,0,sizeof(scalar));store_u64(scalar,(uint64_t)c->transform.size);sha256_update(&closure_hash,scalar,8U);sha256_update(&closure_hash,c->transform_sha256,32U);
    for(i=0;i<4U;++i){amount=snprintf(relative,sizeof(relative),enforce_paths?"lib/plamen/runtime/scripts/%s":"scripts/%s",transform_closure_relatives[i+1U]);if(amount<=0||(size_t)amount>=sizeof(relative))goto fail;c->transform_dependency_fds[i]=openat(c->runtime_root_fd,relative,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(c->transform_dependency_fds[i]<0||regular_readonly(c->transform_dependency_fds[i],owner,&dependency)!=0||hash_fd(c->transform_dependency_fds[i],(uint64_t)dependency.size,source_hash)!=0)goto fail;c->transform_dependencies[i]=dependency;sha256_update(&closure_hash,(const uint8_t *)transform_closure_names[i+1U],strlen(transform_closure_names[i+1U]));memset(scalar,0,sizeof(scalar));store_u64(scalar,(uint64_t)dependency.size);sha256_update(&closure_hash,scalar,8U);sha256_update(&closure_hash,source_hash,32U);}
    sha256_final(&closure_hash,c->transform_closure_sha256);memset(source_hash,0,sizeof(source_hash));memset(scalar,0,sizeof(scalar));
    if(hash_fd(c->install_verifier_public_key_fd,32U,c->install_verifier_public_key_sha256)!=0)goto fail;
    *out=c;return 0;
fail:{int e=errno;plamen_native_operation4_context_dispose_v1(c);errno=e==0?EINVAL:e;return -1;}
}

int plamen_native_operation4_context_create_fixed_v1(uid_t owner,int root,int python,int transform,int verifier_key,int gw,int gr,int tw,int tr,struct plamen_native_operation4_context_v1 **out)
{return context_create(owner,root,python,transform,verifier_key,gw,gr,tw,tr,&plamen_native_operation4_generated_policy_v1,1,out);}
#if defined(PLAMEN_NATIVE_OPERATION4_TESTING)
int plamen_native_operation4_context_create_for_testing_v1(uid_t owner,int root,int python,int transform,int verifier_key,int gw,int gr,int tw,int tr,const struct plamen_native_operation4_fixed_policy_v1 *policy,struct plamen_native_operation4_context_v1 **out)
{return context_create(owner,root,python,transform,verifier_key,gw,gr,tw,tr,policy,0,out);}
#endif

int plamen_native_operation4_policy_fill_fixed_v1(const struct plamen_native_operation4_context_v1 *c,struct plamen_source_bootstrap_input_v1 inputs[PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT])
{
    size_t i;if(c==NULL||inputs==NULL||!validate_policy(&c->policy)){errno=EINVAL;return -1;}for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i){const struct plamen_native_operation4_policy_row_v1 *r=&c->policy.rows[i];inputs[i].identity_mode=r->identity_mode;inputs[i].reserved=0U;memcpy(inputs[i].policy_sha256,r->policy_sha256,32U);if(r->identity_mode==PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1){inputs[i].expected_payload_size=0U;inputs[i].expected_source_manifest_size=0U;memset(inputs[i].expected_payload_sha256,0,32U);memset(inputs[i].expected_source_manifest_sha256,0,32U);}else{inputs[i].expected_payload_size=r->payload_size;inputs[i].expected_source_manifest_size=r->source_manifest_size;memcpy(inputs[i].expected_payload_sha256,r->payload_sha256,32U);memcpy(inputs[i].expected_source_manifest_sha256,r->source_manifest_sha256,32U);}inputs[i].expected_producer_receipt_size=0U;memset(inputs[i].expected_producer_receipt_sha256,0,32U);}return 0;
}

int plamen_native_operation4_executable_sha256_fixed_v1(const struct plamen_native_operation4_context_v1 *c,uint8_t out[32]){if(c==NULL||out==NULL||!nonzero(c->executable_sha256,32U)){errno=EINVAL;return -1;}memcpy(out,c->executable_sha256,32U);return 0;}
int plamen_native_operation4_authenticate_executable_fixed_v1(void *opaque,const uint8_t digest[32]){struct plamen_native_operation4_context_v1 *c=opaque;return c!=NULL&&digest!=NULL&&secure_equal(c->executable_sha256,digest,32U)?0:-1;}

static int canonical_semantic_receipt(int fd,uint64_t size,const char *schema)
{
    uint8_t *raw=NULL;char marker[160];size_t off=0,marker_size,i;int found=0;
    if(size<16U||size>PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX-512U||schema==NULL)return 0;
    raw=malloc((size_t)size);if(raw==NULL)return 0;while(off<(size_t)size){ssize_t n=pread(fd,raw+off,(size_t)size-off,(off_t)off);if(n<=0)goto done;off+=(size_t)n;}
    if(raw[0]!='{'||raw[size-1U]!='}'||memchr(raw,'\0',(size_t)size)!=NULL||memchr(raw,'\n',(size_t)size)!=NULL||memchr(raw,'\r',(size_t)size)!=NULL)goto done;
    for(i=0;i<(size_t)size;++i)if(raw[i]<0x20U||raw[i]>0x7eU)goto done;
    marker_size=(size_t)snprintf(marker,sizeof(marker),"\"schema\":\"%s\"",schema);if(marker_size==0U||marker_size>=sizeof(marker))goto done;
    for(i=0;i+marker_size<=(size_t)size;++i)if(memcmp(raw+i,marker,marker_size)==0){++found;i+=marker_size-1U;}
done:memset(raw,0,(size_t)size);free(raw);return found==1;
}

int plamen_native_operation4_authenticate_source_fixed_v1(void *opaque,uint16_t role,int receipt_fd,const struct plamen_source_bootstrap_input_v1 *expected,const struct plamen_source_bootstrap_fd_identity_v1 *payload,const struct plamen_source_bootstrap_fd_identity_v1 *producer,const struct plamen_source_bootstrap_fd_identity_v1 *manifest)
{
    struct plamen_native_operation4_context_v1 *c=opaque;const struct plamen_native_operation4_policy_row_v1 *policy;struct plamen_native_operation4_producer_footer_v1 footer;uint8_t raw_footer[512],digest[32];uint64_t semantic;ssize_t got;
    if(c==NULL||expected==NULL||payload==NULL||producer==NULL||manifest==NULL||role>=PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT||receipt_fd<0||c->producer_receipt_fds[role]>=0){errno=EINVAL;return -1;}policy=&c->policy.rows[role];
    if(expected->identity_mode!=policy->identity_mode||expected->reserved!=0U||!secure_equal(expected->policy_sha256,policy->policy_sha256,32U)||producer->size<512U||producer->size>PLAMEN_NATIVE_OPERATION4_PRODUCER_RECEIPT_MAX){errno=EINVAL;return -1;}
    got=pread(receipt_fd,raw_footer,sizeof(raw_footer),(off_t)(producer->size-512U));if(got!=(ssize_t)sizeof(raw_footer)||plamen_native_operation4_producer_footer_decode_exact_v1(raw_footer,&footer)!=0)return -1;semantic=producer->size-512U;
    if(footer.role!=role||footer.identity_mode!=policy->identity_mode||footer.receipt_validator!=policy->receipt_validator||footer.semantic_receipt_size!=semantic||footer.payload_size!=payload->size||footer.source_manifest_size!=manifest->size||!secure_equal(footer.policy_sha256,policy->policy_sha256,32U)||!secure_equal(footer.payload_sha256,payload->sha256,32U)||!secure_equal(footer.source_manifest_sha256,manifest->sha256,32U)||strcmp(footer.receipt_schema,policy->receipt_schema)!=0||hash_fd(receipt_fd,semantic,digest)!=0||!secure_equal(digest,footer.semantic_receipt_sha256,32U)||!canonical_semantic_receipt(receipt_fd,semantic,policy->receipt_schema)){memset(&footer,0,sizeof(footer));memset(digest,0,sizeof(digest));errno=EINVAL;return -1;}
    if(policy->identity_mode==PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1){if(role!=PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1&&role!=PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1){errno=EINVAL;return -1;}if(footer.resolved_version[0]=='\0'||policy->payload_size!=0U||policy->source_manifest_size!=0U||expected->expected_payload_size!=0U||expected->expected_source_manifest_size!=0U||nonzero(expected->expected_payload_sha256,32U)||nonzero(expected->expected_source_manifest_sha256,32U)){errno=EINVAL;return -1;}}
    else if(footer.resolved_version[0]!='\0'||footer.payload_size!=policy->payload_size||footer.source_manifest_size!=policy->source_manifest_size||footer.semantic_receipt_size!=policy->semantic_receipt_size||!secure_equal(footer.payload_sha256,policy->payload_sha256,32U)||!secure_equal(footer.source_manifest_sha256,policy->source_manifest_sha256,32U)||!secure_equal(footer.semantic_receipt_sha256,policy->semantic_receipt_sha256,32U)){errno=EINVAL;return -1;}
    c->producer_receipt_fds[role]=duplicate_fd(receipt_fd);if(c->producer_receipt_fds[role]<0||identity_fd(c->producer_receipt_fds[role],&c->producer_receipts[role])!=0){if(c->producer_receipt_fds[role]>=0){close(c->producer_receipt_fds[role]);c->producer_receipt_fds[role]=-1;}memset(&footer,0,sizeof(footer));memset(digest,0,sizeof(digest));return -1;}
    memset(&footer,0,sizeof(footer));memset(digest,0,sizeof(digest));return 0;
}

static int write_all_at(int fd,const uint8_t *p,size_t n,uint64_t offset)
{
    size_t done=0;while(done<n){ssize_t w=pwrite(fd,p+done,n-done,(off_t)(offset+done));if(w<=0){if(w==0)errno=EIO;return -1;}done+=(size_t)w;}return 0;
}
static int copy_fd_to(int source,uint64_t size,int destination,uint64_t offset,uint8_t digest[32])
{
    uint8_t block[65536];uint64_t done=0;struct sha256_context h;sha256_init(&h);while(done<size){size_t want=(size-done)<sizeof(block)?(size_t)(size-done):sizeof(block);ssize_t n=pread(source,block,want,(off_t)done);if(n<=0){errno=EIO;goto fail;}if(write_all_at(destination,block,(size_t)n,offset+done)!=0)goto fail;sha256_update(&h,block,(size_t)n);done+=(uint64_t)n;}sha256_final(&h,digest);memset(block,0,sizeof(block));return 0;fail:memset(&h,0,sizeof(h));memset(block,0,sizeof(block));return -1;
}

static int build_group(struct plamen_native_operation4_context_v1 *c,int composition,const int payloads[11],const int manifests[11],uint8_t group_sha[32])
{
    uint8_t header[256],roster[OP4_GROUP_ROW_COUNT*256U],row_digest[OP4_GROUP_ROW_COUNT][32];uint64_t sizes[OP4_GROUP_ROW_COUNT],offset,data_start,total=0;int fds[OP4_GROUP_ROW_COUNT];size_t i,name_size;struct retained_identity id;
    if(private_store_aliases_exact(c->grouped_writer_fd,c->owner_uid,2U,1U)!=0
            ||private_store_aliases_exact(c->terminal_writer_fd,c->owner_uid,2U,1U)!=0)return -1;
    fds[0]=composition;for(i=0;i<11U;++i){fds[1U+i*2U]=payloads[i];fds[2U+i*2U]=manifests[i];}
    for(i=0;i<OP4_GROUP_ROW_COUNT;++i){if(regular_readonly(fds[i],c->owner_uid,&id)!=0||id.size<0){errno=EINVAL;return -1;}sizes[i]=(uint64_t)id.size;if(sizes[i]>OP4_GROUP_MAX_BYTES-total){errno=EFBIG;return -1;}total+=sizes[i];if(hash_fd(fds[i],sizes[i],row_digest[i])!=0)return -1;}
    data_start=OP4_GROUP_HEADER_SIZE+sizeof(roster);offset=data_start;memset(roster,0,sizeof(roster));
    for(i=0;i<OP4_GROUP_ROW_COUNT;++i){uint8_t *row=roster+i*256U;name_size=strlen(group_paths[i]);store_u16(row,(uint16_t)name_size);store_u64(row+8U,sizes[i]);store_u64(row+16U,offset);memcpy(row+24U,row_digest[i],32U);memcpy(row+56U,group_paths[i],name_size);offset+=sizes[i];}
    memset(header,0,sizeof(header));memcpy(header,group_magic,8U);store_u16(header+8U,1U);store_u16(header+10U,256U);store_u32(header+12U,4U);store_u32(header+16U,OP4_GROUP_ROW_COUNT);store_u32(header+20U,256U);store_u64(header+24U,data_start);store_u64(header+32U,total);memcpy(header+40U,row_digest[0],32U);sha256_bytes(roster,sizeof(roster),header+72U);
    if(ftruncate(c->grouped_writer_fd,0)!=0||fchmod(c->grouped_writer_fd,0600)!=0||write_all_at(c->grouped_writer_fd,header,sizeof(header),0)!=0||write_all_at(c->grouped_writer_fd,roster,sizeof(roster),sizeof(header))!=0)return -1;offset=data_start;for(i=0;i<OP4_GROUP_ROW_COUNT;++i){uint8_t copied[32];if(copy_fd_to(fds[i],sizes[i],c->grouped_writer_fd,offset,copied)!=0||!secure_equal(copied,row_digest[i],32U)){memset(copied,0,sizeof(copied));errno=EIO;return -1;}memset(copied,0,sizeof(copied));offset+=sizes[i];}
    if(fsync(c->grouped_writer_fd)!=0||fchmod(c->grouped_writer_fd,0400)!=0)return -1;
    close(c->grouped_writer_fd);c->grouped_writer_fd=-1;
    if(identity_fd(c->grouped_reader_fd,&id)!=0||!same_vnode(&c->grouped,&id)||id.size!=(off_t)(data_start+total)||(id.mode&07777U)!=0400U||id.links!=0||access_mode(c->grouped_reader_fd)!=O_RDONLY||hash_fd(c->grouped_reader_fd,data_start+total,group_sha)!=0)return -1;
    memset(header,0,sizeof(header));memset(roster,0,sizeof(roster));memset(row_digest,0,sizeof(row_digest));return 0;
}

static int safe_path(const char *p)
{
    size_t i,n;if(p==NULL||(n=strlen(p))==0U||n>=PATH_MAX||p[0]!='/')return 0;for(i=0;i<n;++i){unsigned char b=(unsigned char)p[i];if(!((b>='A'&&b<='Z')||(b>='a'&&b<='z')||(b>='0'&&b<='9')||b=='/'||b=='_'||b=='-'||b=='.'||b=='+'||b=='@'||b==' '))return 0;}return strstr(p,"/../")==NULL&&strstr(p,"/./")==NULL;
}

#if defined(__APPLE__)
static int apply_no_network_sandbox(void)
{
    typedef int (*init_fn)(const char *,uint64_t,char **);typedef void (*free_fn)(char *);void *handle;init_fn init;free_fn release;const char *profile;char *error=NULL;int rc;
    handle=dlopen("/usr/lib/libsandbox.1.dylib",RTLD_NOW|RTLD_LOCAL);if(handle==NULL)return -1;
    init=(init_fn)dlsym(handle,"sandbox_init");release=(free_fn)dlsym(handle,"sandbox_free_error");profile=(const char *)dlsym(handle,"kSBXProfileNoNetwork");
    if(init==NULL||release==NULL||profile==NULL){dlclose(handle);return -1;}rc=init(profile,1U,&error);if(error!=NULL)release(error);if(rc!=0){dlclose(handle);return -1;}/* Keep the provider resident until exec. */return 0;
}

static int mapped_python_matches(pid_t child,const struct retained_identity *expected)
{
    struct proc_regionwithpathinfo region;uint64_t address=0U,next;int amount,matches=0;
    for(;;){
        memset(&region,0,sizeof(region));
        amount=proc_pidinfo(child,PROC_PIDREGIONPATHINFO,address,&region,(int)sizeof(region));
        if(amount<=0)break;
        if(amount!=(int)sizeof(region)||region.prp_prinfo.pri_size==0U){errno=EINVAL;return 0;}
        if(region.prp_prinfo.pri_offset==0U&&(region.prp_prinfo.pri_protection&VM_PROT_EXECUTE)!=0U){
            const struct vinfo_stat *v=&region.prp_vip.vip_vi.vi_stat;
            if((dev_t)v->vst_dev==expected->device&&(ino_t)v->vst_ino==expected->inode&&(v->vst_gen==0U||expected->generation==0U||v->vst_gen==expected->generation)&&(v->vst_size==0||((off_t)v->vst_size==expected->size)))++matches;
        }
        next=region.prp_prinfo.pri_address+region.prp_prinfo.pri_size;
        if(next<=address)break;
        address=next;
    }
    return matches==1;
}

static int spawn_attested_python(const char *python,char *const argv[],char *const environment[],const struct retained_identity *expected,int *status)
{
    posix_spawnattr_t attributes;sigset_t empty,defaults;pid_t child=-1,waited;short flags=POSIX_SPAWN_START_SUSPENDED|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK;int ready=0,rc=-1;
    if(status==NULL||expected==NULL){errno=EINVAL;return -1;}
    if(posix_spawnattr_init(&attributes)!=0)return -1;ready=1;sigemptyset(&empty);sigfillset(&defaults);sigdelset(&defaults,SIGKILL);sigdelset(&defaults,SIGSTOP);
    if(posix_spawnattr_setflags(&attributes,flags)!=0||posix_spawnattr_setsigmask(&attributes,&empty)!=0||posix_spawnattr_setsigdefault(&attributes,&defaults)!=0||posix_spawn(&child,python,NULL,&attributes,argv,environment)!=0)goto done;
    if(!mapped_python_matches(child,expected)||!mapped_python_matches(child,expected)){errno=ESTALE;goto done;}
    if(kill(child,SIGCONT)!=0)goto done;
    do{waited=waitpid(child,status,0);}while(waited<0&&errno==EINTR);
    if(waited!=child)goto done;
    child=-1;rc=0;
done:
    if(child>0){(void)kill(child,SIGKILL);while(waitpid(child,status,0)<0&&errno==EINTR){}}
    if(ready)posix_spawnattr_destroy(&attributes);
    return rc;
}
#else
static int apply_no_network_sandbox(void){errno=ENOTSUP;return -1;}
#endif

#if defined(PLAMEN_NATIVE_OPERATION4_TESTING) && defined(__APPLE__)
int plamen_native_operation4_attest_python_for_testing_v1(int python_fd,int expected_python_fd)
{
    struct retained_identity expected;char python[PATH_MAX];pid_t broker,waited;int status=0;
    if(identity_fd(expected_python_fd,&expected)!=0||!S_ISREG(expected.mode)||path_from_fd(python_fd,python,sizeof(python))!=0||!safe_path(python))return -2;
    broker=fork();if(broker<0)return -1;
    if(broker==0){char *argv[]={python,"-I","-S","-B","-c","pass",NULL};char *environment[]={"HOME=/nonexistent","LANG=C.UTF-8","LC_ALL=C.UTF-8","PATH=/usr/bin:/bin","PYTHONHASHSEED=0",NULL};int child_status=0;if(apply_no_network_sandbox()!=0||spawn_attested_python(python,argv,environment,&expected,&child_status)!=0)_exit(126);_exit(WIFEXITED(child_status)?WEXITSTATUS(child_status):127);}
    do{waited=waitpid(broker,&status,0);}while(waited<0&&errno==EINTR);
    if(waited!=broker||!WIFEXITED(status)||WEXITSTATUS(status)!=0){errno=ESTALE;return WIFEXITED(status)?-(int)WEXITSTATUS(status):-127;}return 0;
}
#elif defined(PLAMEN_NATIVE_OPERATION4_TESTING)
int plamen_native_operation4_attest_python_for_testing_v1(int python_fd,int expected_python_fd)
{(void)python_fd;(void)expected_python_fd;errno=ENOTSUP;return -1;}
#endif

static int duplicate_child_fds(const struct plamen_native_operation4_context_v1 *c,int outputs[5],int scratch[24])
{
    int sources[48],copies[48],targets[48];size_t i,count=0;
    sources[count]=c->runtime_root_fd;targets[count++]=OP4_CHILD_ROOT_FD;sources[count]=c->grouped_reader_fd;targets[count++]=OP4_CHILD_GROUP_FD;
    for(i=0;i<5U;++i){sources[count]=outputs[i];targets[count++]=OP4_CHILD_OUTPUT_FD+(int)i;}
    for(i=0;i<24U;++i){sources[count]=scratch[i];targets[count++]=OP4_CHILD_SCRATCH_FD+(int)i;}
    sources[count]=c->transform_fd;targets[count++]=OP4_CHILD_TRANSFORM_FD;
    for(i=0;i<4U;++i){sources[count]=c->transform_dependency_fds[i];targets[count++]=OP4_CHILD_NATIVE_TRANSFORM_FD+(int)i;}
    sources[count]=c->install_verifier_public_key_fd;targets[count++]=OP4_CHILD_VERIFIER_KEY_FD;
    for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i){if(c->producer_receipt_fds[i]<0){errno=EINVAL;goto fail;}sources[count]=c->producer_receipt_fds[i];targets[count++]=OP4_CHILD_PRODUCER_RECEIPT_FD+(int)i;}
    for(i=0;i<count;++i){copies[i]=fcntl(sources[i],F_DUPFD_CLOEXEC,64);if(copies[i]<0)goto fail;}
    for(i=0;i<count;++i)if(dup2(copies[i],targets[i])<0)goto fail;
    for(i=0;i<count;++i)close(copies[i]);
    for(i=51U;i<4096U;++i)close((int)i);
    return 0;
fail:while(i>0U)close(copies[--i]);return -1;
}

static int launch_transform(struct plamen_native_operation4_context_v1 *c,int outputs[5],int scratch[24],int *wait_status,uint64_t *duration_ns,int *population_zero)
{
    static const char code_production[] =
        "import os,sys,types\n"
        "for fd in range(3,51):os.set_inheritable(fd,False)\n"
        "data=b'';off=0\n"
        "while True:\n"
        " part=os.pread(38,1048576,off)\n"
        " if not part:break\n"
        " data+=part;off+=len(part)\n"
        "validator=types.ModuleType('native_operation4_acquisition_validation');validator.__file__='<retained:validator>'\n"
        "exec(compile(data,validator.__file__,'exec'),validator.__dict__)\n"
        "validator.validate_all(39,tuple(range(40,51)),4)\n"
        "names=('oci_retained_archive_transform','runtime_image_materializer','native_runtime_grouped_transform','plamen_transform_bundle')\n"
        "fds=(37,36,35,34)\n"
        "for name,fd in zip(names,fds):\n"
        " m=types.ModuleType(name);m.__file__='<retained:'+name+'>';sys.modules[name]=m\n"
        " data=b'';off=0\n"
        " while True:\n"
        "  part=os.pread(fd,1048576,off)\n"
        "  if not part:break\n"
        "  data+=part;off+=len(part)\n"
        " exec(compile(data,m.__file__,'exec'),m.__dict__)\n"
        "sys.modules['plamen_transform_bundle'].run(4,4,(5,6,7,8,9),tuple(range(10,34)))\n";
    static const char code_testing[] =
        "import os,sys,types\n"
        "for fd in range(3,51):os.set_inheritable(fd,False)\n"
        "data=b'';off=0\n"
        "while True:\n"
        " part=os.pread(38,1048576,off)\n"
        " if not part:break\n"
        " data+=part;off+=len(part)\n"
        "validator=types.ModuleType('native_operation4_acquisition_validation');validator.__file__='<retained:validator>'\n"
        "exec(compile(data,validator.__file__,'exec'),validator.__dict__)\n"
        "validator.validate_all(39,tuple(range(40,51)),4,_testing_skip_registry_signature=True)\n"
        "names=('oci_retained_archive_transform','runtime_image_materializer','native_runtime_grouped_transform','plamen_transform_bundle')\n"
        "fds=(37,36,35,34)\n"
        "for name,fd in zip(names,fds):\n"
        " m=types.ModuleType(name);m.__file__='<retained:'+name+'>';sys.modules[name]=m\n"
        " data=b'';off=0\n"
        " while True:\n"
        "  part=os.pread(fd,1048576,off)\n"
        "  if not part:break\n"
        "  data+=part;off+=len(part)\n"
        " exec(compile(data,m.__file__,'exec'),m.__dict__)\n"
        "sys.modules['plamen_transform_bundle'].run(4,4,(5,6,7,8,9),tuple(range(10,34)))\n";
    const char *code=c->testing?code_testing:code_production;
    char python[PATH_MAX],root[PATH_MAX];char *argv[7],*environment[6];struct timespec start,now,pause;pid_t child,waited;unsigned int elapsed=0;int status=0;
    if(path_from_fd(c->python_fd,python,sizeof(python))!=0||path_from_fd(c->runtime_root_fd,root,sizeof(root))!=0||!safe_path(python)||!safe_path(root)){errno=EINVAL;return -1;}
    argv[0]=python;argv[1]="-I";argv[2]="-S";argv[3]="-B";argv[4]="-c";argv[5]=(char *)code;argv[6]=NULL;
    environment[0]="HOME=/nonexistent";environment[1]="LANG=C.UTF-8";environment[2]="LC_ALL=C.UTF-8";environment[3]="PATH=/usr/bin:/bin";environment[4]="PYTHONHASHSEED=0";environment[5]=NULL;
    if(clock_gettime(CLOCK_MONOTONIC,&start)!=0)return -1;child=fork();if(child<0)return -1;
    if(child==0){int python_status=0;(void)setpgid(0,0);if(duplicate_child_fds(c,outputs,scratch)!=0||apply_no_network_sandbox()!=0)_exit(125);
#if defined(__APPLE__)
        if(spawn_attested_python(python,argv,environment,&c->python,&python_status)!=0)_exit(126);
        if(WIFEXITED(python_status))_exit(WEXITSTATUS(python_status));
        if(WIFSIGNALED(python_status))_exit(128+WTERMSIG(python_status));
#endif
        _exit(126);}
    (void)setpgid(child,child);pause.tv_sec=0;pause.tv_nsec=10000000L;
    for(;;){waited=waitpid(child,&status,WNOHANG);if(waited==child)break;if(waited<0){if(errno==EINTR)continue;return -1;}if(elapsed++>=OP4_CHILD_TIMEOUT_SECONDS*100U){(void)kill(-child,SIGKILL);while(waitpid(child,&status,0)<0&&errno==EINTR){}errno=ETIMEDOUT;break;}(void)nanosleep(&pause,NULL);}
    (void)kill(-child,SIGKILL);for(elapsed=0U;elapsed<100U;++elapsed){if(kill(-child,0)!=0&&errno==ESRCH)break;(void)nanosleep(&pause,NULL);}*population_zero=(kill(-child,0)!=0&&errno==ESRCH);
    if(clock_gettime(CLOCK_MONOTONIC,&now)!=0)return -1;*duration_ns=(uint64_t)(now.tv_sec-start.tv_sec)*1000000000ULL+(uint64_t)(now.tv_nsec-start.tv_nsec);*wait_status=status;return 0;
}

static void identity_commitment(const struct retained_identity *id,const uint8_t digest[32],uint8_t out[64])
{
    memset(out,0,64U);store_u64(out,(uint64_t)id->device);store_u64(out+8U,(uint64_t)id->inode);store_u32(out+16U,(uint32_t)id->mode);store_u32(out+20U,(uint32_t)id->uid);store_u64(out+24U,(uint64_t)id->size);memcpy(out+32U,digest,32U);
}

static void terminal_mac(const struct plamen_native_operation4_context_v1 *c,
    const uint8_t raw[PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE],
    uint8_t out[32])
{
    uint8_t domain_key[32], commitment[32];
    struct sha256_context input;
    hmac_sha256(c->terminal_mac_key, (const uint8_t *)terminal_mac_domain,
        sizeof(terminal_mac_domain), domain_key);
    sha256_init(&input);
    sha256_update(&input, domain_key, sizeof(domain_key));
    sha256_update(&input, raw, OP4_TERMINAL_MAC_OFFSET);
    sha256_final(&input, commitment);
    hmac_sha256(c->terminal_mac_key, commitment, sizeof(commitment), out);
    memset(domain_key, 0, sizeof(domain_key));
    memset(commitment, 0, sizeof(commitment));
}

static int verify_terminal_readback(
    const struct plamen_native_operation4_context_v1 *c,
    const uint8_t group_sha[32], int expected_status, int population_zero)
{
    uint8_t raw[PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE], mac[32];
    size_t offset = 0U;
    int expected_exit = WIFEXITED(expected_status)
        ? WEXITSTATUS(expected_status) : 255;
    int expected_signal = WIFSIGNALED(expected_status)
        ? WTERMSIG(expected_status) : 0;
    while (offset < sizeof(raw)) {
        ssize_t amount = pread(c->terminal_reader_fd, raw + offset,
            sizeof(raw) - offset, (off_t)offset);
        if (amount <= 0) { errno = EIO; goto fail; }
        offset += (size_t)amount;
    }
    terminal_mac(c, raw, mac);
    { uint8_t body[32]; sha256_bytes(raw, 472U, body);
    if (memcmp(raw, terminal_magic, sizeof(terminal_magic)) != 0
            || load_u16(raw + 8U) != 1U
            || load_u16(raw + 10U)
                != PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE
            || load_u16(raw + 12U) != 11U
            || load_u16(raw + 14U) != 5U
            || load_u16(raw + 16U) != 24U
            || load_u16(raw + 18U) != (uint16_t)(
                WIFEXITED(expected_status) && expected_exit == 0
                    && population_zero ? 7U : population_zero ? 4U : 0U)
            || (int)load_u32(raw + 20U) != expected_exit
            || (int)load_u32(raw + 24U) != expected_signal
            || !secure_equal(raw + 40U, group_sha, 32U)
            || !secure_equal(raw + 72U, c->policy_roster_sha256, 32U)
            || !secure_equal(raw + 104U, c->executable_sha256, 32U)
            || !secure_equal(raw + 136U, c->python_sha256, 32U)
            || !secure_equal(raw + 168U, c->transform_sha256, 32U)
            || !secure_equal(raw + 472U, body, 32U)
            || !secure_equal(raw + 504U, c->transform_closure_sha256, 32U)
            || !secure_equal(raw + 536U, c->install_verifier_public_key_sha256, 32U)
            || !secure_equal(raw + OP4_TERMINAL_MAC_OFFSET, mac, 32U)) {
        memset(body, 0, sizeof(body));
        errno = EINVAL;
        goto fail;
    }
    memset(body, 0, sizeof(body)); }
    memset(raw, 0, sizeof(raw)); memset(mac, 0, sizeof(mac));
    return 0;
fail:
    memset(raw, 0, sizeof(raw)); memset(mac, 0, sizeof(mac));
    return -1;
}

int plamen_native_operation4_rejoin_terminal_outputs_fixed_v1(void *opaque,
    int terminal_fd,
    const struct plamen_source_bootstrap_fd_identity_v1 outputs[
        PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT])
{
    struct plamen_native_operation4_context_v1 *c=opaque;
    uint8_t raw[PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE],mac[32],body[32];
    struct retained_identity terminal;size_t offset=0U,i;int result=-1;
    if(c==NULL||outputs==NULL||terminal_fd<3||!c->consumed
            ||identity_fd(terminal_fd,&terminal)!=0||!S_ISREG(terminal.mode)
            ||terminal.uid!=c->owner_uid||terminal.links!=0
            ||terminal.size!=(off_t)sizeof(raw)||(terminal.mode&07777U)!=0400U
            ||access_mode(terminal_fd)!=O_RDONLY
            ||(fcntl(terminal_fd,F_GETFD)&FD_CLOEXEC)==0){errno=EINVAL;goto done;}
    while(offset<sizeof(raw)){ssize_t amount=pread(terminal_fd,raw+offset,sizeof(raw)-offset,(off_t)offset);if(amount<=0){errno=EIO;goto done;}offset+=(size_t)amount;}
    terminal_mac(c,raw,mac);sha256_bytes(raw,472U,body);
    if(memcmp(raw,terminal_magic,sizeof(terminal_magic))!=0
            ||load_u16(raw+8U)!=1U||load_u16(raw+10U)!=sizeof(raw)
            ||load_u16(raw+12U)!=PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT
            ||load_u16(raw+14U)!=PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT
            ||load_u16(raw+16U)!=PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_SCRATCH_COUNT
            ||load_u16(raw+18U)!=7U||load_u32(raw+20U)!=0U
            ||load_u32(raw+24U)!=0U
            ||!secure_equal(raw+72U,c->policy_roster_sha256,32U)
            ||!secure_equal(raw+104U,c->executable_sha256,32U)
            ||!secure_equal(raw+136U,c->python_sha256,32U)
            ||!secure_equal(raw+168U,c->transform_sha256,32U)
            ||!secure_equal(raw+472U,body,32U)
            ||!secure_equal(raw+504U,c->transform_closure_sha256,32U)
            ||!secure_equal(raw+536U,c->install_verifier_public_key_sha256,32U)
            ||!secure_equal(raw+OP4_TERMINAL_MAC_OFFSET,mac,32U)){errno=EINVAL;goto done;}
    for(i=0U;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_OUTPUT_COUNT;++i){
        if(outputs[i].links!=0U||(outputs[i].mode&07777U)!=0400U
                ||load_u64(raw+200U+i*48U)!=outputs[i].size
                ||!secure_equal(raw+208U+i*48U,outputs[i].sha256,32U)
                ||load_u32(raw+240U+i*48U)!=outputs[i].mode){errno=ESTALE;goto done;}
    }
    result=0;
done:
    memset(raw,0,sizeof(raw));memset(mac,0,sizeof(mac));memset(body,0,sizeof(body));
    return result;
}

static int render_terminal(struct plamen_native_operation4_context_v1 *c,int status,uint64_t duration,int population_zero,const uint8_t group_sha[32],int outputs[5],int scratch[24],int *receipt_fd)
{
    uint8_t raw[PLAMEN_NATIVE_OPERATION4_HELPER_V1_TERMINAL_SIZE],digest[32],identity[64];struct retained_identity id;struct sha256_context scratch_hash;size_t i;int exited=WIFEXITED(status),code=exited?WEXITSTATUS(status):255,signal=WIFSIGNALED(status)?WTERMSIG(status):0;struct retained_identity terminal_after;
    if(private_store_aliases_exact(c->terminal_writer_fd,c->owner_uid,2U,1U)!=0)return -1;
    memset(raw,0,sizeof(raw));memcpy(raw,terminal_magic,8U);store_u16(raw+8U,1U);store_u16(raw+10U,sizeof(raw));store_u16(raw+12U,11U);store_u16(raw+14U,5U);store_u16(raw+16U,24U);store_u16(raw+18U,(uint16_t)((exited&&code==0&&population_zero)?7U:population_zero?4U:0U));store_u32(raw+20U,(uint32_t)code);store_u32(raw+24U,(uint32_t)signal);store_u64(raw+32U,duration);memcpy(raw+40U,group_sha,32U);memcpy(raw+72U,c->policy_roster_sha256,32U);memcpy(raw+104U,c->executable_sha256,32U);memcpy(raw+136U,c->python_sha256,32U);memcpy(raw+168U,c->transform_sha256,32U);memcpy(raw+504U,c->transform_closure_sha256,32U);memcpy(raw+536U,c->install_verifier_public_key_sha256,32U);
    for(i=0;i<5U;++i){if(identity_fd(outputs[i],&id)!=0||!S_ISREG(id.mode)||id.uid!=c->owner_uid||id.links!=0||id.size<=0||access_mode(outputs[i])!=O_RDWR||hash_fd(outputs[i],(uint64_t)id.size,digest)!=0)return -1;store_u64(raw+200U+i*48U,(uint64_t)id.size);memcpy(raw+208U+i*48U,digest,32U);store_u32(raw+240U+i*48U,(uint32_t)((id.mode&~07777U)|0400U));}
    sha256_init(&scratch_hash);for(i=0;i<24U;++i){if(identity_fd(scratch[i],&id)!=0||!S_ISREG(id.mode)||id.uid!=c->owner_uid||id.links!=0||access_mode(scratch[i])!=O_RDWR)return -1;memset(digest,0,sizeof(digest));identity_commitment(&id,digest,identity);sha256_update(&scratch_hash,identity,sizeof(identity));}sha256_final(&scratch_hash,raw+440U);
    sha256_bytes(raw,472U,raw+472U);
    terminal_mac(c,raw,raw+OP4_TERMINAL_MAC_OFFSET);
    if(ftruncate(c->terminal_writer_fd,0)!=0||fchmod(c->terminal_writer_fd,0600)!=0||write_all_at(c->terminal_writer_fd,raw,sizeof(raw),0)!=0||fsync(c->terminal_writer_fd)!=0||fchmod(c->terminal_writer_fd,0400)!=0||identity_fd(c->terminal_reader_fd,&terminal_after)!=0||terminal_after.size!=(off_t)sizeof(raw)||terminal_after.links!=0||access_mode(c->terminal_reader_fd)!=O_RDONLY){memset(raw,0,sizeof(raw));return -1;}
    close(c->terminal_writer_fd);c->terminal_writer_fd=-1;
    if(verify_terminal_readback(c,group_sha,status,population_zero)!=0){memset(raw,0,sizeof(raw));return -1;}
    *receipt_fd=duplicate_fd(c->terminal_reader_fd);memset(raw,0,sizeof(raw));memset(digest,0,sizeof(digest));memset(identity,0,sizeof(identity));return *receipt_fd<0?-1:0;
}

int plamen_native_operation4_invoke_fixed_v1(void *opaque,int composition,const int payloads[11],const int manifests[11],int outputs[5],int scratch[24],int *receipt_fd)
{
    struct plamen_native_operation4_context_v1 *c=opaque;uint8_t group_sha[32];int status=0,population_zero=0,rendered=-1;uint64_t duration=0;size_t i;struct retained_identity now;
    if(c==NULL||payloads==NULL||manifests==NULL||outputs==NULL||scratch==NULL||receipt_fd==NULL||*receipt_fd!=-1||c->consumed){errno=EINVAL;return -1;}c->consumed=1;
    if(build_group(c,composition,payloads,manifests,group_sha)!=0)return -1;
    if(launch_transform(c,outputs,scratch,&status,&duration,&population_zero)!=0){status=0;population_zero=0;}
    rendered=render_terminal(c,status,duration,population_zero,group_sha,outputs,scratch,receipt_fd);
    if(identity_fd(c->runtime_root_fd,&now)!=0||!same_identity(&c->runtime_root,&now)||identity_fd(c->python_fd,&now)!=0||!same_identity(&c->python,&now)||identity_fd(c->transform_fd,&now)!=0||!same_identity(&c->transform,&now)){if(*receipt_fd>=0){close(*receipt_fd);*receipt_fd=-1;}errno=ESTALE;return -1;}
    for(i=0;i<4U;++i)if(identity_fd(c->transform_dependency_fds[i],&now)!=0||!same_identity(&c->transform_dependencies[i],&now)){if(*receipt_fd>=0){close(*receipt_fd);*receipt_fd=-1;}errno=ESTALE;return -1;}
    if(identity_fd(c->install_verifier_public_key_fd,&now)!=0||!same_identity(&c->install_verifier_public_key,&now)){if(*receipt_fd>=0){close(*receipt_fd);*receipt_fd=-1;}errno=ESTALE;return -1;}
    for(i=0;i<PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT;++i)if(identity_fd(c->producer_receipt_fds[i],&now)!=0||!same_identity(&c->producer_receipts[i],&now)){if(*receipt_fd>=0){close(*receipt_fd);*receipt_fd=-1;}errno=ESTALE;return -1;}
    for(i=0;i<sizeof(group_sha);++i)group_sha[i]=0U;
    if(rendered!=0||!WIFEXITED(status)||WEXITSTATUS(status)!=0||!population_zero){if(*receipt_fd>=0){close(*receipt_fd);*receipt_fd=-1;}errno=EIO;return -1;}return 0;
}
