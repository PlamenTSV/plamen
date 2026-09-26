/*
 * Plamen native POSIX launch/wait broker.
 *
 * The broker is deliberately a standalone one-shot process.  Production
 * Python never receives the session key and cannot mint a broker receipt; a
 * future native CPython adapter owns the peer socket and authenticates frames.
 * This file currently enables the exact Darwin primitives.  Other POSIX
 * platforms fail closed until an equivalent descriptor-exec/close discipline
 * is compiled in.
 */

#ifdef __linux__
#define _GNU_SOURCE 1
#endif
#define _DARWIN_C_SOURCE 1

#include "../include/plamen_broker_v2.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/magic.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/vfs.h>
#endif

#ifdef __APPLE__
#include <libproc.h>
#include <sys/event.h>
#include <sys/proc_info.h>
#include <sys/un.h>
#endif

extern char **environ;

#if defined(__APPLE__) \
    && !defined(PLAMEN_NATIVE_BROKER_FORCE_UNSUPPORTED) \
    && defined(PLAMEN_NATIVE_BROKER_TEST_ONLY)
#define PLAMEN_NATIVE_BROKER_DARWIN 1
#elif defined(__APPLE__) && !defined(PLAMEN_NATIVE_BROKER_FORCE_UNSUPPORTED)
#define PLAMEN_NATIVE_BROKER_PRODUCTION_HARDSTOP 1
#endif

#ifdef PLAMEN_NATIVE_BROKER_DARWIN
#define FRAME_HEADER_SIZE 196U
#define FRAME_AUTH_OFFSET 164U
#define FRAME_VERSION 1U
#define FRAME_HELLO 1U
#define FRAME_REQUEST 2U
#define FRAME_RECEIPT 3U
#define FRAME_RECEIPT_CANDIDATE 4U
#define FRAME_RECEIPT_ACK 5U
#define FRAME_RECEIPT_COMMIT_ACK 6U
#define MAX_FRAME_PAYLOAD (2U * 1024U * 1024U)
#define MAX_ARGUMENTS 128U
#define MAX_ENVIRONMENT 256U
#define MAX_PASS_FDS 16U
#define MAX_TEXT 4096U
#define MAX_CAPTURE (1024U * 1024U)
#define MAX_TIMEOUT_MS 300000U
#define RECEIPT_FIXED_FIELDS 364U
#define CONTAINMENT_DEDICATED_PROCESS_GROUP_ONLY 1U

static const uint8_t FRAME_MAGIC[8] = {'P','L','M','B','R','K','1','\0'};

typedef struct {
    uint32_t state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} Sha256;

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t offset;
} Reader;

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} Writer;

typedef struct {
    char *attempt;
    uint64_t creator_pid;
    uint64_t creator_birth;
    uint32_t timeout_ms;
    uint32_t stdout_limit;
    uint32_t stderr_limit;
    uint8_t interpreter_sha[32];
    uint8_t executable_sha[32];
    uint8_t cwd_identity[32];
    uint8_t stdin_identity[32];
    char **argv;
    uint32_t argc;
    char **environment;
    uint32_t environment_count;
    uint32_t pass_count;
    uint32_t pass_targets[MAX_PASS_FDS];
    uint8_t pass_identities[MAX_PASS_FDS][32];
} LaunchRequest;

typedef struct {
    uint8_t *data;
    size_t size;
    size_t observed;
    size_t limit;
    int overflow;
    int truncated;
    Sha256 full_hash;
} Capture;

static uint32_t
rotr32(uint32_t value, unsigned amount)
{
    return (value >> amount) | (value << (32U - amount));
}

static void
sha256_transform(Sha256 *context, const uint8_t block[64])
{
    static const uint32_t constants[64] = {
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
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    unsigned index;
    for (index = 0; index < 16; index++) {
        words[index] = ((uint32_t)block[index * 4] << 24)
            | ((uint32_t)block[index * 4 + 1] << 16)
            | ((uint32_t)block[index * 4 + 2] << 8)
            | block[index * 4 + 3];
    }
    for (index = 16; index < 64; index++) {
        uint32_t s0 = rotr32(words[index - 15], 7)
            ^ rotr32(words[index - 15], 18) ^ (words[index - 15] >> 3);
        uint32_t s1 = rotr32(words[index - 2], 17)
            ^ rotr32(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a=context->state[0]; b=context->state[1]; c=context->state[2]; d=context->state[3];
    e=context->state[4]; f=context->state[5]; g=context->state[6]; h=context->state[7];
    for (index = 0; index < 64; index++) {
        uint32_t s1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
        uint32_t choice=(e&f)^((~e)&g);
        uint32_t t1=h+s1+choice+constants[index]+words[index];
        uint32_t s0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
        uint32_t majority=(a&b)^(a&c)^(b&c);
        uint32_t t2=s0+majority;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    context->state[0]+=a; context->state[1]+=b; context->state[2]+=c;
    context->state[3]+=d; context->state[4]+=e; context->state[5]+=f;
    context->state[6]+=g; context->state[7]+=h;
}

static void
sha256_init(Sha256 *context)
{
    static const uint32_t initial[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bits = 0; context->used = 0;
}

static void
sha256_update(Sha256 *context, const void *raw, size_t size)
{
    const uint8_t *data = raw;
    context->bits += (uint64_t)size * 8U;
    while (size != 0) {
        size_t room = 64U - context->used;
        size_t take = size < room ? size : room;
        memcpy(context->block + context->used, data, take);
        context->used += take; data += take; size -= take;
        if (context->used == 64U) {
            sha256_transform(context, context->block); context->used = 0;
        }
    }
}

static void
sha256_final(Sha256 *context, uint8_t digest[32])
{
    uint64_t bits = context->bits;
    unsigned index;
    context->block[context->used++] = 0x80U;
    if (context->used > 56U) {
        memset(context->block + context->used, 0, 64U - context->used);
        sha256_transform(context, context->block); context->used = 0;
    }
    memset(context->block + context->used, 0, 56U - context->used);
    for (index = 0; index < 8; index++)
        context->block[63U - index] = (uint8_t)(bits >> (index * 8U));
    sha256_transform(context, context->block);
    for (index = 0; index < 8; index++) {
        digest[index*4]=(uint8_t)(context->state[index]>>24);
        digest[index*4+1]=(uint8_t)(context->state[index]>>16);
        digest[index*4+2]=(uint8_t)(context->state[index]>>8);
        digest[index*4+3]=(uint8_t)context->state[index];
    }
    memset(context, 0, sizeof(*context));
}

static void
sha256_bytes(const void *data, size_t size, uint8_t digest[32])
{
    Sha256 context; sha256_init(&context); sha256_update(&context, data, size);
    sha256_final(&context, digest);
}

static void
hmac_sha256(const uint8_t key[32], const uint8_t *header_prefix,
            const uint8_t *payload, size_t payload_size, uint8_t digest[32])
{
    uint8_t inner_key[64], outer_key[64], inner_digest[32];
    Sha256 context; size_t index;
    memset(inner_key, 0x36, sizeof(inner_key));
    memset(outer_key, 0x5c, sizeof(outer_key));
    for (index = 0; index < 32; index++) {
        inner_key[index] ^= key[index]; outer_key[index] ^= key[index];
    }
    sha256_init(&context); sha256_update(&context, inner_key, sizeof(inner_key));
    sha256_update(&context, header_prefix, FRAME_AUTH_OFFSET);
    sha256_update(&context, payload, payload_size); sha256_final(&context, inner_digest);
    sha256_init(&context); sha256_update(&context, outer_key, sizeof(outer_key));
    sha256_update(&context, inner_digest, sizeof(inner_digest));
    sha256_final(&context, digest);
    memset(inner_key, 0, sizeof(inner_key)); memset(outer_key, 0, sizeof(outer_key));
    memset(inner_digest, 0, sizeof(inner_digest));
}

static int
constant_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0; size_t index;
    for (index = 0; index < size; index++) difference |= left[index] ^ right[index];
    return difference == 0;
}

static void put_u16(uint8_t *out, uint16_t value) { out[0]=(uint8_t)(value>>8); out[1]=(uint8_t)value; }
static void put_u32(uint8_t *out, uint32_t value) { out[0]=(uint8_t)(value>>24); out[1]=(uint8_t)(value>>16); out[2]=(uint8_t)(value>>8); out[3]=(uint8_t)value; }
static void put_u64(uint8_t *out, uint64_t value) { put_u32(out,(uint32_t)(value>>32)); put_u32(out+4,(uint32_t)value); }
static uint16_t get_u16(const uint8_t *in) { return (uint16_t)(((uint16_t)in[0]<<8)|in[1]); }
static uint32_t get_u32(const uint8_t *in) { return ((uint32_t)in[0]<<24)|((uint32_t)in[1]<<16)|((uint32_t)in[2]<<8)|in[3]; }
static uint64_t get_u64(const uint8_t *in) { return ((uint64_t)get_u32(in)<<32)|get_u32(in+4); }

static int
writer_grow(Writer *writer, size_t amount)
{
    size_t needed;
    uint8_t *replacement;
    if (amount > MAX_FRAME_PAYLOAD || writer->size > MAX_FRAME_PAYLOAD - amount) return -1;
    needed = writer->size + amount;
    if (needed <= writer->capacity) return 0;
    writer->capacity = writer->capacity == 0 ? 512U : writer->capacity;
    while (writer->capacity < needed) writer->capacity *= 2U;
    replacement = realloc(writer->data, writer->capacity);
    if (replacement == NULL) return -1;
    writer->data = replacement; return 0;
}

static int writer_bytes(Writer *w, const void *p, size_t n) { if(writer_grow(w,n)<0)return -1; memcpy(w->data+w->size,p,n); w->size+=n; return 0; }
static int writer_u32(Writer *w, uint32_t v) { uint8_t b[4]; put_u32(b,v); return writer_bytes(w,b,4); }
static int writer_u64(Writer *w, uint64_t v) { uint8_t b[8]; put_u64(b,v); return writer_bytes(w,b,8); }
static int writer_text(Writer *w, const char *s) { size_t n=strlen(s); return n<=UINT32_MAX && writer_u32(w,(uint32_t)n)==0 ? writer_bytes(w,s,n) : -1; }

static int reader_bytes(Reader *r, void *out, size_t n) { if(n>r->size-r->offset)return -1; memcpy(out,r->data+r->offset,n); r->offset+=n; return 0; }
static int reader_u32(Reader *r, uint32_t *v) { uint8_t b[4]; if(reader_bytes(r,b,4)<0)return -1; *v=get_u32(b); return 0; }
static int reader_u64(Reader *r, uint64_t *v) { uint8_t b[8]; if(reader_bytes(r,b,8)<0)return -1; *v=get_u64(b); return 0; }

static int
reader_text(Reader *reader, char **output)
{
    uint32_t size; char *text;
    if (reader_u32(reader, &size) < 0 || size == 0 || size > MAX_TEXT
            || size > reader->size - reader->offset) return -1;
    text = malloc((size_t)size + 1U); if (text == NULL) return -1;
    memcpy(text, reader->data + reader->offset, size); text[size] = '\0';
    if (memchr(text, '\0', size) != NULL) { free(text); return -1; }
    reader->offset += size; *output = text; return 0;
}

static void
free_request(LaunchRequest *request)
{
    uint32_t index;
    free(request->attempt);
    for (index=0; index<request->argc; index++) free(request->argv[index]);
    for (index=0; index<request->environment_count; index++) free(request->environment[index]);
    free(request->argv); free(request->environment); memset(request,0,sizeof(*request));
}

static int
valid_attempt(const char *value)
{
    size_t index, size=strlen(value); if(size<1||size>128)return 0;
    for(index=0;index<size;index++) if(!((value[index]>='a'&&value[index]<='z')||(value[index]>='A'&&value[index]<='Z')||(value[index]>='0'&&value[index]<='9')||value[index]=='_'||value[index]=='-'||value[index]=='.')) return 0;
    return 1;
}

static int
valid_environment(const char *value)
{
    const char *equals=strchr(value,'='); const char *p;
    if(equals==NULL||equals==value)return 0;
    if(!((*value>='A'&&*value<='Z')||(*value>='a'&&*value<='z')||*value=='_'))return 0;
    for(p=value+1;p<equals;p++) if(!((*p>='A'&&*p<='Z')||(*p>='a'&&*p<='z')||(*p>='0'&&*p<='9')||*p=='_'))return 0;
    return 1;
}

static int
compare_environment_name(const char *left,const char *right)
{
    const char *left_equals=strchr(left,'='),*right_equals=strchr(right,'=');
    size_t left_size,right_size,shared;int compared;
    if(left_equals==NULL||right_equals==NULL)return 0;
    left_size=(size_t)(left_equals-left);right_size=(size_t)(right_equals-right);
    shared=left_size<right_size?left_size:right_size;
    compared=memcmp(left,right,shared);
    if(compared!=0)return compared;
    if(left_size<right_size)return -1;
    if(left_size>right_size)return 1;
    return 0;
}

static int
parse_request(const uint8_t *payload, size_t size, LaunchRequest *request)
{
    Reader reader={payload,size,0}; uint32_t version,index;
    memset(request,0,sizeof(*request));
    if(reader_u32(&reader,&version)<0||version!=1U
       ||reader_u64(&reader,&request->creator_pid)<0
       ||reader_u64(&reader,&request->creator_birth)<0
       ||reader_u32(&reader,&request->timeout_ms)<0
       ||reader_u32(&reader,&request->stdout_limit)<0
       ||reader_u32(&reader,&request->stderr_limit)<0
       ||reader_bytes(&reader,request->interpreter_sha,32)<0
       ||reader_bytes(&reader,request->executable_sha,32)<0
       ||reader_bytes(&reader,request->cwd_identity,32)<0
       ||reader_bytes(&reader,request->stdin_identity,32)<0
       ||reader_text(&reader,&request->attempt)<0
       ||!valid_attempt(request->attempt)
       ||request->timeout_ms<1U||request->timeout_ms>MAX_TIMEOUT_MS
       ||request->stdout_limit<1U||request->stdout_limit>MAX_CAPTURE
       ||request->stderr_limit<1U||request->stderr_limit>MAX_CAPTURE) goto fail;
    if(reader_u32(&reader,&request->argc)<0||request->argc<1U||request->argc>MAX_ARGUMENTS)goto fail;
    request->argv=calloc((size_t)request->argc+1U,sizeof(char*)); if(request->argv==NULL)goto fail;
    for(index=0;index<request->argc;index++)if(reader_text(&reader,&request->argv[index])<0)goto fail;
    if(reader_u32(&reader,&request->environment_count)<0||request->environment_count>MAX_ENVIRONMENT)goto fail;
    request->environment=calloc((size_t)request->environment_count+1U,sizeof(char*)); if(request->environment==NULL)goto fail;
    for(index=0;index<request->environment_count;index++){
        if(reader_text(&reader,&request->environment[index])<0||!valid_environment(request->environment[index]))goto fail;
        if(index>0&&compare_environment_name(
            request->environment[index-1],request->environment[index])>=0)goto fail;
    }
    if(reader_u32(&reader,&request->pass_count)<0||request->pass_count>MAX_PASS_FDS)goto fail;
    for(index=0;index<request->pass_count;index++){
        if(reader_u32(&reader,&request->pass_targets[index])<0
           ||reader_bytes(&reader,request->pass_identities[index],32)<0
           ||request->pass_targets[index]<3U||request->pass_targets[index]>63U
           ||(index>0&&request->pass_targets[index-1]>=request->pass_targets[index]))goto fail;
    }
    if(reader.offset!=reader.size)goto fail;
    return 0;
fail:
    free_request(request); return -1;
}

static int
set_cloexec(int descriptor)
{
    int flags=fcntl(descriptor,F_GETFD); return flags<0? -1:fcntl(descriptor,F_SETFD,flags|FD_CLOEXEC);
}

static void close_many(int *descriptors, size_t count) { size_t i; for(i=0;i<count;i++)if(descriptors[i]>=0){close(descriptors[i]);descriptors[i]=-1;} }

static int
read_exact(int descriptor, uint8_t *buffer, size_t size)
{
    size_t offset=0;ssize_t amount;
    while(offset<size){amount=read(descriptor,buffer+offset,size-offset);if(amount>0){offset+=(size_t)amount;continue;}if(amount<0&&errno==EINTR)continue;return -1;}
    return 0;
}

static int
receive_request(int control_fd, uint8_t **frame_out, size_t *frame_size,
                int fds[4+MAX_PASS_FDS], size_t *fd_count)
{
    uint8_t header_bytes[FRAME_HEADER_SIZE],*frame=NULL; struct iovec iov;
    char ancillary[CMSG_SPACE(sizeof(int)*(4+MAX_PASS_FDS))]; struct msghdr message;
    struct cmsghdr *header; ssize_t received; size_t count=0;uint32_t payload_size;
    memset(&message,0,sizeof(message)); memset(ancillary,0,sizeof(ancillary));
    iov.iov_base=header_bytes;iov.iov_len=FRAME_HEADER_SIZE;
    message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=ancillary;message.msg_controllen=sizeof(ancillary);
    do{received=recvmsg(control_fd,&message,MSG_WAITALL);}while(received<0&&errno==EINTR);
    if(received!=(ssize_t)FRAME_HEADER_SIZE||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0)return -1;
    for(header=CMSG_FIRSTHDR(&message);header!=NULL;header=CMSG_NXTHDR(&message,header)){
        size_t bytes;
        if(header->cmsg_level!=SOL_SOCKET||header->cmsg_type!=SCM_RIGHTS)goto fail;
        if(header->cmsg_len<CMSG_LEN(0))goto fail;
        bytes=header->cmsg_len-CMSG_LEN(0);
        if(bytes%sizeof(int)!=0||count+bytes/sizeof(int)>4+MAX_PASS_FDS)goto fail;
        memcpy(fds+count,CMSG_DATA(header),bytes);count+=bytes/sizeof(int);
    }
    for(size_t index=0;index<count;index++)if(set_cloexec(fds[index])<0){close_many(fds,count);return -1;}
    payload_size=get_u32(header_bytes+20);if(payload_size>MAX_FRAME_PAYLOAD){close_many(fds,count);return -1;}
    frame=malloc(FRAME_HEADER_SIZE+payload_size);if(frame==NULL){close_many(fds,count);return -1;}
    memcpy(frame,header_bytes,FRAME_HEADER_SIZE);
    if(read_exact(control_fd,frame+FRAME_HEADER_SIZE,payload_size)<0){close_many(fds,count);free(frame);return -1;}
    {
        uint8_t trailing;ssize_t extra=recv(control_fd,&trailing,1,MSG_PEEK|MSG_DONTWAIT);
        if(extra>0||(extra<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK)){close_many(fds,count);free(frame);return -1;}
    }
    *frame_out=frame;*frame_size=FRAME_HEADER_SIZE+payload_size;*fd_count=count;return 0;
fail:
    close_many(fds,count);free(frame);return -1;
}

static int creator_lease_intact(int descriptor,pid_t creator_pid);

static int
send_frame(int descriptor, uint16_t type, uint64_t sequence, uint16_t fd_count,
           const uint8_t session[32], const uint8_t key[32],
           const uint8_t nonce[32], const uint8_t previous[32],
           const uint8_t *payload, size_t payload_size, int authenticate,
           int creator_lease_fd,pid_t creator_pid,uint8_t frame_digest[32])
{
    uint8_t *frame; uint8_t digest[32],mac[32]; size_t offset=0,total,amount;ssize_t result;
    if(payload_size>MAX_FRAME_PAYLOAD)return -1;
    frame=calloc(1,FRAME_HEADER_SIZE+payload_size);if(frame==NULL)return -1;
    memcpy(frame,FRAME_MAGIC,8);put_u16(frame+8,FRAME_VERSION);put_u16(frame+10,type);put_u32(frame+12,0);
    put_u32(frame+16,FRAME_HEADER_SIZE);put_u32(frame+20,(uint32_t)payload_size);put_u16(frame+24,fd_count);put_u16(frame+26,0);put_u64(frame+28,sequence);
    memcpy(frame+36,session,32);memcpy(frame+68,nonce,32);memcpy(frame+100,previous,32);
    sha256_bytes(payload,payload_size,digest);memcpy(frame+132,digest,32);
    if(authenticate){hmac_sha256(key,frame,payload,payload_size,mac);memcpy(frame+164,mac,32);}
    memcpy(frame+FRAME_HEADER_SIZE,payload,payload_size);
    total=FRAME_HEADER_SIZE+payload_size;
    if(frame_digest!=NULL)sha256_bytes(frame,total,frame_digest);
    while(offset<total){
        if(creator_lease_fd>=0&&creator_lease_intact(creator_lease_fd,creator_pid)<0){free(frame);return -1;}
        amount=total-offset;if(amount>4096U)amount=4096U;
        result=send(descriptor,frame+offset,amount,MSG_NOSIGNAL);
        if(result>0){offset+=(size_t)result;continue;}
        if(result<0&&errno==EINTR)continue;free(frame);return -1;
    }
    if(creator_lease_fd>=0&&creator_lease_intact(creator_lease_fd,creator_pid)<0){free(frame);return -1;}
    free(frame);return 0;
}

static int
verify_request_frame(const uint8_t *frame,size_t frame_size,const uint8_t session[32],const uint8_t key[32])
{
    uint8_t digest[32],mac[32];uint32_t payload_size;
    if(frame_size<FRAME_HEADER_SIZE||memcmp(frame,FRAME_MAGIC,8)!=0||get_u16(frame+8)!=FRAME_VERSION
       ||get_u16(frame+10)!=FRAME_REQUEST||get_u32(frame+12)!=0||get_u32(frame+16)!=FRAME_HEADER_SIZE
       ||get_u16(frame+26)!=0||get_u64(frame+28)!=1U||!constant_equal(frame+36,session,32))return -1;
    payload_size=get_u32(frame+20);if(payload_size!=frame_size-FRAME_HEADER_SIZE)return -1;
    sha256_bytes(frame+FRAME_HEADER_SIZE,payload_size,digest);if(!constant_equal(digest,frame+132,32))return -1;
hmac_sha256(key,frame,frame+FRAME_HEADER_SIZE,payload_size,mac);return constant_equal(mac,frame+164,32)?0:-1;
}

static int
verify_receipt_ack(const uint8_t *frame,size_t frame_size,uint16_t expected_type,
                   uint64_t expected_sequence,const uint8_t session[32],
                   const uint8_t key[32],const uint8_t nonce[32],
                   const uint8_t previous[32])
{
    uint8_t digest[32],mac[32];uint32_t payload_size;
    if(frame_size!=FRAME_HEADER_SIZE+32U||memcmp(frame,FRAME_MAGIC,8)!=0
       ||get_u16(frame+8)!=FRAME_VERSION||get_u16(frame+10)!=expected_type
       ||get_u32(frame+12)!=0||get_u32(frame+16)!=FRAME_HEADER_SIZE
       ||get_u16(frame+24)!=0||get_u16(frame+26)!=0
       ||get_u64(frame+28)!=expected_sequence||!constant_equal(frame+36,session,32)
       ||!constant_equal(frame+68,nonce,32)||!constant_equal(frame+100,previous,32))return -1;
    payload_size=get_u32(frame+20);if(payload_size!=32U)return -1;
    sha256_bytes(frame+FRAME_HEADER_SIZE,payload_size,digest);
    if(!constant_equal(digest,frame+132,32)||!constant_equal(frame+FRAME_HEADER_SIZE,previous,32))return -1;
    hmac_sha256(key,frame,frame+FRAME_HEADER_SIZE,payload_size,mac);
    return constant_equal(mac,frame+164,32)?0:-1;
}

static int
sha256_fd(int descriptor,uint8_t digest[32])
{
    struct stat info;Sha256 context;uint8_t buffer[65536];off_t offset=0;ssize_t amount;
    if(fstat(descriptor,&info)<0||!S_ISREG(info.st_mode)||info.st_size<0)return -1;
    sha256_init(&context);
    while(offset<info.st_size){size_t wanted=(size_t)(info.st_size-offset);if(wanted>sizeof(buffer))wanted=sizeof(buffer);amount=pread(descriptor,buffer,wanted,offset);if(amount<=0)return -1;sha256_update(&context,buffer,(size_t)amount);offset+=amount;}
    if(pread(descriptor,buffer,1,info.st_size)!=0)return -1;sha256_final(&context,digest);return 0;
}

static int
identity_digest(int descriptor,uint8_t digest[32],int require_regular,int require_directory)
{
    struct stat info;uint8_t canonical[112],content[32];
    if(fstat(descriptor,&info)<0)return -1;
    if(require_regular&&!S_ISREG(info.st_mode))return -1;if(require_directory&&!S_ISDIR(info.st_mode))return -1;
    memset(content,0,sizeof(content));if(S_ISREG(info.st_mode)&&sha256_fd(descriptor,content)<0)return -1;
    memset(canonical,0,sizeof(canonical));put_u64(canonical,(uint64_t)info.st_dev);put_u64(canonical+8,(uint64_t)info.st_ino);
    put_u64(canonical+16,(uint64_t)info.st_mode);put_u64(canonical+24,(uint64_t)info.st_uid);put_u64(canonical+32,(uint64_t)info.st_gid);
    put_u64(canonical+40,(uint64_t)info.st_size);
#ifdef __APPLE__
    put_u64(canonical+48,(uint64_t)info.st_mtimespec.tv_sec);put_u64(canonical+56,(uint64_t)info.st_mtimespec.tv_nsec);
    put_u64(canonical+64,(uint64_t)info.st_ctimespec.tv_sec);put_u64(canonical+72,(uint64_t)info.st_ctimespec.tv_nsec);
#else
    put_u64(canonical+48,(uint64_t)info.st_mtim.tv_sec);put_u64(canonical+56,(uint64_t)info.st_mtim.tv_nsec);
    put_u64(canonical+64,(uint64_t)info.st_ctim.tv_sec);put_u64(canonical+72,(uint64_t)info.st_ctim.tv_nsec);
#endif
    memcpy(canonical+80,content,32);
    sha256_bytes(canonical,sizeof(canonical),digest);return 0;
}

#ifdef __APPLE__
static int
creator_lease_open(pid_t creator_pid)
{
    int descriptor=kqueue();struct kevent change;
    if(descriptor<0)return -1;
    EV_SET(&change,(uintptr_t)creator_pid,EVFILT_PROC,EV_ADD|EV_CLEAR,
           NOTE_FORK|NOTE_EXEC|NOTE_EXIT,0,NULL);
    if(kevent(descriptor,&change,1,NULL,0,NULL)<0){close(descriptor);return -1;}
    return descriptor;
}

static int
creator_lease_intact(int descriptor,pid_t creator_pid)
{
    struct kevent events[8];struct timespec immediate={0,0};int count,index;
    for(;;){
        do{count=kevent(descriptor,NULL,0,events,8,&immediate);}while(count<0&&errno==EINTR);
        if(count<0)return -1;
        for(index=0;index<count;index++)
            if(events[index].filter==EVFILT_PROC
               &&events[index].ident==(uintptr_t)creator_pid)return -1;
        if(count<8)return 0;
    }
}

static int
secure_root_owned_ancestry(const char *path)
{
    char prefix[PATH_MAX];size_t size,index;struct stat info;
    if(path==NULL||path[0]!='/'||(size=strlen(path))<2U||size>=sizeof(prefix))return -1;
    if(lstat("/",&info)<0||!S_ISDIR(info.st_mode)||info.st_uid!=0
       ||(info.st_mode&(S_IWGRP|S_IWOTH))!=0)return -1;
    memcpy(prefix,path,size+1U);
    for(index=1U;index<=size;index++){
        char saved;
        if(index<size&&prefix[index]!='/')continue;
        saved=prefix[index];prefix[index]='\0';
        if(lstat(prefix,&info)<0||S_ISLNK(info.st_mode)||info.st_uid!=0
           ||(info.st_mode&(S_IWGRP|S_IWOTH))!=0
           ||(index<size&&!S_ISDIR(info.st_mode))){prefix[index]=saved;return -1;}
        prefix[index]=saved;
    }
    return 0;
}

static int
peer_pid_and_birth(int control_fd,pid_t *pid,uint64_t *birth)
{
    socklen_t size=sizeof(*pid);struct proc_bsdinfo info;int result;
    if(getsockopt(control_fd,SOL_LOCAL,LOCAL_PEERPID,pid,&size)<0||size!=sizeof(*pid)||*pid<=1)return -1;
    memset(&info,0,sizeof(info));result=proc_pidinfo(*pid,PROC_PIDTBSDINFO,0,&info,sizeof(info));
    if(result!=(int)sizeof(info))return -1;
    *birth=(uint64_t)info.pbi_start_tvsec*1000000U+(uint64_t)info.pbi_start_tvusec;return 0;
}

static int
same_file(const struct stat *left,const struct stat *right)
{
    return left->st_dev==right->st_dev&&left->st_ino==right->st_ino&&left->st_mode==right->st_mode
        &&left->st_uid==right->st_uid&&left->st_gid==right->st_gid&&left->st_size==right->st_size
        &&left->st_mtimespec.tv_sec==right->st_mtimespec.tv_sec&&left->st_mtimespec.tv_nsec==right->st_mtimespec.tv_nsec
        &&left->st_ctimespec.tv_sec==right->st_ctimespec.tv_sec&&left->st_ctimespec.tv_nsec==right->st_ctimespec.tv_nsec;
}

static int
admit_executable(int descriptor,char path[PATH_MAX],uint8_t digest[32])
{
    struct stat retained,named;int named_fd=-1;const char *prefixes[]={"/bin/","/usr/bin/","/System/","/Library/Developer/CommandLineTools/"};size_t index;
    if(geteuid()==0||fstat(descriptor,&retained)<0||!S_ISREG(retained.st_mode)||(retained.st_mode&0111)==0
       ||retained.st_uid!=0||(retained.st_mode&(S_IWGRP|S_IWOTH))!=0||fcntl(descriptor,F_GETPATH,path)<0)return -1;
    for(index=0;index<sizeof(prefixes)/sizeof(prefixes[0]);index++)if(strncmp(path,prefixes[index],strlen(prefixes[index]))==0)break;
    if(index==sizeof(prefixes)/sizeof(prefixes[0]))return -1;
    if(secure_root_owned_ancestry(path)<0)return -1;
    named_fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(named_fd<0)return -1;
    if(fstat(named_fd,&named)<0||!same_file(&retained,&named)||sha256_fd(descriptor,digest)<0){close(named_fd);return -1;}
    close(named_fd);return 0;
}

static int
admit_peer_interpreter(int descriptor,pid_t peer_pid)
{
    char process_path[PROC_PIDPATHINFO_MAXSIZE];char descriptor_path[PATH_MAX];
    struct stat retained,named;int named_fd;
    if(proc_pidpath(peer_pid,process_path,sizeof(process_path))<=0
       ||fcntl(descriptor,F_GETPATH,descriptor_path)<0
       ||strcmp(process_path,descriptor_path)!=0||fstat(descriptor,&retained)<0)return -1;
    named_fd=open(process_path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(named_fd<0)return -1;
    if(fstat(named_fd,&named)<0||!same_file(&retained,&named)){close(named_fd);return -1;}
    close(named_fd);return 0;
}

static int
normalize_fds(int *fds,size_t count)
{
    size_t index;int duplicate;
    for(index=0;index<count;index++){
        duplicate=fcntl(fds[index],F_DUPFD_CLOEXEC,64);
        if(duplicate<0)return -1;close(fds[index]);fds[index]=duplicate;
    }
    return 0;
}

static int
reject_fd_aliases(const int *fds,size_t count)
{
    struct stat left,right;size_t i,j;
    for(i=0;i<count;i++){
        if(fstat(fds[i],&left)<0)return -1;
        for(j=0;j<i;j++){
            if(fstat(fds[j],&right)<0)return -1;
            if(left.st_dev==right.st_dev&&left.st_ino==right.st_ino
               &&(left.st_mode&S_IFMT)==(right.st_mode&S_IFMT))return -1;
        }
    }
    return 0;
}

static int
make_pipe(int pair[2])
{
    if(pipe(pair)<0)return -1;
    if(set_cloexec(pair[0])<0||set_cloexec(pair[1])<0){close(pair[0]);close(pair[1]);return -1;}
    return 0;
}

static uint64_t
monotonic_ms(void)
{
    struct timespec value;if(clock_gettime(CLOCK_MONOTONIC,&value)<0)return 0;
    return (uint64_t)value.tv_sec*1000U+(uint64_t)value.tv_nsec/1000000U;
}

static int
capture_init(Capture *capture,size_t limit)
{
    memset(capture,0,sizeof(*capture));capture->data=malloc(limit);if(capture->data==NULL)return -1;
    capture->limit=limit;sha256_init(&capture->full_hash);return 0;
}

static int
capture_read(int descriptor,Capture *capture,int *eof)
{
    uint8_t buffer[65536];ssize_t amount;size_t retained;
    for(;;){
        amount=read(descriptor,buffer,sizeof(buffer));
        if(amount>0){
            sha256_update(&capture->full_hash,buffer,(size_t)amount);
            if((size_t)amount>SIZE_MAX-capture->observed)return -1;
            capture->observed+=(size_t)amount;if(capture->observed>MAX_CAPTURE)capture->overflow=1;
            retained=(size_t)amount;if(retained>capture->limit-capture->size)retained=capture->limit-capture->size;
            if(retained>0){memcpy(capture->data+capture->size,buffer,retained);capture->size+=retained;}
            if(retained<(size_t)amount)capture->truncated=1;
            continue;
        }
        if(amount==0){*eof=1;return 0;}if(errno==EINTR)continue;if(errno==EAGAIN||errno==EWOULDBLOCK)return 0;return -1;
    }
}

static int
spawn_and_capture(const LaunchRequest *request,int fds[4+MAX_PASS_FDS],
                  Capture *out,Capture *err,pid_t *child_out,int *wait_status,
                  uint32_t *terminal_status,int *extinct,
                  const uint8_t expected_executable_sha[32],int creator_lease_fd,
                  pid_t creator_pid)
{
    posix_spawn_file_actions_t actions;posix_spawnattr_t attributes;sigset_t empty,defaults;
    int out_pipe[2]={-1,-1},err_pipe[2]={-1,-1},kqueue_fd=creator_lease_fd,result=-1,spawned=0;
    int actions_initialized=0,attributes_initialized=0;
    short flags=POSIX_SPAWN_CLOEXEC_DEFAULT|POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK;
    struct kevent changes[3],events[6];pid_t child=-1;uint32_t index;char executable[PATH_MAX];uint8_t executable_sha[32];
    uint64_t deadline;int out_eof=0,err_eof=0,child_exited=0,child_reaped=0,killed=0;
    struct stat before,after;
    if(admit_executable(fds[1],executable,executable_sha)<0
       ||!constant_equal(executable_sha,expected_executable_sha,32)
       ||strcmp(request->argv[0],executable)!=0)return -1;
    if(make_pipe(out_pipe)<0||make_pipe(err_pipe)<0)goto done;
    if(fcntl(out_pipe[0],F_SETFL,fcntl(out_pipe[0],F_GETFL)|O_NONBLOCK)<0||fcntl(err_pipe[0],F_SETFL,fcntl(err_pipe[0],F_GETFL)|O_NONBLOCK)<0)goto done;
    if(posix_spawn_file_actions_init(&actions)!=0)goto done;actions_initialized=1;
    if(posix_spawnattr_init(&attributes)!=0)goto destroy;attributes_initialized=1;
    sigemptyset(&empty);sigfillset(&defaults);sigdelset(&defaults,SIGKILL);sigdelset(&defaults,SIGSTOP);
    if(posix_spawnattr_setflags(&attributes,flags)!=0||posix_spawnattr_setpgroup(&attributes,0)!=0
       ||posix_spawnattr_setsigmask(&attributes,&empty)!=0||posix_spawnattr_setsigdefault(&attributes,&defaults)!=0
       ||posix_spawn_file_actions_addfchdir_np(&actions,fds[2])!=0
       ||posix_spawn_file_actions_adddup2(&actions,fds[3],STDIN_FILENO)!=0
       ||posix_spawn_file_actions_adddup2(&actions,out_pipe[1],STDOUT_FILENO)!=0
       ||posix_spawn_file_actions_adddup2(&actions,err_pipe[1],STDERR_FILENO)!=0)goto destroy;
    for(index=0;index<request->pass_count;index++)if(posix_spawn_file_actions_adddup2(&actions,fds[4+index],(int)request->pass_targets[index])!=0)goto destroy;
    if(fstat(fds[1],&before)<0)goto destroy;
    {
        int check=open(executable,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        if(check<0||fstat(check,&after)<0||!same_file(&before,&after)){if(check>=0)close(check);goto destroy;}close(check);
    }
    if(posix_spawn(&child,executable,&actions,&attributes,request->argv,request->environment)!=0)goto destroy;
    spawned=1;*child_out=child;close(out_pipe[1]);out_pipe[1]=-1;close(err_pipe[1]);err_pipe[1]=-1;
    if(kqueue_fd<0)goto terminate;
    EV_SET(&changes[0],(uintptr_t)out_pipe[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,NULL);
    EV_SET(&changes[1],(uintptr_t)err_pipe[0],EVFILT_READ,EV_ADD|EV_CLEAR,0,0,NULL);
    EV_SET(&changes[2],(uintptr_t)child,EVFILT_PROC,EV_ADD|EV_ONESHOT,NOTE_EXIT,0,NULL);
    if(kevent(kqueue_fd,changes,3,NULL,0,NULL)<0){
        if(errno==ESRCH){
            pid_t waited;
            do{waited=waitpid(child,wait_status,WNOHANG);}while(waited<0&&errno==EINTR);
            if(waited==child){child_exited=1;child_reaped=1;goto child_observed;}
        }
        goto terminate;
    }
    deadline=monotonic_ms()+request->timeout_ms;
    while(!child_exited){
        uint64_t now=monotonic_ms();struct timespec timeout;int count,event_index;
        if(now==0||now>=deadline){*terminal_status=1U;goto terminate;}
        timeout.tv_sec=(time_t)((deadline-now)/1000U);timeout.tv_nsec=(long)(((deadline-now)%1000U)*1000000U);
        count=kevent(kqueue_fd,NULL,0,events,6,&timeout);
        if(count<0){if(errno==EINTR)continue;goto terminate;}if(count==0){*terminal_status=1U;goto terminate;}
        for(event_index=0;event_index<count;event_index++){
            if(events[event_index].filter==EVFILT_PROC){
                if(events[event_index].ident==(uintptr_t)creator_pid){*terminal_status=4U;goto terminate;}
                if(events[event_index].ident==(uintptr_t)child){child_exited=1;continue;}
                *terminal_status=3U;goto terminate;
            }
            if(events[event_index].ident==(uintptr_t)out_pipe[0]&&capture_read(out_pipe[0],out,&out_eof)<0)goto terminate;
            if(events[event_index].ident==(uintptr_t)err_pipe[0]&&capture_read(err_pipe[0],err,&err_eof)<0)goto terminate;
        }
        if(out->overflow||err->overflow){*terminal_status=2U;goto terminate;}
    }
child_observed:
    /* Kill every remaining member before the single logical child reap. */
    if(kill(-child,SIGKILL)==0)killed=1;
    else if(errno!=ESRCH&&errno!=EPERM)goto terminate;
    goto drain;
terminate:
    if(*terminal_status==0)*terminal_status=3U;
    if(spawned){
        if(kill(-child,SIGKILL)==0)killed=1;
        else if(errno!=ESRCH)(void)kill(child,SIGKILL);
    }
drain:
    for(index=0;index<200U&&(!out_eof||!err_eof);index++){
        struct timespec pause={0,10000000};
        if(!out_eof&&capture_read(out_pipe[0],out,&out_eof)<0){*terminal_status=3U;goto reap;}
        if(!err_eof&&capture_read(err_pipe[0],err,&err_eof)<0){*terminal_status=3U;goto reap;}
        if(!out_eof||!err_eof)nanosleep(&pause,NULL);
    }
    if(!out_eof||!err_eof){*terminal_status=3U;goto reap;}
    goto reap;
reap:
    if(spawned&&!child_reaped){pid_t waited;do{waited=waitpid(child,wait_status,0);}while(waited<0&&errno==EINTR);if(waited!=child)goto destroy;child_reaped=1;}
    if(kill(-child,0)<0&&errno==ESRCH)*extinct=1;else{kill(-child,SIGKILL);*extinct=0;if(*terminal_status==0)*terminal_status=3U;}
    if((out->overflow||err->overflow)&&*terminal_status==0)*terminal_status=2U;
    result=spawned?0:-1;
destroy:
    if(attributes_initialized)posix_spawnattr_destroy(&attributes);
    if(actions_initialized)posix_spawn_file_actions_destroy(&actions);
done:
    if(out_pipe[0]>=0)close(out_pipe[0]);if(out_pipe[1]>=0)close(out_pipe[1]);if(err_pipe[0]>=0)close(err_pipe[0]);if(err_pipe[1]>=0)close(err_pipe[1]);
    (void)killed;return result;
}
#endif

static int
build_receipt(Writer *receipt,const LaunchRequest *request,const uint8_t request_digest[32],
              const uint8_t session[32],pid_t child,int wait_status,uint32_t terminal_status,
              int extinct,const uint8_t interpreter_sha[32],const uint8_t executable_sha[32],
              const uint8_t interpreter_identity[32],const uint8_t executable_identity[32],
              const uint8_t cwd_identity[32],const uint8_t stdin_identity[32],
              const uint8_t pass_roster[32],Capture *out,Capture *err)
{
    uint8_t out_full[32],err_full[32],out_retained[32],err_retained[32];uint32_t rc=UINT32_MAX,signal_number=0;
    Sha256 out_copy=out->full_hash,err_copy=err->full_hash;
    sha256_final(&out_copy,out_full);sha256_final(&err_copy,err_full);
    sha256_bytes(out->data,out->size,out_retained);sha256_bytes(err->data,err->size,err_retained);
    if(WIFEXITED(wait_status))rc=(uint32_t)WEXITSTATUS(wait_status);else if(WIFSIGNALED(wait_status))signal_number=(uint32_t)WTERMSIG(wait_status);
    if(writer_u32(receipt,1U)<0||writer_u32(receipt,terminal_status)<0||writer_u32(receipt,rc)<0||writer_u32(receipt,signal_number)<0
       ||writer_u64(receipt,(uint64_t)child)<0||writer_u64(receipt,request->creator_pid)<0||writer_u64(receipt,request->creator_birth)<0
       ||writer_u32(receipt,CONTAINMENT_DEDICATED_PROCESS_GROUP_ONLY)<0
       ||writer_u32(receipt,(uint32_t)(extinct!=0))<0||writer_text(receipt,request->attempt)<0
       ||writer_bytes(receipt,request_digest,32)<0||writer_bytes(receipt,session,32)<0||writer_bytes(receipt,interpreter_sha,32)<0
       ||writer_bytes(receipt,executable_sha,32)<0||writer_bytes(receipt,interpreter_identity,32)<0
       ||writer_bytes(receipt,executable_identity,32)<0||writer_bytes(receipt,cwd_identity,32)<0||writer_bytes(receipt,stdin_identity,32)<0
       ||writer_bytes(receipt,pass_roster,32)<0||writer_bytes(receipt,out_full,32)<0||writer_bytes(receipt,out_retained,32)<0
       ||writer_bytes(receipt,err_full,32)<0||writer_bytes(receipt,err_retained,32)<0
       ||writer_u64(receipt,(uint64_t)out->observed)<0||writer_u32(receipt,(uint32_t)out->size)<0||writer_u32(receipt,(uint32_t)out->truncated)<0
       ||writer_bytes(receipt,out->data,out->size)<0||writer_u64(receipt,(uint64_t)err->observed)<0
       ||writer_u32(receipt,(uint32_t)err->size)<0||writer_u32(receipt,(uint32_t)err->truncated)<0
       ||writer_bytes(receipt,err->data,err->size)<0)return -1;
    return 0;
}

static int
parse_control_fd(int argc,char **argv)
{
    char *end=NULL;long value;
    if(argc!=3||strcmp(argv[1],"--control-fd")!=0)return -1;
    errno=0;value=strtol(argv[2],&end,10);if(errno!=0||end==argv[2]||*end!='\0'||value<3||value>INT_MAX)return -1;
    return (int)value;
}
#endif

#ifdef __linux__
#define PLAMEN_LINUX_BOOT_ID_TEXT_SIZE 36U
#define PLAMEN_LINUX_PROC_TEXT_MAX 16384U

static int
plamen_linux_equal(const uint8_t *left, const uint8_t *right, size_t size)
{
    uint8_t difference = 0;
    size_t index;
    for (index = 0; index < size; ++index) difference |= left[index] ^ right[index];
    return difference == 0;
}

static int
plamen_linux_connected_seqpacket(int descriptor)
{
    struct stat info;
    struct sockaddr_storage local, peer;
    socklen_t type_size = sizeof(int), local_size = sizeof(local),
        peer_size = sizeof(peer);
    int type = 0, flags;
    memset(&local, 0, sizeof(local));
    memset(&peer, 0, sizeof(peer));
    if (descriptor < 0 || fstat(descriptor, &info) != 0
        || !S_ISSOCK(info.st_mode)
        || getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &type, &type_size) != 0
        || type_size != sizeof(int) || type != SOCK_SEQPACKET
        || getsockname(descriptor, (struct sockaddr *)&local, &local_size) != 0
        || local_size < sizeof(sa_family_t) || local.ss_family != AF_UNIX
        || getpeername(descriptor, (struct sockaddr *)&peer, &peer_size) != 0
        || peer_size < sizeof(sa_family_t) || peer.ss_family != AF_UNIX
        || (flags = fcntl(descriptor, F_GETFD)) < 0
        || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0)
        return 0;
    return 1;
}

static int
plamen_linux_read_file_at(int directory, const char *name, uint8_t *out,
    size_t capacity, size_t *size)
{
    int descriptor = -1, result = -1;
    size_t offset = 0;
    ssize_t amount;
    if (out == NULL || capacity == 0 || size == NULL) return -1;
    *size = 0;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    for (;;) {
        if (offset == capacity) goto done;
        do {
            amount = read(descriptor, out + offset, capacity - offset);
        } while (amount < 0 && errno == EINTR);
        if (amount < 0) goto done;
        if (amount == 0) break;
        offset += (size_t)amount;
    }
    *size = offset;
    result = 0;
done:
    close(descriptor);
    return result;
}

static int
plamen_linux_decimal_fields(const char *start, const char *end,
    uint64_t values[4])
{
    unsigned index;
    const char *cursor = start;
    for (index = 0; index < 4; ++index) {
        char *after;
        unsigned long long value;
        while (cursor < end && (*cursor == ' ' || *cursor == '\t')) ++cursor;
        if (cursor == end || *cursor < '0' || *cursor > '9') return -1;
        errno = 0;
        value = strtoull(cursor, &after, 10);
        if (errno != 0 || after == cursor || after > end) return -1;
        values[index] = (uint64_t)value;
        cursor = after;
    }
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) ++cursor;
    return cursor == end ? 0 : -1;
}

static int
plamen_linux_status_ids(int process_directory, const struct ucred *credential)
{
    uint8_t raw[PLAMEN_LINUX_PROC_TEXT_MAX];
    size_t size = 0, offset = 0;
    int uid_seen = 0, gid_seen = 0;
    if (credential == NULL
        || plamen_linux_read_file_at(process_directory, "status", raw,
            sizeof(raw), &size) != 0 || size == sizeof(raw))
        return -1;
    while (offset < size) {
        size_t end = offset;
        uint64_t fields[4];
        while (end < size && raw[end] != '\n') ++end;
        if (end - offset >= 4 && memcmp(raw + offset, "Uid:", 4) == 0) {
            if (uid_seen || plamen_linux_decimal_fields(
                    (const char *)raw + offset + 4, (const char *)raw + end,
                    fields) != 0
                || fields[0] != (uint64_t)credential->uid
                || fields[1] != fields[0] || fields[2] != fields[0]
                || fields[3] != fields[0])
                return -1;
            uid_seen = 1;
        } else if (end - offset >= 4 && memcmp(raw + offset, "Gid:", 4) == 0) {
            if (gid_seen || plamen_linux_decimal_fields(
                    (const char *)raw + offset + 4, (const char *)raw + end,
                    fields) != 0
                || fields[0] != (uint64_t)credential->gid
                || fields[1] != fields[0] || fields[2] != fields[0]
                || fields[3] != fields[0])
                return -1;
            gid_seen = 1;
        }
        offset = end < size ? end + 1 : end;
    }
    return uid_seen && gid_seen ? 0 : -1;
}

static int
plamen_linux_start_ticks(int process_directory, pid_t expected_pid,
    uint64_t *start_ticks)
{
    uint8_t raw[PLAMEN_LINUX_PROC_TEXT_MAX];
    char *cursor, *end, *close_paren, *after;
    size_t size = 0;
    long parsed_pid;
    unsigned field;
    if (start_ticks == NULL
        || plamen_linux_read_file_at(process_directory, "stat", raw,
            sizeof(raw) - 1, &size) != 0 || size == 0
        || size == sizeof(raw) - 1)
        return -1;
    raw[size] = '\0';
    cursor = (char *)raw;
    errno = 0;
    parsed_pid = strtol(cursor, &after, 10);
    if (errno != 0 || parsed_pid != (long)expected_pid || after == cursor
        || *after != ' ') return -1;
    close_paren = strrchr(after + 1, ')');
    if (close_paren == NULL || close_paren[1] != ' '
        || close_paren[2] == '\0' || close_paren[3] != ' ')
        return -1;
    cursor = close_paren + 4;
    end = (char *)raw + size;
    for (field = 4; field <= 22; ++field) {
        unsigned long long value;
        while (cursor < end && *cursor == ' ') ++cursor;
        if (cursor == end) return -1;
        errno = 0;
        value = strtoull(cursor, &after, 10);
        if (errno != 0 || after == cursor || after > end
            || (after < end && *after != ' ' && *after != '\n'))
            return -1;
        if (field == 22) {
            if (value == 0) return -1;
            *start_ticks = (uint64_t)value;
            return 0;
        }
        cursor = after;
    }
    return -1;
}

static int
plamen_linux_boot_digest(int proc_root, uint8_t digest[32])
{
    uint8_t raw[PLAMEN_LINUX_BOOT_ID_TEXT_SIZE + 2];
    size_t size = 0, index;
    if (plamen_linux_read_file_at(proc_root, "sys/kernel/random/boot_id", raw,
            sizeof(raw), &size) != 0
        || size != PLAMEN_LINUX_BOOT_ID_TEXT_SIZE + 1
        || raw[PLAMEN_LINUX_BOOT_ID_TEXT_SIZE] != '\n')
        return -1;
    for (index = 0; index < PLAMEN_LINUX_BOOT_ID_TEXT_SIZE; ++index) {
        int hyphen = index == 8 || index == 13 || index == 18 || index == 23;
        if (hyphen ? raw[index] != '-'
                   : !((raw[index] >= '0' && raw[index] <= '9')
                        || (raw[index] >= 'a' && raw[index] <= 'f')))
            return -1;
    }
    return plamen_broker_v2_sha256(raw, PLAMEN_LINUX_BOOT_ID_TEXT_SIZE,
        digest) == 0 ? 0 : -1;
}

static int
plamen_linux_pidfd_open(pid_t pid)
{
#ifdef SYS_pidfd_open
    int descriptor = (int)syscall(SYS_pidfd_open, pid, 0U);
    int flags;
    if (descriptor < 0 || (flags = fcntl(descriptor, F_GETFD)) < 0
        || fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != 0) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    return descriptor;
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

static int
plamen_linux_pidfd_alive(int descriptor)
{
    struct pollfd item;
    int result;
    memset(&item, 0, sizeof(item));
    item.fd = descriptor;
    item.events = POLLIN;
    do { result = poll(&item, 1, 0); } while (result < 0 && errno == EINTR);
    return result == 0 && item.revents == 0 ? 0 : -1;
}

int
plamen_broker_v2_linux_peer_admit(int connected_socket_fd,
    const uint8_t expected_executable_identity[32],
    struct plamen_broker_v2_peer_identity *identity, int *pidfd_out)
{
    struct plamen_broker_v2_peer_identity candidate;
    struct statfs filesystem;
    struct stat executable_info;
    struct ucred first, second;
    socklen_t credential_size;
    char process_name[32];
    uint8_t executable_identity[32], second_boot[32];
    uint64_t second_start = 0;
    long ticks;
    int proc_root = -1, process_directory = -1, executable = -1, pidfd = -1;
    int result = PLAMEN_BROKER_V2_AUTH_FAILED;
    if (identity != NULL) memset(identity, 0, sizeof(*identity));
    if (pidfd_out != NULL) *pidfd_out = -1;
    memset(&candidate, 0, sizeof(candidate));
    memset(&first, 0, sizeof(first));
    memset(&second, 0, sizeof(second));
    if (expected_executable_identity == NULL || identity == NULL
        || pidfd_out == NULL
        || !plamen_linux_connected_seqpacket(connected_socket_fd))
        return PLAMEN_BROKER_V2_INVALID;
    credential_size = sizeof(first);
    if (getsockopt(connected_socket_fd, SOL_SOCKET, SO_PEERCRED, &first,
            &credential_size) != 0 || credential_size != sizeof(first)
        || first.pid <= 1 || first.uid != geteuid())
        goto done;
    if (snprintf(process_name, sizeof(process_name), "%ld", (long)first.pid) <= 0)
        goto done;
    proc_root = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (proc_root < 0 || fstatfs(proc_root, &filesystem) != 0
        || (unsigned long)filesystem.f_type != (unsigned long)PROC_SUPER_MAGIC)
        goto done;
    process_directory = openat(proc_root, process_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (process_directory < 0
        || plamen_linux_status_ids(process_directory, &first) != 0
        || plamen_linux_start_ticks(process_directory, first.pid,
            &candidate.birth_primary) != 0
        || plamen_linux_boot_digest(proc_root, candidate.boot_id_sha256) != 0)
        goto done;
    ticks = sysconf(_SC_CLK_TCK);
    if (ticks <= 0) goto done;
    candidate.pid = (uint64_t)first.pid;
    candidate.uid = (uint64_t)first.uid;
    candidate.gid = (uint64_t)first.gid;
    candidate.birth_kind = PLAMEN_BROKER_V2_BIRTH_LINUX_BOOT_TICKS;
    candidate.birth_secondary = (uint64_t)ticks;
    pidfd = plamen_linux_pidfd_open(first.pid);
    if (pidfd < 0 || plamen_linux_pidfd_alive(pidfd) != 0) goto done;
    executable = openat(process_directory, "exe", O_RDONLY | O_CLOEXEC);
    if (executable < 0 || fstat(executable, &executable_info) != 0
        || !S_ISREG(executable_info.st_mode)
        || (executable_info.st_mode & 0111) == 0
        || plamen_broker_v2_fd_identity(executable, executable_identity) != 0
        || !plamen_linux_equal(executable_identity,
            expected_executable_identity, 32))
        goto done;
    credential_size = sizeof(second);
    if (getsockopt(connected_socket_fd, SOL_SOCKET, SO_PEERCRED, &second,
            &credential_size) != 0 || credential_size != sizeof(second)
        || second.pid != first.pid || second.uid != first.uid
        || second.gid != first.gid
        || plamen_linux_status_ids(process_directory, &second) != 0
        || plamen_linux_start_ticks(process_directory, second.pid,
            &second_start) != 0 || second_start != candidate.birth_primary
        || plamen_linux_boot_digest(proc_root, second_boot) != 0
        || !plamen_linux_equal(second_boot, candidate.boot_id_sha256, 32)
        || plamen_linux_pidfd_alive(pidfd) != 0)
        goto done;
    *identity = candidate;
    *pidfd_out = pidfd;
    pidfd = -1;
    result = PLAMEN_BROKER_V2_OK;
done:
    if (pidfd >= 0) close(pidfd);
    if (executable >= 0) close(executable);
    if (process_directory >= 0) close(process_directory);
    if (proc_root >= 0) close(proc_root);
    plamen_broker_v2_secure_zero(executable_identity,
        sizeof(executable_identity));
    plamen_broker_v2_secure_zero(second_boot, sizeof(second_boot));
    if (result != PLAMEN_BROKER_V2_OK) {
        memset(identity, 0, sizeof(*identity));
        *pidfd_out = -1;
    }
    return result;
}

int
plamen_broker_v2_linux_projection_fd_validate(int projection_fd,
    const struct plamen_broker_v2_service_registration *registration)
{
    struct stat info;
    struct plamen_broker_v2_commitment decoded_commitment;
    uint8_t *projection = NULL;
    size_t offset = 0;
    ssize_t amount;
    int access, seals, result = PLAMEN_BROKER_V2_FD_INVALID;
    uint32_t expected_size;
    memset(&decoded_commitment, 0, sizeof(decoded_commitment));
    if (projection_fd < 0 || registration == NULL
        || (expected_size = registration->request_projection_size) == 0
        || expected_size > PLAMEN_BROKER_V2_REQUEST_PROJECTION_MAX
        || fstat(projection_fd, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_size != (off_t)expected_size
        || (access = fcntl(projection_fd, F_GETFL)) < 0
        || (access & O_ACCMODE) != O_RDONLY
        || (seals = fcntl(projection_fd, F_GET_SEALS)) < 0
        || (seals & (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE))
            != (F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE))
        return PLAMEN_BROKER_V2_FD_INVALID;
    projection = malloc(expected_size);
    if (projection == NULL) return PLAMEN_BROKER_V2_NOMEM;
    while (offset < expected_size) {
        do {
            amount = pread(projection_fd, projection + offset,
                expected_size - offset, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) goto done;
        offset += (size_t)amount;
    }
    do { amount = pread(projection_fd, projection, 1, (off_t)expected_size); }
    while (amount < 0 && errno == EINTR);
    if (amount != 0) goto done;
    result = plamen_broker_v2_request_projection_validate_exact(projection,
        expected_size, registration->request_projection_sha256,
        registration->commitment, registration->commitment_size,
        registration->commitment_sha256, &decoded_commitment);
done:
    plamen_broker_v2_secure_zero(&decoded_commitment,
        sizeof(decoded_commitment));
    plamen_broker_v2_secure_zero(projection, expected_size);
    free(projection);
    return result;
}

int
plamen_broker_v2_linux_service_send_owned(int connected_socket_fd,
    const uint8_t *envelope, size_t envelope_size,
    int fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS], size_t fd_count)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(int) * PLAMEN_BROKER_V2_SERVICE_MAX_FDS)];
    } control;
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *header;
    ssize_t amount;
    size_t close_count = fd_count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS
        ? PLAMEN_BROKER_V2_SERVICE_MAX_FDS : fd_count;
    int result = PLAMEN_BROKER_V2_SYSTEM;
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    if (envelope == NULL
        || envelope_size < PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE
        || envelope_size > PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX
        || fd_count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS
        || (fd_count != 0 && fds == NULL)
        || !plamen_linux_connected_seqpacket(connected_socket_fd)) {
        result = PLAMEN_BROKER_V2_INVALID;
        goto done;
    }
    vector.iov_base = (void *)(uintptr_t)envelope;
    vector.iov_len = envelope_size;
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    if (fd_count != 0) {
        size_t index;
        for (index = 0; index < fd_count; ++index)
            if (fds[index] < 0) { result = PLAMEN_BROKER_V2_FD_INVALID; goto done; }
        message.msg_control = control.bytes;
        message.msg_controllen = CMSG_SPACE(sizeof(int) * fd_count);
        header = CMSG_FIRSTHDR(&message);
        if (header == NULL) { result = PLAMEN_BROKER_V2_SYSTEM; goto done; }
        header->cmsg_level = SOL_SOCKET;
        header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int) * fd_count);
        memcpy(CMSG_DATA(header), fds, sizeof(int) * fd_count);
    }
    do { amount = sendmsg(connected_socket_fd, &message, MSG_NOSIGNAL); }
    while (amount < 0 && errno == EINTR);
    result = amount == (ssize_t)envelope_size
        ? PLAMEN_BROKER_V2_OK : PLAMEN_BROKER_V2_SYSTEM;
done:
    if (fds != NULL) plamen_broker_v2_close_fds(fds, close_count);
    return result;
}

int
plamen_broker_v2_linux_service_receive(int connected_socket_fd,
    uint8_t local_role, uint8_t **envelope, size_t *envelope_size,
    int fds[PLAMEN_BROKER_V2_SERVICE_MAX_FDS], size_t *fd_count,
    struct plamen_broker_v2_service_envelope_view *view)
{
    union {
        struct cmsghdr alignment;
        uint8_t bytes[CMSG_SPACE(sizeof(struct ucred))
            + CMSG_SPACE(sizeof(int) * (PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1))];
    } control;
    uint8_t packet[PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX + 1];
    struct msghdr message;
    struct iovec vector;
    struct cmsghdr *header;
    struct ucred socket_credential, packet_credential;
    socklen_t credential_size = sizeof(socket_credential);
    int received[PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1] = {-1, -1, -1};
    size_t received_count = 0, index;
    int credential_seen = 0, rights_seen = 0, passcred = 1;
    ssize_t amount, trailing;
    int result = PLAMEN_BROKER_V2_INVALID;
    if (envelope != NULL) *envelope = NULL;
    if (envelope_size != NULL) *envelope_size = 0;
    if (fd_count != NULL) *fd_count = 0;
    if (view != NULL) memset(view, 0, sizeof(*view));
    if (fds != NULL)
        for (index = 0; index < PLAMEN_BROKER_V2_SERVICE_MAX_FDS; ++index)
            fds[index] = -1;
    if (envelope == NULL || envelope_size == NULL || fds == NULL
        || fd_count == NULL || view == NULL
        || !plamen_linux_connected_seqpacket(connected_socket_fd)
        || setsockopt(connected_socket_fd, SOL_SOCKET, SO_PASSCRED, &passcred,
            sizeof(passcred)) != 0
        || getsockopt(connected_socket_fd, SOL_SOCKET, SO_PEERCRED,
            &socket_credential, &credential_size) != 0
        || credential_size != sizeof(socket_credential)
        || socket_credential.pid <= 1 || socket_credential.uid != geteuid())
        return PLAMEN_BROKER_V2_AUTH_FAILED;
    memset(&message, 0, sizeof(message));
    memset(&control, 0, sizeof(control));
    memset(&packet_credential, 0, sizeof(packet_credential));
    vector.iov_base = packet;
    vector.iov_len = sizeof(packet);
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.bytes;
    message.msg_controllen = sizeof(control.bytes);
    do {
        amount = recvmsg(connected_socket_fd, &message,
            MSG_CMSG_CLOEXEC | MSG_TRUNC);
    } while (amount < 0 && errno == EINTR);
    if (amount < (ssize_t)PLAMEN_BROKER_V2_SERVICE_HEADER_SIZE
        || amount > (ssize_t)PLAMEN_BROKER_V2_LINUX_SERVICE_PACKET_MAX
        || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
        goto done;
    for (header = CMSG_FIRSTHDR(&message); header != NULL;
            header = CMSG_NXTHDR(&message, header)) {
        if (header->cmsg_len < CMSG_LEN(0)) goto done;
        if (header->cmsg_level != SOL_SOCKET) goto done;
        if (header->cmsg_type == SCM_CREDENTIALS) {
            if (credential_seen || header->cmsg_len != CMSG_LEN(sizeof(struct ucred)))
                goto done;
            memcpy(&packet_credential, CMSG_DATA(header), sizeof(packet_credential));
            credential_seen = 1;
        } else if (header->cmsg_type == SCM_RIGHTS) {
            size_t bytes, count;
            if (rights_seen) goto done;
            rights_seen = 1;
            bytes = header->cmsg_len - CMSG_LEN(0);
            if (bytes == 0 || bytes % sizeof(int) != 0) goto done;
            count = bytes / sizeof(int);
            if (count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1) goto done;
            memcpy(received, CMSG_DATA(header), bytes);
            received_count = count;
        } else {
            goto done;
        }
    }
    if (!credential_seen || packet_credential.pid != socket_credential.pid
        || packet_credential.uid != socket_credential.uid
        || packet_credential.gid != socket_credential.gid
        || received_count > PLAMEN_BROKER_V2_SERVICE_MAX_FDS)
        goto done;
    *envelope = malloc((size_t)amount);
    if (*envelope == NULL) { result = PLAMEN_BROKER_V2_NOMEM; goto done; }
    memcpy(*envelope, packet, (size_t)amount);
    if (plamen_broker_v2_service_envelope_accept(local_role, *envelope,
            (size_t)amount, received_count, view) != 0)
        goto done;
    if (view->type == PLAMEN_BROKER_V2_SERVICE_REGISTER_INITIAL
        || view->type == PLAMEN_BROKER_V2_SERVICE_REGISTER_RECOVERY) {
        struct plamen_broker_v2_service_registration registration;
        if (received_count != 1
            || plamen_broker_v2_service_registration_decode(view->payload,
                view->payload_size, &registration) != 0
            || plamen_broker_v2_linux_projection_fd_validate(received[0],
                &registration) != 0) {
            plamen_broker_v2_secure_zero(&registration, sizeof(registration));
            goto done;
        }
        plamen_broker_v2_secure_zero(&registration, sizeof(registration));
    } else if (view->type == PLAMEN_BROKER_V2_SERVICE_SESSION_OPEN) {
        struct plamen_broker_v2_service_session_open open;
        if (received_count != 2
            || plamen_broker_v2_service_session_open_decode(view->payload,
                view->payload_size, &open) != 0
            || plamen_broker_v2_validate_received_fds(received, received_count,
                open.descriptors, 2) != 0) {
            plamen_broker_v2_secure_zero(&open, sizeof(open));
            received_count = 0;
            goto done;
        }
        plamen_broker_v2_secure_zero(&open, sizeof(open));
    } else if (received_count != 0) {
        goto done;
    }
    do { trailing = recv(connected_socket_fd, packet, 1, MSG_PEEK | MSG_DONTWAIT); }
    while (trailing < 0 && errno == EINTR);
    if (trailing > 0 || (trailing < 0 && errno != EAGAIN
            && errno != EWOULDBLOCK))
        goto done;
    for (index = 0; index < received_count; ++index) {
        fds[index] = received[index];
        received[index] = -1;
    }
    *fd_count = received_count;
    *envelope_size = (size_t)amount;
    result = PLAMEN_BROKER_V2_OK;
done:
    plamen_broker_v2_close_fds(received,
        PLAMEN_BROKER_V2_SERVICE_MAX_FDS + 1);
    plamen_broker_v2_secure_zero(packet, sizeof(packet));
    if (result != PLAMEN_BROKER_V2_OK) {
        if (*envelope != NULL) {
            plamen_broker_v2_secure_zero(*envelope, (size_t)(amount > 0 ? amount : 0));
            free(*envelope);
            *envelope = NULL;
        }
        *envelope_size = 0;
        *fd_count = 0;
        memset(view, 0, sizeof(*view));
    }
    return result;
}
#endif

#ifndef PLAMEN_NATIVE_BROKER_NO_MAIN
int
main(int argc,char **argv)
{
#ifndef PLAMEN_NATIVE_BROKER_DARWIN
    (void)argc;(void)argv;
#ifdef PLAMEN_NATIVE_BROKER_PRODUCTION_HARDSTOP
    fputs("PLAMEN_NATIVE_BROKER_HARDSTOP_NATIVE_V2_ADAPTER_REQUIRED\n",stderr);
#else
    fputs("PLAMEN_NATIVE_BROKER_HARDSTOP_UNSUPPORTED_POSIX_AUTHORITY\n",stderr);
#endif
    return 78;
#else
    int control_fd=parse_control_fd(argc,argv),creator_lease_fd=-1,socket_type=0,fds[4+MAX_PASS_FDS];socklen_t socket_type_size=sizeof(socket_type);
    uint8_t session[32],key[32],hello[48],request_nonce[32],zero_digest[32]={0},*frame=NULL,request_digest[32],candidate_digest[32],ack_digest[32],commit_digest[32],interpreter_sha[32],interpreter_identity[32],executable_sha[32],executable_identity[32],cwd_identity[32],stdin_identity[32],pass_roster[32];
    size_t frame_size=0,fd_count=0;LaunchRequest request;pid_t peer_pid=0,child=0;uint64_t peer_birth=0;uint32_t index,terminal_status=0;
    Capture out={0},err={0};int wait_status=0,extinct=0,result=70;Writer roster={0},receipt={0};struct stat control_info;
    for(index=0;index<4+MAX_PASS_FDS;index++)fds[index]=-1;memset(&request,0,sizeof(request));
    if(control_fd<0||fstat(control_fd,&control_info)<0||!S_ISSOCK(control_info.st_mode)
       ||getsockopt(control_fd,SOL_SOCKET,SO_TYPE,&socket_type,&socket_type_size)<0||socket_type!=SOCK_STREAM
       ||set_cloexec(control_fd)<0||peer_pid_and_birth(control_fd,&peer_pid,&peer_birth)<0)goto done;
    creator_lease_fd=creator_lease_open(peer_pid);if(creator_lease_fd<0)goto done;
    if(getentropy(session,sizeof(session))<0||getentropy(key,sizeof(key))<0)goto done;
    memcpy(hello,key,sizeof(key));put_u64(hello+32,(uint64_t)peer_pid);put_u64(hello+40,peer_birth);
    if(send_frame(control_fd,FRAME_HELLO,0,0,session,key,zero_digest,zero_digest,
                  hello,sizeof(hello),0,creator_lease_fd,peer_pid,NULL)<0)goto done;
    if(receive_request(control_fd,&frame,&frame_size,fds,&fd_count)<0
       ||creator_lease_intact(creator_lease_fd,peer_pid)<0
       ||verify_request_frame(frame,frame_size,session,key)<0)goto done;
    memcpy(request_digest,frame+132,32);memcpy(request_nonce,frame+68,32);
    if(parse_request(frame+FRAME_HEADER_SIZE,frame_size-FRAME_HEADER_SIZE,&request)<0
       ||get_u16(frame+24)!=fd_count||fd_count!=4U+request.pass_count
       ||constant_equal(request_nonce,zero_digest,32)
       ||!constant_equal(frame+100,zero_digest,32)
       ||request.creator_pid!=(uint64_t)peer_pid||request.creator_birth!=peer_birth
       ||normalize_fds(fds,fd_count)<0||reject_fd_aliases(fds,fd_count)<0)goto done;
    if(admit_peer_interpreter(fds[0],peer_pid)<0
       ||identity_digest(fds[0],interpreter_identity,1,0)<0||!constant_equal(interpreter_identity,request.interpreter_sha,32)
       ||sha256_fd(fds[0],interpreter_sha)<0
       ||identity_digest(fds[1],executable_identity,1,0)<0||!constant_equal(executable_identity,request.executable_sha,32)
       ||sha256_fd(fds[1],executable_sha)<0
       ||identity_digest(fds[2],cwd_identity,0,1)<0||!constant_equal(cwd_identity,request.cwd_identity,32)
       ||identity_digest(fds[3],stdin_identity,1,0)<0||!constant_equal(stdin_identity,request.stdin_identity,32))goto done;
    for(index=0;index<request.pass_count;index++){
        uint8_t identity[32];if(identity_digest(fds[4+index],identity,0,0)<0||!constant_equal(identity,request.pass_identities[index],32)
           ||writer_u32(&roster,request.pass_targets[index])<0||writer_bytes(&roster,identity,32)<0)goto done;
    }
    sha256_bytes(roster.data,roster.size,pass_roster);
    if(capture_init(&out,request.stdout_limit)<0||capture_init(&err,request.stderr_limit)<0)goto done;
    if(creator_lease_intact(creator_lease_fd,peer_pid)<0)goto done;
    if(spawn_and_capture(&request,fds,&out,&err,&child,&wait_status,&terminal_status,&extinct,
                         executable_sha,creator_lease_fd,peer_pid)<0
       ||terminal_status==4U||creator_lease_intact(creator_lease_fd,peer_pid)<0)goto done;
    if(build_receipt(&receipt,&request,request_digest,session,child,wait_status,terminal_status,extinct,
                     interpreter_sha,executable_sha,interpreter_identity,executable_identity,
                     cwd_identity,stdin_identity,pass_roster,&out,&err)<0)goto done;
    close_many(fds,fd_count);fd_count=0;free(frame);frame=NULL;
    if(send_frame(control_fd,FRAME_RECEIPT_CANDIDATE,2,0,session,key,request_nonce,
                  request_digest,receipt.data,receipt.size,1,creator_lease_fd,
                  peer_pid,candidate_digest)<0)goto done;
    if(receive_request(control_fd,&frame,&frame_size,fds,&fd_count)<0||fd_count!=0
       ||creator_lease_intact(creator_lease_fd,peer_pid)<0
       ||verify_receipt_ack(frame,frame_size,FRAME_RECEIPT_ACK,3,session,key,
                             request_nonce,candidate_digest)<0)goto done;
    sha256_bytes(frame,frame_size,ack_digest);free(frame);frame=NULL;
    if(send_frame(control_fd,FRAME_RECEIPT,4,0,session,key,request_nonce,ack_digest,
                  candidate_digest,sizeof(candidate_digest),1,creator_lease_fd,
                  peer_pid,commit_digest)<0)goto done;
    if(receive_request(control_fd,&frame,&frame_size,fds,&fd_count)<0||fd_count!=0
       ||creator_lease_intact(creator_lease_fd,peer_pid)<0
       ||verify_receipt_ack(frame,frame_size,FRAME_RECEIPT_COMMIT_ACK,5,
                             session,key,request_nonce,commit_digest)<0
       ||creator_lease_intact(creator_lease_fd,peer_pid)<0)goto done;
    if(shutdown(control_fd,SHUT_RDWR)<0||creator_lease_intact(creator_lease_fd,peer_pid)<0)goto done;
    result=0;
done:
    memset(key,0,sizeof(key));if(creator_lease_fd>=0)close(creator_lease_fd);if(control_fd>=0)close(control_fd);close_many(fds,fd_count);free(frame);free_request(&request);
    free(roster.data);free(receipt.data);free(out.data);free(err.data);return result;
#endif
}
#endif
