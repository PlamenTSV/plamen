#define _DARWIN_C_SOURCE 1

#include "plamen_native_evm_static_acquisition_v1.h"
#include "plamen_native_operation4_helper_v1.h"

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include "plamen_native_evm_static_assets_v1.inc"

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

#define MEDUSA_ARCHIVE_SIZE 11948454ULL
#define MEDUSA_BUNDLE_SIZE 10584ULL
#define MEDUSA_PAYLOAD_SIZE 23748448ULL
#define SOLC_INDEX_SIZE 47730ULL
#define SOLC_PAYLOAD_SIZE 15434456ULL
#define INPUT_MAX (64ULL * 1024ULL * 1024ULL)

extern int32_t plamen_native_evm_medusa_sigstore_verify_v1(
    const uint8_t *, size_t, const uint8_t[32], uint64_t);
extern int32_t plamen_native_evm_solc_provider_verify_v1(
    const uint8_t *, size_t, const uint8_t[32], uint64_t);

struct retained_identity_v1 {
    dev_t device; ino_t inode; mode_t mode; uid_t uid; gid_t gid;
    nlink_t links; off_t size; struct timespec mtime; struct timespec ctime;
    uint8_t sha256[32];
};

struct role_spec_v1 {
    uint16_t role, validator;
    uint64_t payload_size, semantic_size, manifest_size;
    const char *schema, *version, *payload_hex, *policy_hex;
    const char *semantic_hex, *manifest_hex;
    const uint8_t *semantic, *manifest;
    const unsigned int *semantic_len, *manifest_len;
    const char *payload_leaf, *producer_leaf, *manifest_leaf;
};

static const uint8_t footer_magic[8] = {'P','L','M','O','P','4','R','1'};
static const char medusa_archive_hex[] =
    "ddfe1517ae9028ef9fc331b00f5a6a9d5406f3fcd11a715d60c6b6fb3e4546d3";
static const char medusa_bundle_hex[] =
    "e7a277b17588fe02425a0cf4656f36d98f39eea9d4a7b0548e6617184238efb6";
static const char medusa_payload_hex[] =
    "86e54c586e49e6bf9676f448218e10475afacb0a8bd5ca1aea234f66db7169d6";
static const char medusa_policy_hex[] =
    "4112703567b4c398207eaf09c75503840704be44b663a43e82fae42aa32a0208";
static const char medusa_semantic_hex[] =
    "208b814ab650db58fb326d58930ae5db47162905a938e6c3532d9d6ff18a7f97";
static const char medusa_manifest_hex[] =
    "3353512eebb22a052ba2e5a87c2fe86055381b729498df3299b4d36dedf09260";
static const char solc_index_hex[] =
    "ee1a2b4811bd1225c220cd2342e2b49a58cbe18f5687f230f456c443b29497d6";
static const char solc_payload_hex[] =
    "d5f23436f443edb85d8e76906d12f0a86ce0490e7663a9e608efeb7a93f149ef";
static const char solc_policy_hex[] =
    "f08a1ce15fc990a296f39bb8736cf31d55a1708201d4765e51752dcc86414d68";
static const char solc_semantic_hex[] =
    "9eebf95c0a0eceaf853f30419b9d71abde65c594dad0666619d86c022c9eb39c";
static const char solc_manifest_hex[] =
    "bb013be7af35e8df4ff900521a4859100af71a0b9c460777877768c5ddee8b9b";

static const struct role_spec_v1 role_specs[2] = {
    {PLAMEN_SOURCE_BOOTSTRAP_MEDUSA_V1,
     PLAMEN_NATIVE_OPERATION4_MEDUSA_RECEIPT_V1,
     MEDUSA_PAYLOAD_SIZE, 1237U, 555U,
     "plamen.medusa-acquisition-receipt.v1", "1.5.1",
     medusa_payload_hex, medusa_policy_hex, medusa_semantic_hex,
     medusa_manifest_hex,
     verification_policy_medusa_acquisition_receipt_v1_json,
     verification_policy_medusa_runtime_source_manifest_v1_json,
     &verification_policy_medusa_acquisition_receipt_v1_json_len,
     &verification_policy_medusa_runtime_source_manifest_v1_json_len,
     "08-medusa.payload", "08-medusa.producer-receipt",
     "08-medusa.source-manifest"},
    {PLAMEN_SOURCE_BOOTSTRAP_SOLC_AMD64_V1,
     PLAMEN_NATIVE_OPERATION4_SOLC_RECEIPT_V1,
     SOLC_PAYLOAD_SIZE, 1341U, 596U,
     "plamen.solc-amd64-acquisition-receipt.v1",
     "0.8.26+commit.8a97fa7a",
     solc_payload_hex, solc_policy_hex, solc_semantic_hex,
     solc_manifest_hex,
     verification_policy_solc_amd64_acquisition_receipt_v1_json,
     verification_policy_solc_amd64_runtime_source_manifest_v1_json,
     &verification_policy_solc_amd64_acquisition_receipt_v1_json_len,
     &verification_policy_solc_amd64_runtime_source_manifest_v1_json_len,
     "09-solc_amd64.payload", "09-solc_amd64.producer-receipt",
     "09-solc_amd64.source-manifest"}
};

static void store16(uint8_t *p, uint16_t v)
{ p[0]=(uint8_t)(v>>8U); p[1]=(uint8_t)v; }
static void store64(uint8_t *p, uint64_t v)
{ size_t i; for(i=0;i<8U;++i)p[i]=(uint8_t)(v>>(56U-8U*i)); }
static int constant_equal(const uint8_t *a,const uint8_t *b,size_t n)
{ uint8_t d=0;size_t i;for(i=0;i<n;++i)d|=(uint8_t)(a[i]^b[i]);return d==0U; }
static int all_zero(const uint8_t *p,size_t n)
{ uint8_t v=0;size_t i;for(i=0;i<n;++i)v|=p[i];return v==0U; }
static int hex32(const char *s,uint8_t out[32])
{
    size_t i;if(s==NULL||strlen(s)!=64U)return -1;
    for(i=0;i<32U;++i){unsigned int h,l;char a=s[2U*i],b=s[2U*i+1U];
        h=(a>='0'&&a<='9')?(unsigned)(a-'0'):(a>='a'&&a<='f')?(unsigned)(a-'a'+10):-1U;
        l=(b>='0'&&b<='9')?(unsigned)(b-'0'):(b>='a'&&b<='f')?(unsigned)(b-'a'+10):-1U;
        if(h>15U||l>15U)return -1;out[i]=(uint8_t)((h<<4U)|l);}
    return 0;
}

static int sha256_fd(int fd,uint64_t size,uint8_t out[32])
{
    CC_SHA256_CTX c;uint8_t buffer[1024U*1024U];uint64_t off=0;
    if(CC_SHA256_Init(&c)!=1)return -1;
    while(off<size){size_t want=size-off>sizeof(buffer)?sizeof(buffer):(size_t)(size-off);
        ssize_t got=pread(fd,buffer,want,(off_t)off);
        if(got!=(ssize_t)want||CC_SHA256_Update(&c,buffer,(CC_LONG)want)!=1){memset(&c,0,sizeof(c));memset(buffer,0,sizeof(buffer));return -1;}off+=want;}
    if(CC_SHA256_Final(out,&c)!=1){memset(&c,0,sizeof(c));memset(buffer,0,sizeof(buffer));return -1;}
    memset(&c,0,sizeof(c));memset(buffer,0,sizeof(buffer));return 0;
}
static int identity_fd(int fd,uid_t owner,int access,uint64_t size,
    const uint8_t digest[32],struct retained_identity_v1 *out)
{
    struct stat a,b;int fl,df;
    if(fd<3||out==NULL||(fl=fcntl(fd,F_GETFL))<0||(df=fcntl(fd,F_GETFD))<0
        ||(fl&O_ACCMODE)!=access||(df&FD_CLOEXEC)==0||fstat(fd,&a)!=0
        ||!S_ISREG(a.st_mode)||a.st_uid!=owner||a.st_nlink!=1
        ||(a.st_mode&0022U)!=0U||a.st_size<0||(uint64_t)a.st_size!=size
        ||sha256_fd(fd,size,out->sha256)!=0||!constant_equal(out->sha256,digest,32U)
        ||fstat(fd,&b)!=0||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino
        ||a.st_mode!=b.st_mode||a.st_uid!=b.st_uid||a.st_gid!=b.st_gid
        ||a.st_nlink!=b.st_nlink||a.st_size!=b.st_size
        ||a.st_mtimespec.tv_sec!=b.st_mtimespec.tv_sec
        ||a.st_mtimespec.tv_nsec!=b.st_mtimespec.tv_nsec
        ||a.st_ctimespec.tv_sec!=b.st_ctimespec.tv_sec
        ||a.st_ctimespec.tv_nsec!=b.st_ctimespec.tv_nsec){memset(out,0,sizeof(*out));errno=EINVAL;return -1;}
    out->device=a.st_dev;out->inode=a.st_ino;out->mode=a.st_mode;out->uid=a.st_uid;
    out->gid=a.st_gid;out->links=a.st_nlink;out->size=a.st_size;
    out->mtime=a.st_mtimespec;out->ctime=a.st_ctimespec;return 0;
}
static int same_identity(const struct retained_identity_v1 *a,
    const struct retained_identity_v1 *b)
{
    return a->device==b->device&&a->inode==b->inode&&a->mode==b->mode
        &&a->uid==b->uid&&a->gid==b->gid&&a->links==b->links&&a->size==b->size
        &&a->mtime.tv_sec==b->mtime.tv_sec&&a->mtime.tv_nsec==b->mtime.tv_nsec
        &&a->ctime.tv_sec==b->ctime.tv_sec&&a->ctime.tv_nsec==b->ctime.tv_nsec
        &&constant_equal(a->sha256,b->sha256,32U);
}
static int load_fd(int fd,uint64_t size,uint8_t **output)
{
    uint8_t *p;uint64_t off=0;if(output==NULL||size==0U||size>INPUT_MAX)return -1;
    p=(uint8_t *)malloc((size_t)size);if(p==NULL)return -1;
    while(off<size){size_t want=size-off>1024U*1024U?1024U*1024U:(size_t)(size-off);
        ssize_t got=pread(fd,p+off,want,(off_t)off);if(got!=(ssize_t)want){free(p);return -1;}off+=want;}
    *output=p;return 0;
}
static int write_all(int fd,const uint8_t *p,uint64_t size)
{
    uint64_t off=0;while(off<size){size_t want=size-off>1024U*1024U?1024U*1024U:(size_t)(size-off);
        ssize_t n=write(fd,p+off,want);if(n<=0)return -1;off+=(uint64_t)n;}return 0;
}
static int contains_fd(int fd,uint64_t size,const char *needle)
{
    uint8_t buffer[65536U+128U];uint64_t offset=0;size_t kept=0;
    size_t needle_size=strlen(needle);if(needle_size==0U||needle_size>128U)return 0;
    while(offset<size){size_t want=size-offset>65536U?65536U:(size_t)(size-offset),i;
        ssize_t amount=pread(fd,buffer+kept,want,(off_t)offset);if(amount!=(ssize_t)want)return 0;
        for(i=0;i+needle_size<=kept+want;++i)if(buffer[i]==(uint8_t)needle[0]
            &&memcmp(buffer+i,needle,needle_size)==0){memset(buffer,0,sizeof(buffer));return 1;}
        {size_t available=kept+want;kept=needle_size-1U;
            if(kept>available)kept=available;
            memmove(buffer,buffer+available-kept,kept);}offset+=want;
    }
    memset(buffer,0,sizeof(buffer));return 0;
}
static int elf_amd64_fd(int fd,int require_go)
{
    uint8_t h[24];if(pread(fd,h,sizeof(h),0)!=(ssize_t)sizeof(h)
        ||memcmp(h,"\177ELF",4U)!=0||h[4]!=2U||h[5]!=1U||h[6]!=1U
        ||h[18]!=0x3eU||h[19]!=0U)return 0;
    if(require_go&&(!contains_fd(fd,MEDUSA_PAYLOAD_SIZE,"github.com/crytic/medusa")
        ||!contains_fd(fd,MEDUSA_PAYLOAD_SIZE,"go1.25.7")))return 0;
    return 1;
}

static int root_directory(int fd,uid_t owner)
{
    struct stat s;int fl,df;
    return fd>=3&&(fl=fcntl(fd,F_GETFL))>=0&&(df=fcntl(fd,F_GETFD))>=0
        &&(fl&O_ACCMODE)==O_RDONLY&&(df&FD_CLOEXEC)!=0&&fstat(fd,&s)==0
        &&S_ISDIR(s.st_mode)&&s.st_uid==owner&&s.st_nlink>=1
        &&(s.st_mode&0077U)==0U;
}
static int open_authority_directory(int root,uid_t owner)
{
    const char *parts[3]={"share","plamen","native-source-authority-v1"};
    int current=fcntl(root,F_DUPFD_CLOEXEC,3),next=-1;size_t i;struct stat s;
    if(current<0)return -1;
    for(i=0;i<3U;++i){
        if(mkdirat(current,parts[i],0700)!=0&&errno!=EEXIST)goto fail;
        next=openat(current,parts[i],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if(next<0||fstat(next,&s)!=0||!S_ISDIR(s.st_mode)||s.st_uid!=owner
            ||s.st_nlink<1||(s.st_mode&0077U)!=0U)goto fail;
        close(current);current=next;next=-1;
    }
    return current;
fail:
    if(next>=0)close(next);close(current);return -1;
}

static int tar_octal(const uint8_t *p,size_t n,uint64_t *value)
{
    uint64_t v=0;size_t i=0;int any=0;
    while(i<n&&(p[i]==' '||p[i]=='\0'))++i;
    for(;i<n&&p[i]>='0'&&p[i]<='7';++i){if(v>(UINT64_MAX-(p[i]-'0'))/8U)return -1;v=v*8U+(p[i]-'0');any=1;}
    while(i<n&&(p[i]==' '||p[i]=='\0'))++i;
    if(!any||i!=n)return -1;*value=v;return 0;
}
static int tar_checksum(const uint8_t h[512])
{
    uint64_t expected,sum=0;size_t i;if(tar_octal(h+148U,8U,&expected)!=0)return 0;
    for(i=0;i<512U;++i)sum+=(i>=148U&&i<156U)?32U:h[i];return sum==expected;
}
static int block_zero(const uint8_t b[512])
{ uint8_t v=0;size_t i;for(i=0;i<512U;++i)v|=b[i];return v==0U; }
static int bytes_zero(const uint8_t *b,size_t n)
{ uint8_t v=0;size_t i;for(i=0;i<n;++i)v|=b[i];return v==0U; }
static int gz_exact(gzFile gz,uint8_t *p,unsigned int n)
{
    unsigned int off=0;while(off<n){int got=gzread(gz,p+off,n-off);if(got<=0)return -1;off+=(unsigned)got;}return 0;
}
static int extract_medusa(int archive_fd,int writer,
    uint8_t payload_sha[32])
{
    int dupfd=-1,result=-1;gzFile gz=NULL;uint8_t header[512],block[512];
    uint64_t size,remaining;CC_SHA256_CTX hash;int extra;
    dupfd=fcntl(archive_fd,F_DUPFD_CLOEXEC,3);if(dupfd<0)return -1;
    if(lseek(dupfd,0,SEEK_SET)<0)goto done;
    gz=gzdopen(dupfd,"rb");if(gz==NULL)goto done;dupfd=-1;
    if(gz_exact(gz,header,512U)!=0||!tar_checksum(header)
        ||memcmp(header,"medusa\0",7U)!=0||!bytes_zero(header+7U,93U)
        ||header[156U]!='0'
        ||tar_octal(header+124U,12U,&size)!=0||size!=MEDUSA_PAYLOAD_SIZE
        ||memcmp(header+257U,"ustar  \0",8U)!=0||CC_SHA256_Init(&hash)!=1)goto done;
    remaining=size;
    while(remaining>0U){unsigned int want=remaining>sizeof(block)?sizeof(block):(unsigned int)remaining;
        if(gz_exact(gz,block,512U)!=0||write_all(writer,block,want)!=0
            ||CC_SHA256_Update(&hash,block,(CC_LONG)want)!=1)goto done;
        remaining-=want;
    }
    if(gz_exact(gz,block,512U)!=0||!block_zero(block)
        ||gz_exact(gz,block,512U)!=0||!block_zero(block))goto done;
    while((extra=gzread(gz,block,sizeof(block)))>0){int aggregate=0;size_t i;
        for(i=0;i<(size_t)extra;++i)aggregate|=block[i];if(aggregate!=0)goto done;}
    if(extra!=0||!gzeof(gz)||CC_SHA256_Final(payload_sha,&hash)!=1)goto done;
    result=0;
done:
    memset(header,0,sizeof(header));memset(block,0,sizeof(block));memset(&hash,0,sizeof(hash));
    if(gz!=NULL){int z=gzclose(gz);if(z!=Z_OK)result=-1;}if(dupfd>=0)close(dupfd);return result;
}

static int validate_fixed_row(const struct role_spec_v1 *spec)
{
    const struct plamen_native_operation4_fixed_policy_v1 *policy=
        &plamen_native_operation4_generated_policy_v1;
    const struct plamen_native_operation4_policy_row_v1 *row;
    uint8_t p[32],s[32],m[32],d[32];size_t schema_size;
    if(policy->version!=1U||policy->role_count!=11U||all_zero(policy->roster_sha256,32U)
        ||spec->role>=11U||hex32(spec->payload_hex,p)!=0||hex32(spec->policy_hex,d)!=0
        ||hex32(spec->semantic_hex,s)!=0||hex32(spec->manifest_hex,m)!=0)return -1;
    row=&policy->rows[spec->role];schema_size=strlen(spec->schema);
    if(row->role!=spec->role||row->identity_mode!=PLAMEN_NATIVE_OPERATION4_STATIC_PAYLOAD_V1
        ||row->receipt_validator!=spec->validator||row->reserved!=0U
        ||row->payload_size!=spec->payload_size||row->semantic_receipt_size!=spec->semantic_size
        ||row->source_manifest_size!=spec->manifest_size
        ||!constant_equal(row->payload_sha256,p,32U)||!constant_equal(row->policy_sha256,d,32U)
        ||!constant_equal(row->semantic_receipt_sha256,s,32U)
        ||!constant_equal(row->source_manifest_sha256,m,32U)
        ||schema_size>=sizeof(row->receipt_schema)
        ||memcmp(row->receipt_schema,spec->schema,schema_size)!=0
        ||row->receipt_schema[schema_size]!='\0')return -1;
    return 0;
}
static void render_footer(const struct role_spec_v1 *spec,uint8_t footer[512])
{
    uint8_t p[32],policy[32],semantic[32],manifest[32];
    (void)hex32(spec->payload_hex,p);(void)hex32(spec->policy_hex,policy);
    (void)hex32(spec->semantic_hex,semantic);(void)hex32(spec->manifest_hex,manifest);
    memset(footer,0,512U);memcpy(footer,footer_magic,8U);store16(footer+8U,1U);
    store16(footer+10U,512U);store16(footer+12U,spec->role);
    store16(footer+14U,PLAMEN_NATIVE_OPERATION4_STATIC_PAYLOAD_V1);
    store16(footer+16U,spec->validator);store64(footer+20U,spec->payload_size);
    store64(footer+28U,spec->manifest_size);store64(footer+36U,spec->semantic_size);
    memcpy(footer+44U,policy,32U);memcpy(footer+76U,p,32U);
    memcpy(footer+108U,manifest,32U);memcpy(footer+140U,semantic,32U);
    memcpy(footer+172U,spec->schema,strlen(spec->schema));
    (void)CC_SHA256(footer,480U,footer+480U);
    memset(p,0,32U);memset(policy,0,32U);memset(semantic,0,32U);memset(manifest,0,32U);
}
static int create_leaf(int dir,const char *name)
{ return openat(dir,name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); }
static int publish_leaf(int dir,const char *name,int *writer,uid_t owner,
    uint64_t size,const uint8_t digest[32],int *reader,
    struct retained_identity_v1 *identity)
{
    struct retained_identity_v1 before,after;int result=-1;
    if(writer==NULL||*writer<0||fsync(*writer)!=0||fchmod(*writer,0400)!=0
        ||fsync(*writer)!=0||identity_fd(*writer,owner,O_RDWR,size,digest,&before)!=0)return -1;
    if(close(*writer)!=0){*writer=-1;return -1;}*writer=-1;
    *reader=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(*reader<0)return -1;
    if(identity_fd(*reader,owner,O_RDONLY,size,digest,&after)!=0
        ||!same_identity(&before,&after))goto done;
    *identity=after;result=0;
done:
    if(result!=0&&*reader>=0){close(*reader);*reader=-1;}return result;
}
static void projection_reset(struct plamen_native_evm_static_projection_v1 *p)
{
    size_t i;memset(p,0,sizeof(*p));for(i=0;i<2U;++i){p->roles[i].role=role_specs[i].role;
        p->roles[i].payload_fd=p->roles[i].producer_receipt_fd=p->roles[i].source_manifest_fd=-1;}
}

int plamen_native_evm_static_acquisition_issue_v1(uid_t owner,int root_fd,
    int medusa_archive_fd,int medusa_bundle_fd,int solc_index_fd,int solc_binary_fd,
    struct plamen_native_evm_static_projection_v1 *projection)
{
    struct retained_identity_v1 input_before[4],input_after[4];
    uint8_t archive_sha[32],medusa_sha[32],solc_sha[32];
    uint8_t expected[32],footer[512];uint8_t *bundle=NULL,*index=NULL;
    int dir=-1,writers[6]={-1,-1,-1,-1,-1,-1};int created=0,result=-1;
    size_t i;const int input_fds[4]={medusa_archive_fd,medusa_bundle_fd,solc_index_fd,solc_binary_fd};
    const uint64_t input_sizes[4]={MEDUSA_ARCHIVE_SIZE,MEDUSA_BUNDLE_SIZE,SOLC_INDEX_SIZE,SOLC_PAYLOAD_SIZE};
    const char *input_hex[4]={medusa_archive_hex,medusa_bundle_hex,solc_index_hex,solc_payload_hex};
    if(projection==NULL){errno=EINVAL;return -1;}projection_reset(projection);
    if(!root_directory(root_fd,owner))goto done;
    for(i=0;i<4U;++i){if(hex32(input_hex[i],expected)!=0
        ||identity_fd(input_fds[i],owner,O_RDONLY,input_sizes[i],expected,&input_before[i])!=0)goto done;}
    memcpy(archive_sha,input_before[0].sha256,32U);
    memcpy(solc_sha,input_before[3].sha256,32U);
    if(validate_fixed_row(&role_specs[0])!=0||validate_fixed_row(&role_specs[1])!=0
        ||load_fd(medusa_bundle_fd,MEDUSA_BUNDLE_SIZE,&bundle)!=0
        ||load_fd(solc_index_fd,SOLC_INDEX_SIZE,&index)!=0
        ||plamen_native_evm_medusa_sigstore_verify_v1(bundle,MEDUSA_BUNDLE_SIZE,
            archive_sha,MEDUSA_ARCHIVE_SIZE)!=0
        ||plamen_native_evm_solc_provider_verify_v1(index,SOLC_INDEX_SIZE,
            solc_sha,SOLC_PAYLOAD_SIZE)!=0)goto done;
    dir=open_authority_directory(root_fd,owner);if(dir<0)goto done;
    for(i=0;i<2U;++i){writers[i*3U]=create_leaf(dir,role_specs[i].payload_leaf);
        if(writers[i*3U]<0)goto done;created=(int)(i*3U+1U);
        writers[i*3U+1U]=create_leaf(dir,role_specs[i].producer_leaf);
        if(writers[i*3U+1U]<0)goto done;created=(int)(i*3U+2U);
        writers[i*3U+2U]=create_leaf(dir,role_specs[i].manifest_leaf);
        if(writers[i*3U+2U]<0)goto done;created=(int)(i*3U+3U);}
    if(extract_medusa(medusa_archive_fd,writers[0],medusa_sha)!=0
        ||hex32(medusa_payload_hex,expected)!=0||!constant_equal(medusa_sha,expected,32U)
        ||!elf_amd64_fd(writers[0],1))goto done;
    {
        uint8_t buffer[1024U*1024U];uint64_t off=0;
        while(off<SOLC_PAYLOAD_SIZE){size_t want=SOLC_PAYLOAD_SIZE-off>sizeof(buffer)?sizeof(buffer):(size_t)(SOLC_PAYLOAD_SIZE-off);
            ssize_t n=pread(solc_binary_fd,buffer,want,(off_t)off);if(n!=(ssize_t)want||write_all(writers[3],buffer,want)!=0){memset(buffer,0,sizeof(buffer));goto done;}off+=want;}
        memset(buffer,0,sizeof(buffer));
    }
    if(!elf_amd64_fd(writers[3],0))goto done;
    for(i=0;i<2U;++i){render_footer(&role_specs[i],footer);
        if(write_all(writers[i*3U+1U],role_specs[i].semantic,role_specs[i].semantic_size)!=0
            ||write_all(writers[i*3U+1U],footer,512U)!=0
            ||write_all(writers[i*3U+2U],role_specs[i].manifest,role_specs[i].manifest_size)!=0)goto done;}
    if(fsync(dir)!=0)goto done;
    for(i=0;i<2U;++i){struct plamen_native_evm_static_role_projection_v1 *out=&projection->roles[i];
        uint8_t pd[32],rd[32],md[32];struct retained_identity_v1 id;
        if(hex32(role_specs[i].payload_hex,pd)!=0||hex32(role_specs[i].manifest_hex,md)!=0)goto done;
        CC_SHA256_CTX hc;if(CC_SHA256_Init(&hc)!=1
            ||CC_SHA256_Update(&hc,role_specs[i].semantic,
                (CC_LONG)role_specs[i].semantic_size)!=1){memset(&hc,0,sizeof(hc));goto done;}
        render_footer(&role_specs[i],footer);if(CC_SHA256_Update(&hc,footer,512U)!=1||CC_SHA256_Final(rd,&hc)!=1){memset(&hc,0,sizeof(hc));goto done;}memset(&hc,0,sizeof(hc));
        if(publish_leaf(dir,role_specs[i].payload_leaf,&writers[i*3U],owner,role_specs[i].payload_size,pd,&out->payload_fd,&id)!=0)goto done;
        out->payload_size=role_specs[i].payload_size;memcpy(out->payload_sha256,pd,32U);
        if(publish_leaf(dir,role_specs[i].producer_leaf,&writers[i*3U+1U],owner,role_specs[i].semantic_size+512U,rd,&out->producer_receipt_fd,&id)!=0)goto done;
        out->producer_receipt_size=role_specs[i].semantic_size+512U;memcpy(out->producer_receipt_sha256,rd,32U);
        if(publish_leaf(dir,role_specs[i].manifest_leaf,&writers[i*3U+2U],owner,role_specs[i].manifest_size,md,&out->source_manifest_fd,&id)!=0)goto done;
        out->source_manifest_size=role_specs[i].manifest_size;memcpy(out->source_manifest_sha256,md,32U);
    }
    if(fsync(dir)!=0)goto done;
    for(i=0;i<4U;++i){uint8_t digest[32];if(hex32(input_hex[i],digest)!=0
        ||identity_fd(input_fds[i],owner,O_RDONLY,input_sizes[i],digest,&input_after[i])!=0
        ||!same_identity(&input_before[i],&input_after[i]))goto done;}
    result=0;
done:
    if(result!=0){plamen_native_evm_static_projection_dispose_v1(projection);
        if(dir>=0){for(i=0;i<(size_t)created;++i){const struct role_spec_v1 *s=&role_specs[i/3U];
            const char *n=(i%3U)==0U?s->payload_leaf:(i%3U)==1U?s->producer_leaf:s->manifest_leaf;
            (void)unlinkat(dir,n,0);} (void)fsync(dir);}}
    for(i=0;i<6U;++i)if(writers[i]>=0)close(writers[i]);if(dir>=0)close(dir);
    if(bundle!=NULL){memset(bundle,0,MEDUSA_BUNDLE_SIZE);free(bundle);}if(index!=NULL){memset(index,0,SOLC_INDEX_SIZE);free(index);}
    memset(footer,0,sizeof(footer));memset(expected,0,sizeof(expected));
    memset(archive_sha,0,32U);memset(medusa_sha,0,32U);
    memset(solc_sha,0,32U);return result;
}

void plamen_native_evm_static_projection_dispose_v1(
    struct plamen_native_evm_static_projection_v1 *projection)
{
    size_t i;if(projection==NULL)return;for(i=0;i<2U;++i){
        if(projection->roles[i].payload_fd>=0)close(projection->roles[i].payload_fd);
        if(projection->roles[i].producer_receipt_fd>=0)close(projection->roles[i].producer_receipt_fd);
        if(projection->roles[i].source_manifest_fd>=0)close(projection->roles[i].source_manifest_fd);}
    projection_reset(projection);
}
