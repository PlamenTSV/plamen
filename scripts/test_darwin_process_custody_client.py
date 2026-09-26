from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(
    sys.platform != "darwin", reason="Darwin XPC custody client only"
)

ROOT = Path(__file__).resolve().parents[1]


def test_frame_mapping_and_production_client_compile(tmp_path: Path) -> None:
    source = tmp_path / "mapping.c"
    source.write_text(
        r'''
#include "plamen_broker_v2_process_custody_client.h"
#include <stdio.h>
#include <string.h>
void plamen_broker_v2_process_custodian_terminal_dispose(
    struct plamen_broker_v2_process_custodian_terminal_receipt *value) {
    (void)value;
}
int main(void) {
    const uint16_t requests[] = {0x20,0x22,0x30,0x32,0x40};
    const uint16_t responses[] = {0x21,0x21,0x31,0x31,0x41};
    const char *operations[] = {"start","adopt","wait","recover","revoke"};
    for (unsigned i = 0; i < 5; ++i) {
        uint16_t response = 0; const char *operation = NULL;
        if (plamen_broker_v2_process_custody_client_frame_mapping(
                requests[i], &response, &operation) != 0
            || response != responses[i] || strcmp(operation, operations[i]) != 0)
            return 1;
    }
    { uint16_t response; const char *operation;
      if (plamen_broker_v2_process_custody_client_frame_mapping(
              0x50, &response, &operation) == 0) return 2; }
    puts("MAPPED=5"); return 0;
}
'''
    )
    output = tmp_path / "mapping"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"), str(source),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_client.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(output),
        ],
        check=True, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    completed = subprocess.run(
        [str(output)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    assert completed.stdout == "MAPPED=5\n"


HARNESS = r'''
#include "plamen_broker_v2_process_custody_client.h"
#include "plamen_broker_v2_process_custody_daemon.h"
#include <CommonCrypto/CommonDigest.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct plamen_broker_v2_process { int state; };
static int starts, waits, tamper_reply, have_session, session_rotations;
static int exact_process_spec_seen;
static uint8_t last_session[32];
int plamen_broker_v2_process_prepare(const struct plamen_broker_v2_process_spec *s,
    struct plamen_broker_v2_process_prepared_identity *i,
    struct plamen_broker_v2_process **p) {
    size_t index;
    if (!s || s->environment_policy != PLAMEN_BROKER_V2_PROCESS_ENV_EXACT
        || s->environment_count != 1 || !s->environment
        || strcmp(s->environment[0],"ONLY=value") != 0
        || s->fd_map_count != PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX
        || !s->fd_maps) return 4;
    for(index=0;index<s->fd_map_count;++index)
        if(s->fd_maps[index].source_fd<0
            ||(fcntl(s->fd_maps[index].source_fd,F_GETFD)&FD_CLOEXEC)==0
            ||s->fd_maps[index].target_fd!=(int)(20+index)) return 4;
    exact_process_spec_seen=1;
    memset(i,0,sizeof(*i)); i->version=1; *p=calloc(1,sizeof(**p));
    if (!*p) return 4; (*p)->state=1; return 0;
}
int plamen_broker_v2_process_start(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_start_identity *i) {
    if (!p || p->state != 1) return 4; ++starts; p->state=2;
    memset(i,0,sizeof(*i)); i->version=1; i->child_pid=7171;
    i->process_group_id=7171; i->child_birth_us=88;
    memset(i->executable_sha256,1,32); memset(i->executable_identity_sha256,2,32);
    memset(i->native_process_handle_sha256,3,32); memset(i->cdhash,4,20);
    i->cdhash_size=20; strcpy(i->signing_identifier,"test.helper");
    strcpy(i->team_identifier,"TEAM"); return 0;
}
int plamen_broker_v2_process_wait(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t) {
    if (!p || (p->state != 2 && p->state != 3)) return 4;
    if (p->state == 2) { ++waits; p->state=3; }
    memset(t,0,sizeof(*t)); t->version=1; t->exit_code=7;
    t->child_pid=7171; t->process_group_id=7171; t->child_birth_us=88;
    CC_SHA256(NULL,0,t->stdout_sha256); CC_SHA256(NULL,0,t->stderr_sha256);
    t->child_reaped=1; t->process_group_extinct=1; return 0;
}
int plamen_broker_v2_process_extinguish(struct plamen_broker_v2_process *p,
    struct plamen_broker_v2_process_terminal *t) {
    return plamen_broker_v2_process_wait(p,t);
}
int plamen_broker_v2_process_read_output(struct plamen_broker_v2_process *p,
    uint32_t stream,uint64_t offset,uint32_t maximum,uint8_t *output,
    uint32_t capacity,uint32_t *size,uint8_t *eof,uint8_t chunk[32],
    uint8_t full[32],uint64_t *full_size) {
    (void)p;(void)stream;(void)offset;(void)maximum;(void)output;(void)capacity;
    *size=0;*eof=1;CC_SHA256(NULL,0,chunk);CC_SHA256(NULL,0,full);*full_size=0;return 0;
}
int plamen_broker_v2_process_close(struct plamen_broker_v2_process *p) {
    if (!p || p->state != 3) return 4; free(p); return 0;
}
static void fill(uint8_t out[32], uint8_t byte) { memset(out,byte,32); }
static void requests(int executable,int cwd,int input,
    struct plamen_broker_v2_process_spec *spec,
    struct plamen_broker_v2_process_custodian_start_request *start,
    struct plamen_broker_v2_process_custodian_start_recovery_request *adopt) {
    static const char *argv[]={"/fake","run",NULL};
    static const char *environment[]={"ONLY=value",NULL};
    static uint8_t sha[32];
    memset(spec,0,sizeof(*spec));spec->version=1;spec->executable_fd=executable;
    spec->executable_path="/fake";spec->argv=argv;spec->argc=2;
    spec->environment_policy=PLAMEN_BROKER_V2_PROCESS_ENV_EXACT;
    spec->environment=environment;spec->environment_count=1;
    spec->cwd_fd=cwd;spec->stdin_fd=input;spec->timeout_seconds=30;
    spec->stdout_spool_limit=64;spec->stderr_spool_limit=64;fill(sha,9);
    spec->expected_executable_sha256=sha;spec->expected_signing_identifier="test.helper";
    spec->expected_team_identifier="TEAM";memset(start,0,sizeof(*start));start->version=1;
    fill(start->operation_key,0x11);fill(start->request_sha256,0x12);
    fill(start->prior_checkpoint_sha256,0x13);fill(start->claim_owner_sha256,0x14);
    start->process_spec=spec;memset(adopt,0,sizeof(*adopt));adopt->version=1;
    memcpy(adopt->operation_key,start->operation_key,32);
    memcpy(adopt->request_sha256,start->request_sha256,32);
    memcpy(adopt->prior_checkpoint_sha256,start->prior_checkpoint_sha256,32);
    memcpy(adopt->claim_owner_sha256,start->claim_owner_sha256,32);
}
int main(int argc,char **argv) {
    struct plamen_broker_v2_process_custodian *custodian=NULL;
    struct plamen_broker_v2_custody_daemon_readiness readiness, wrong;
    xpc_connection_t listener; xpc_endpoint_t endpoint; dispatch_queue_t queue;
    struct plamen_broker_v2_process_fd_map descriptor_maps[
        PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX];
    int descriptors[PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX][2];
    int state, executable, cwd, input; pid_t broker; size_t descriptor_index;
    struct plamen_broker_v2_process_custodian_start_receipt started;
    if (argc != 2) return 64; state=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    executable=open(argv[0],O_RDONLY|O_CLOEXEC);cwd=open(".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    input=open("/dev/null",O_RDONLY|O_CLOEXEC);
    for(descriptor_index=0;
        descriptor_index<PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX;
        ++descriptor_index){
        if(pipe(descriptors[descriptor_index])!=0)return 65;
        descriptor_maps[descriptor_index].source_fd=descriptors[descriptor_index][0];
        descriptor_maps[descriptor_index].target_fd=(int)(20+descriptor_index);
    }
    if (state<0||executable<0||cwd<0||input<0
        ||plamen_broker_v2_process_custodian_open(state,&custodian)!=0) return 65;
    memset(&readiness,0,sizeof(readiness));
    fill(readiness.installation_receipt_sha256,0xa1);
    fill(readiness.generation_id_sha256,0xa2);fill(readiness.service_sha256,0xa3);
    queue=dispatch_queue_create("test.custody",DISPATCH_QUEUE_CONCURRENT);
    listener=xpc_connection_create(NULL,queue);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t event) {
        if (xpc_get_type(event) != XPC_TYPE_CONNECTION) return;
        xpc_connection_t peer=(xpc_connection_t)event;
        xpc_connection_set_event_handler(peer, ^(xpc_object_t message) {
            xpc_object_t plain=NULL,reply,session;
            const void *session_bytes; size_t session_size;
            session=xpc_dictionary_get_value(message,"broker_session_id");
            session_size=session == NULL ? 0 : xpc_data_get_length(session);
            session_bytes=session == NULL ? NULL : xpc_data_get_bytes_ptr(session);
            if(session_size==32&&session_bytes!=NULL){
                if(have_session&&!memcmp(last_session,session_bytes,32)){}
                else {if(have_session)++session_rotations;memcpy(last_session,session_bytes,32);have_session=1;}
            }
            if (plamen_broker_v2_process_custody_daemon_TEST_ONLY_dispatch_readiness(
                    custodian,&readiness,message,&plain)!=0) return;
            reply=xpc_dictionary_create_reply(message);
            xpc_dictionary_apply(plain,^bool(const char *key,xpc_object_t value){
                xpc_dictionary_set_value(reply,key,value);return true;});
            if(tamper_reply){uint8_t wrong[32];memset(wrong,0xee,32);
                xpc_dictionary_set_data(reply,"broker_session_id",wrong,32);tamper_reply=0;}
            xpc_connection_send_message(peer,reply);xpc_release(reply);xpc_release(plain);
        }); xpc_connection_activate(peer);
    });
    xpc_connection_activate(listener);endpoint=xpc_endpoint_create(listener);
    if (!endpoint) return 66;
    struct plamen_broker_v2_process_custody_client *client=NULL;
    struct plamen_broker_v2_process_spec spec;
    struct plamen_broker_v2_process_custodian_start_request start;
    struct plamen_broker_v2_process_custodian_start_recovery_request adopt;
    struct plamen_broker_v2_process_custodian_start_receipt adopted;
    struct plamen_broker_v2_process_custodian_terminal_request terminal;
    struct plamen_broker_v2_process_custodian_terminal_receipt exited;
    struct plamen_broker_v2_process_custodian_terminal_receipt recovered;
    uint32_t dsready=99,dswrong=99,dsready2=99,dsoverflow=99,ds0=99,dsreplay=99;
    uint32_t dsconflict=99,ds1=99,ds2=99,ds3=99,ds4=99;
    requests(executable,cwd,input,&spec,&start,&adopt);
    spec.fd_maps=descriptor_maps;
    spec.fd_map_count=PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX;
    int s=plamen_broker_v2_process_custody_client_TEST_ONLY_open_endpoint(endpoint,&client);
    if(s==0)s=plamen_broker_v2_process_custody_client_readiness(client,&readiness,&dsready);
    wrong=readiness;wrong.service_sha256[0]^=1;
    int wrong_result=s==0?plamen_broker_v2_process_custody_client_readiness(
        client,&wrong,&dswrong):99;
    int ready_again=plamen_broker_v2_process_custody_client_readiness(
        client,&readiness,&dsready2);
    struct plamen_broker_v2_process_custodian_start_receipt overflowed;
    spec.fd_map_count=PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX+1U;
    int overflow=plamen_broker_v2_process_custody_client_start(
        client,&start,&overflowed,&dsoverflow);
    spec.fd_map_count=PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX;
    if(s==0)s=plamen_broker_v2_process_custody_client_start(client,&start,&started,&ds0);
    struct plamen_broker_v2_process_custodian_start_receipt replayed,conflicted;
    int replay=s==0?plamen_broker_v2_process_custody_client_start(
        client,&start,&replayed,&dsreplay):99;
    descriptor_maps[0].target_fd=35;
    int conflict=replay==0?plamen_broker_v2_process_custody_client_start(
        client,&start,&conflicted,&dsconflict):99;
    plamen_broker_v2_process_custody_client_close(client);client=NULL;
    for(descriptor_index=0;
        descriptor_index<PLAMEN_BROKER_V2_PROCESS_FD_MAP_MAX;
        ++descriptor_index){close(descriptors[descriptor_index][0]);close(descriptors[descriptor_index][1]);}
    if(overflow!=2||dsoverflow!=99||s!=0||ds0!=0||replay!=0||dsreplay!=1
        ||conflict!=0||dsconflict!=2
        ||!exact_process_spec_seen)return 67;
    /* A dead broker has no authority object left; the daemon-owned child does. */
    broker=fork();if(broker==0)_exit(0);if(broker<0)return 68;waitpid(broker,NULL,0);
    int a=plamen_broker_v2_process_custody_client_TEST_ONLY_open_endpoint(endpoint,&client);
    if(a==0)a=plamen_broker_v2_process_custody_client_adopt(client,&adopt,&adopted,&ds1);
    memset(&terminal,0,sizeof(terminal));terminal.version=1;
    memcpy(terminal.start_operation_key,start.operation_key,32);fill(terminal.operation_key,0x21);
    fill(terminal.request_sha256,0x22);memcpy(terminal.prior_checkpoint_sha256,
        started.started_checkpoint_sha256,32);memcpy(terminal.claim_owner_sha256,start.claim_owner_sha256,32);
    int w=a==0?plamen_broker_v2_process_custody_client_wait(client,&terminal,&exited,&ds2):99;
    tamper_reply=1;
    int t=plamen_broker_v2_process_custody_client_recover(client,&terminal,&recovered,&ds3);
    int r=plamen_broker_v2_process_custody_client_recover(client,&terminal,&recovered,&ds4);
    plamen_broker_v2_process_custodian_terminal_dispose(&exited);
    plamen_broker_v2_process_custodian_terminal_dispose(&recovered);
    plamen_broker_v2_process_custody_client_close(client);
    printf("READY=%d/%u WRONG=%d/%u READY2=%d/%u OVERFLOW=%d/%u START=%d/%u REPLAY=%d/%u CONFLICT=%d/%u EXACT=%d STARTS=%d WAITS=%d ADOPT=%d/%u WAIT=%d/%u TAMPER=%d/%u RECOVER=%d/%u ROTATIONS=%d\n",
        s==0?0:s,dsready,wrong_result,dswrong,ready_again,dsready2,
        overflow,dsoverflow,s,ds0,replay,dsreplay,conflict,dsconflict,exact_process_spec_seen,
        starts,waits,a,ds1,w,ds2,t,ds3,r,ds4,session_rotations);return 0;
}
'''


def test_forked_broker_death_reconnect_adopts_without_duplicate_spawn(
    tmp_path: Path,
) -> None:
    source = tmp_path / "harness.c"
    source.write_text(HARNESS)
    output = tmp_path / "harness"
    subprocess.run(
        [
            "/usr/bin/clang", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
            "-fblocks", "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
            "-I", str(ROOT / "native" / "include"),
            "-I", str(ROOT / "native" / "darwin"), str(source),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custodian.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_daemon.c"),
            str(ROOT / "native" / "darwin" / "plamen_broker_v2_process_custody_client.c"),
            str(ROOT / "native" / "posix" / "plamen_broker_v2_protocol.c"),
            "-framework", "Security", "-framework", "CoreFoundation",
            "-o", str(output),
        ], check=True, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    completed = subprocess.run(
        [str(output), str(state)], cwd=ROOT, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout == (
        "READY=0/0 WRONG=2/0 READY2=0/0 OVERFLOW=2/99 START=0/0 REPLAY=0/1 "
        "CONFLICT=0/2 EXACT=1 STARTS=1 WAITS=1 "
        "ADOPT=0/1 WAIT=0/0 TAMPER=2/4294967295 "
        "RECOVER=0/1 ROTATIONS=3\n"
    )
