#include "plamen_broker_v2.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int run_case(uint16_t lane, uint16_t method, uint16_t disposition,
    const uint8_t *payload, size_t payload_size, int accepted)
{
    struct plamen_broker_v2_specialized_response value, decoded;
    uint8_t wire[1024]; size_t wire_size = 0; int status;
    memset(&value, 0, sizeof(value)); memset(&decoded, 0, sizeof(decoded));
    value.lane = lane; value.method = method; value.disposition = disposition;
    memset(value.operation_nonce, 0x11, 32); memset(value.request_sha256, 0x22, 32);
    value.payload = payload; value.payload_size = (uint32_t)payload_size;
    if (method == PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY)
        memset(value.capability_id, 0x33, 32);
    if (plamen_broker_v2_sha256(payload, payload_size,
            value.terminal_sha256) != PLAMEN_BROKER_V2_OK) return -1;
    status = plamen_broker_v2_specialized_response_encode(
        &value, wire, sizeof(wire), &wire_size);
    if (!accepted) return status == PLAMEN_BROKER_V2_INVALID ? 0 : -1;
    if (status != PLAMEN_BROKER_V2_OK
        || plamen_broker_v2_specialized_response_decode_exact(
            wire, wire_size, &decoded) != PLAMEN_BROKER_V2_OK
        || decoded.payload_size != payload_size
        || memcmp(decoded.payload, payload, payload_size) != 0) return -1;
    return 0;
}

int main(void)
{
    static const uint8_t no_lf[] = "{\"schema\":\"x\"}";
    static const uint8_t one_lf[] = "{\"schema\":\"x\"}\n";
    static const uint8_t two_lf[] = "{\"schema\":\"x\"}\n\n";
    if (run_case(PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED,
            one_lf, sizeof(one_lf)-1U, 1) != 0
        || run_case(PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED,
            no_lf, sizeof(no_lf)-1U, 0) != 0
        || run_case(PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_EXECUTE,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED,
            two_lf, sizeof(two_lf)-1U, 0) != 0
        || run_case(PLAMEN_BROKER_V2_SPECIALIZED_JS_MATERIALIZER,
            PLAMEN_BROKER_V2_METHOD_JS_MATERIALIZER_REPLAY,
            PLAMEN_BROKER_V2_SPECIALIZED_REPLAYED,
            one_lf, sizeof(one_lf)-1U, 1) != 0
        || run_case(PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED,
            no_lf, sizeof(no_lf)-1U, 1) != 0
        || run_case(PLAMEN_BROKER_V2_SPECIALIZED_SNAPSHOT_TOOL,
            PLAMEN_BROKER_V2_METHOD_SNAPSHOT_TOOL_EXECUTE,
            PLAMEN_BROKER_V2_SPECIALIZED_COMMITTED,
            one_lf, sizeof(one_lf)-1U, 0) != 0)
        return 1;
    puts("specialized JS response framing: ok"); return 0;
}
