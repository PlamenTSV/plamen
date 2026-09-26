#include "plamen_native_operation4_helper_v1.h"

#define B32(value) { \
    value,value,value,value,value,value,value,value, \
    value,value,value,value,value,value,value,value, \
    value,value,value,value,value,value,value,value, \
    value,value,value,value,value,value,value,value \
}

const struct plamen_native_operation4_fixed_policy_v1
    plamen_native_operation4_generated_policy_v1 = {
        .version = 1U,
        .role_count = PLAMEN_SOURCE_BOOTSTRAP_COORDINATOR_V1_ROLE_COUNT,
        .roster_sha256 = B32(0x91U),
        .rows = {
            [PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1] = {
                .role = PLAMEN_SOURCE_BOOTSTRAP_CODEX_V1,
                .identity_mode =
                    PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1,
                .receipt_validator =
                    PLAMEN_NATIVE_OPERATION4_BACKEND_RECEIPT_V1,
                .policy_sha256 = B32(0xaaU),
                .receipt_schema =
                    "plamen.native-backend-latest-acquisition-receipt.v1",
            },
            [PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1] = {
                .role = PLAMEN_SOURCE_BOOTSTRAP_CLAUDE_V1,
                .identity_mode =
                    PLAMEN_NATIVE_OPERATION4_LATEST_BACKEND_RECEIPT_V1,
                .receipt_validator =
                    PLAMEN_NATIVE_OPERATION4_BACKEND_RECEIPT_V1,
                .policy_sha256 = B32(0xaaU),
                .receipt_schema =
                    "plamen.native-backend-latest-acquisition-receipt.v1",
            },
        },
    };
