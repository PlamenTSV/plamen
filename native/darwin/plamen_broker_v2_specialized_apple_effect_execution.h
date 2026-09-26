#ifndef PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_H
#define PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_H

#include "plamen_broker_v2_effects.h"
#include "plamen_broker_v2_specialized_effect_store.h"
#include "plamen_broker_v2_specialized_output_census.h"
#include "plamen_broker_v2_specialized_output_receipt.h"
#include "plamen_broker_v2_specialized_runtime_effects_handoff.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PLAMEN_BROKER_V2_SPECIALIZED_APPLE_EFFECT_EXECUTION_VERSION 1U

typedef int (*plamen_broker_v2_specialized_apple_run_fn)(void *,
    const struct plamen_broker_v2_specialized_worker_request *,
    struct plamen_broker_v2_specialized_worker_result *);

typedef void (*plamen_broker_v2_specialized_apple_result_dispose_fn)(
    struct plamen_broker_v2_specialized_worker_result *);

/*
 * Converts authenticated guest observation plus independent host lifecycle
 * evidence into the method-exact canonical terminal.  This is deliberately a
 * required codec-owned function: the execution layer never relabels the
 * guest observation or manufactures a protocol terminal.
 */
typedef int (*plamen_broker_v2_specialized_terminal_render_fn)(
    const struct plamen_broker_v2_tool_effect_plan_view *,
    const struct plamen_broker_v2_specialized_worker_request_binding *,
    const struct plamen_broker_v2_specialized_worker_terminal_observation *,
    const struct plamen_broker_v2_specialized_output_receipt *,
    const uint8_t session_key[32],
    const uint8_t lifecycle_receipt_sha256[32],
    uint8_t **terminal, size_t *terminal_size);

struct plamen_broker_v2_specialized_apple_effect_execution {
    uint32_t version;
    struct plamen_broker_v2_specialized_effect_store *store;
    struct plamen_broker_v2_specialized_runtime_handoff *runtime_handoff;
    const struct plamen_broker_v2_tool_effect_plan_view *view;
    const uint8_t *session_key;

    void *native_effects_context;
    plamen_broker_v2_specialized_apple_run_fn run;
    plamen_broker_v2_specialized_apple_result_dispose_fn dispose_result;
    plamen_broker_v2_specialized_terminal_render_fn render_terminal;
};

/*
 * Executes only the current deny-all Apple worker boundary.  ONLINE_INSTALL
 * is intentionally not accepted here; it requires the separately versioned
 * guest-firewall admission and evidence contract.
 */
int plamen_broker_v2_specialized_apple_effect_execute_deny_all(
    const struct plamen_broker_v2_specialized_apple_effect_execution *,
    struct plamen_broker_v2_tool_effect_evidence *);

/*
 * Resolves a 0x2104 replay only from the exact canonical request/terminal
 * binding and the durable, runtime-authority-bound execute terminal index.
 * No provider callback is accepted or invoked.  The returned terminal is an
 * owned copy of the originally committed one-LF wire payload.
 */
int plamen_broker_v2_specialized_apple_effect_replay_js(
    struct plamen_broker_v2_specialized_effect_store *,
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_specialized_effect_completion *,
    uint8_t **terminal, size_t *terminal_size);

/*
 * Re-admits a committed EVM projection only through its authenticated
 * terminal digest and the runtime-bound durable store.  The recover request
 * contains no path or caller-selected operation key; the store independently
 * authenticates the original COMMIT completion and terminal HMAC.
 */
int plamen_broker_v2_specialized_apple_effect_recover_projection(
    struct plamen_broker_v2_specialized_effect_store *,
    const struct plamen_broker_v2_tool_effect_plan_view *,
    struct plamen_broker_v2_specialized_effect_completion *,
    uint8_t **terminal, size_t *terminal_size);

#ifdef __cplusplus
}
#endif

#endif
