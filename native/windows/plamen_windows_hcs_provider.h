#ifndef PLAMEN_WINDOWS_HCS_PROVIDER_H
#define PLAMEN_WINDOWS_HCS_PROVIDER_H

#define PLAMEN_WINDOWS_HCS_PROVIDER_ABI 1u
#define PLAMEN_WINDOWS_HCS_DIAGNOSTIC_SCHEMA \
    "plamen.windows_hcs_native_doctor.diagnostic.v1"
#define PLAMEN_WINDOWS_HCS_ACCEPTED_SCHEMA \
    "plamen.windows_hcs_doctor_receipt.v1"

enum plamen_windows_hcs_exit_code {
    PLAMEN_WINDOWS_HCS_OK = 0,
    PLAMEN_WINDOWS_HCS_USAGE = 2,
    PLAMEN_WINDOWS_HCS_INCOMPLETE = 3,
    PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE = 4,
    PLAMEN_WINDOWS_HCS_INTERNAL = 5
};

#endif
