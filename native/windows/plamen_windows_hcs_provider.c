/* Native Windows HCS doctor transport.
 *
 * This executable deliberately emits a diagnostic, not an accepted production
 * receipt.  It binds a fresh challenge to its own open-file SHA-256 identity
 * and exercises the real ComputeCore operation API.  The accepted receipt must
 * not be emitted until a disposable Hyper-V guest has proved the complete A8/A9
 * boundary (no NIC, immutable/bounded VHDX roots, guest Job zero, flush and
 * detach).  Exit code INCOMPLETE makes that missing postcondition mechanical.
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <ComputeCore.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "plamen_windows_hcs_provider.h"

#pragma comment(lib, "bcrypt.lib")

#define PLAMEN_MAX_HCS_RESULT_CHARS ((size_t)4u * 1024u * 1024u)

typedef HCS_OPERATION(WINAPI *hcs_create_operation_fn)(
    void *, HCS_OPERATION_COMPLETION
);
typedef void(WINAPI *hcs_close_operation_fn)(HCS_OPERATION);
typedef HRESULT(WINAPI *hcs_enumerate_fn)(PCWSTR, HCS_OPERATION);
typedef HRESULT(WINAPI *hcs_wait_fn)(HCS_OPERATION, DWORD, PWSTR *);
typedef HRESULT(WINAPI *hcs_create_system_fn)(
    PCWSTR, PCWSTR, HCS_OPERATION, const SECURITY_DESCRIPTOR *, HCS_SYSTEM *
);
typedef HRESULT(WINAPI *hcs_get_properties_fn)(
    HCS_SYSTEM, HCS_OPERATION, PCWSTR
);
typedef HRESULT(WINAPI *hcs_terminate_system_fn)(
    HCS_SYSTEM, HCS_OPERATION, PCWSTR
);
typedef void(WINAPI *hcs_close_system_fn)(HCS_SYSTEM);

static const wchar_t plamen_empty_vm_configuration[] =
    L"{\"SchemaVersion\":{\"Major\":2,\"Minor\":1},"
    L"\"Owner\":\"PlamenNativeDoctor\",\"VirtualMachine\":{"
    L"\"Chipset\":{\"Uefi\":{}},\"ComputeTopology\":{"
    L"\"Memory\":{\"Backing\":\"Physical\",\"SizeInMB\":1024},"
    L"\"Processor\":{\"Count\":2}}},"
    L"\"ShouldTerminateOnLastHandleClosed\":true}";

static int load_function(
    HMODULE module, const char *name, void *target, size_t target_size
) {
    FARPROC procedure;
    if (target_size != sizeof(procedure)) return 0;
    procedure = GetProcAddress(module, name);
    if (procedure == NULL) return 0;
    memcpy(target, &procedure, sizeof(procedure));
    return 1;
}

static int hex_value(wchar_t value) {
    if (value >= L'0' && value <= L'9') return (int)(value - L'0');
    if (value >= L'a' && value <= L'f') return 10 + (int)(value - L'a');
    if (value >= L'A' && value <= L'F') return 10 + (int)(value - L'A');
    return -1;
}

static int decode_challenge(
    const wchar_t *text, unsigned char *output, DWORD *output_size
) {
    size_t length = wcslen(text);
    size_t index;
    if (length < 32 || length > 512 || (length & 1u) != 0) return 0;
    for (index = 0; index < length / 2; ++index) {
        int high = hex_value(text[index * 2]);
        int low = hex_value(text[index * 2 + 1]);
        if (high < 0 || low < 0) return 0;
        output[index] = (unsigned char)((high << 4) | low);
    }
    *output_size = (DWORD)(length / 2);
    return 1;
}

static int hash_bytes(
    const unsigned char *input, DWORD input_size, unsigned char digest[32]
) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char *object = NULL;
    DWORD object_size = 0;
    DWORD returned = 0;
    NTSTATUS status;
    int ok = 0;
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0
    );
    if (status < 0) goto done;
    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_size,
        sizeof(object_size), &returned, 0
    );
    if (status < 0 || returned != sizeof(object_size) || object_size == 0)
        goto done;
    object = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, object_size);
    if (object == NULL) goto done;
    status = BCryptCreateHash(
        algorithm, &hash, object, object_size, NULL, 0, 0
    );
    if (status < 0) goto done;
    status = BCryptHashData(hash, (PUCHAR)input, input_size, 0);
    if (status < 0) goto done;
    status = BCryptFinishHash(hash, digest, 32, 0);
    if (status < 0) goto done;
    ok = 1;
done:
    if (hash != NULL) BCryptDestroyHash(hash);
    if (object != NULL) HeapFree(GetProcessHeap(), 0, object);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static int hash_wide_utf8(
    const wchar_t *input, unsigned char digest[32]
) {
    size_t characters = 0;
    int bytes;
    char *utf8 = NULL;
    int ok = 0;
    if (input == NULL) return 0;
    while (
        characters <= PLAMEN_MAX_HCS_RESULT_CHARS &&
        input[characters] != L'\0'
    ) {
        ++characters;
    }
    if (
        characters == 0 || characters > PLAMEN_MAX_HCS_RESULT_CHARS ||
        characters > INT_MAX
    ) return 0;
    bytes = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, input, (int)characters,
        NULL, 0, NULL, NULL
    );
    if (bytes <= 0 || (size_t)bytes > PLAMEN_MAX_HCS_RESULT_CHARS * 4u)
        return 0;
    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
    if (utf8 == NULL) return 0;
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, input, (int)characters,
            utf8, bytes, NULL, NULL
        ) != bytes) goto done;
    ok = hash_bytes((const unsigned char *)utf8, (DWORD)bytes, digest);
done:
    SecureZeroMemory(utf8, (SIZE_T)bytes);
    HeapFree(GetProcessHeap(), 0, utf8);
    return ok;
}

static uint64_t current_windows_filetime(void) {
    FILETIME now;
    ULARGE_INTEGER value;
    GetSystemTimeAsFileTime(&now);
    value.LowPart = now.dwLowDateTime;
    value.HighPart = now.dwHighDateTime;
    return (uint64_t)value.QuadPart;
}

static int hash_open_file(
    HANDLE file, uint64_t size, unsigned char digest[32]
) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    unsigned char *object = NULL;
    unsigned char buffer[65536];
    DWORD object_size = 0;
    DWORD returned = 0;
    DWORD read_size;
    uint64_t observed = 0;
    NTSTATUS status;
    int ok = 0;
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(file, zero, NULL, FILE_BEGIN)) return 0;
    status = BCryptOpenAlgorithmProvider(
        &algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0
    );
    if (status < 0) goto done;
    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_size,
        sizeof(object_size), &returned, 0
    );
    if (status < 0 || returned != sizeof(object_size) || object_size == 0)
        goto done;
    object = (unsigned char *)HeapAlloc(GetProcessHeap(), 0, object_size);
    if (object == NULL) goto done;
    status = BCryptCreateHash(
        algorithm, &hash, object, object_size, NULL, 0, 0
    );
    if (status < 0) goto done;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &read_size, NULL)) goto done;
        if (read_size == 0) break;
        observed += read_size;
        if (observed > size) goto done;
        status = BCryptHashData(hash, buffer, read_size, 0);
        if (status < 0) goto done;
    }
    if (observed != size) goto done;
    status = BCryptFinishHash(hash, digest, 32, 0);
    if (status < 0) goto done;
    ok = 1;
done:
    SecureZeroMemory(buffer, sizeof(buffer));
    if (hash != NULL) BCryptDestroyHash(hash);
    if (object != NULL) HeapFree(GetProcessHeap(), 0, object);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return ok;
}

static void print_hex(const unsigned char *value, size_t size) {
    static const char alphabet[] = "0123456789abcdef";
    size_t index;
    for (index = 0; index < size; ++index) {
        putchar(alphabet[value[index] >> 4]);
        putchar(alphabet[value[index] & 15]);
    }
}

static int print_json_wide_string(const wchar_t *value) {
    int bytes;
    char *utf8;
    const unsigned char *cursor;
    bytes = WideCharToMultiByte(
        CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, NULL, 0, NULL, NULL
    );
    if (bytes <= 0 || bytes > 131072) return 0;
    utf8 = (char *)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)bytes);
    if (utf8 == NULL) return 0;
    if (WideCharToMultiByte(
            CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, utf8, bytes, NULL, NULL
        ) != bytes) {
        HeapFree(GetProcessHeap(), 0, utf8);
        return 0;
    }
    putchar('"');
    for (cursor = (const unsigned char *)utf8; *cursor != 0; ++cursor) {
        if (*cursor == '"' || *cursor == '\\') putchar('\\');
        if (*cursor < 0x20) {
            printf("\\u%04x", (unsigned int)*cursor);
        } else {
            putchar(*cursor);
        }
    }
    putchar('"');
    HeapFree(GetProcessHeap(), 0, utf8);
    return 1;
}

static int run_doctor(const wchar_t *challenge_text) {
    wchar_t module_path[32768];
    DWORD module_length;
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    BY_HANDLE_FILE_INFORMATION before;
    BY_HANDLE_FILE_INFORMATION after;
    unsigned char challenge[256];
    unsigned char challenge_digest[32];
    unsigned char provider_digest[32];
    unsigned char inventory_digest[32];
    unsigned char empty_vm_configuration_digest[32];
    unsigned char empty_vm_properties_digest[32];
    DWORD challenge_size = 0;
    HMODULE compute_core = NULL;
    hcs_create_operation_fn create_operation = NULL;
    hcs_close_operation_fn close_operation = NULL;
    hcs_enumerate_fn enumerate_systems = NULL;
    hcs_wait_fn wait_result = NULL;
    hcs_create_system_fn create_system = NULL;
    hcs_get_properties_fn get_properties = NULL;
    hcs_terminate_system_fn terminate_system = NULL;
    hcs_close_system_fn close_system = NULL;
    HCS_OPERATION operation = NULL;
    HCS_SYSTEM compute_system = NULL;
    PWSTR result_document = NULL;
    wchar_t compute_system_id[96];
    int compute_system_terminated = 0;
    HRESULT result;
    uint64_t observed_at;
    int exit_code = PLAMEN_WINDOWS_HCS_INTERNAL;

    if (!decode_challenge(challenge_text, challenge, &challenge_size))
        return PLAMEN_WINDOWS_HCS_USAGE;
    if (!hash_bytes(challenge, challenge_size, challenge_digest)) goto done;
    SecureZeroMemory(challenge, sizeof(challenge));

    module_length = GetModuleFileNameW(module_path, 32768);
    if (module_length == 0 || module_length >= 32767) goto done;
    file = CreateFileW(
        module_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL
    );
    if (file == INVALID_HANDLE_VALUE) goto done;
    if (!GetFileInformationByHandle(file, &before)) goto done;
    if ((before.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) goto done;
    if (before.nNumberOfLinks != 1) goto done;
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart <= 0) goto done;
    if (!hash_open_file(file, (uint64_t)file_size.QuadPart, provider_digest))
        goto done;
    if (!GetFileInformationByHandle(file, &after)) goto done;
    if (
        before.dwVolumeSerialNumber != after.dwVolumeSerialNumber ||
        before.nFileIndexHigh != after.nFileIndexHigh ||
        before.nFileIndexLow != after.nFileIndexLow ||
        before.nFileSizeHigh != after.nFileSizeHigh ||
        before.nFileSizeLow != after.nFileSizeLow ||
        before.ftLastWriteTime.dwHighDateTime !=
            after.ftLastWriteTime.dwHighDateTime ||
        before.ftLastWriteTime.dwLowDateTime !=
            after.ftLastWriteTime.dwLowDateTime ||
        after.nNumberOfLinks != 1
    ) goto done;

    compute_core = LoadLibraryExW(
        L"ComputeCore.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32
    );
    if (compute_core == NULL) {
        exit_code = PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE;
        goto done;
    }
    if (
        !load_function(
            compute_core, "HcsCreateOperation", &create_operation,
            sizeof(create_operation)
        ) ||
        !load_function(
            compute_core, "HcsCloseOperation", &close_operation,
            sizeof(close_operation)
        ) ||
        !load_function(
            compute_core, "HcsEnumerateComputeSystems", &enumerate_systems,
            sizeof(enumerate_systems)
        ) ||
        !load_function(
            compute_core, "HcsWaitForOperationResult", &wait_result,
            sizeof(wait_result)
        ) ||
        !load_function(
            compute_core, "HcsCreateComputeSystem", &create_system,
            sizeof(create_system)
        ) ||
        !load_function(
            compute_core, "HcsGetComputeSystemProperties", &get_properties,
            sizeof(get_properties)
        ) ||
        !load_function(
            compute_core, "HcsTerminateComputeSystem", &terminate_system,
            sizeof(terminate_system)
        ) ||
        !load_function(
            compute_core, "HcsCloseComputeSystem", &close_system,
            sizeof(close_system)
        ) ||
        GetProcAddress(compute_core, "HcsStartComputeSystem") == NULL ||
        !hash_wide_utf8(
            plamen_empty_vm_configuration,
            empty_vm_configuration_digest
        )
    ) {
        exit_code = PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE;
        goto done;
    }
    operation = create_operation(NULL, NULL);
    if (operation == NULL) goto done;
    result = enumerate_systems(L"{\"Types\":[\"VirtualMachine\"]}", operation);
    if (FAILED(result)) {
        exit_code = PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE;
        goto done;
    }
    result = wait_result(operation, 30000, &result_document);
    if (FAILED(result)) {
        exit_code = PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE;
        goto done;
    }
    if (!hash_wide_utf8(result_document, inventory_digest)) goto done;
    LocalFree(result_document);
    result_document = NULL;
    close_operation(operation);
    operation = NULL;

    if (swprintf_s(
            compute_system_id, sizeof(compute_system_id) / sizeof(wchar_t),
            L"PlamenDoctor-%lu-%02x%02x%02x%02x%02x%02x%02x%02x",
            (unsigned long)GetCurrentProcessId(),
            (unsigned int)challenge_digest[0],
            (unsigned int)challenge_digest[1],
            (unsigned int)challenge_digest[2],
            (unsigned int)challenge_digest[3],
            (unsigned int)challenge_digest[4],
            (unsigned int)challenge_digest[5],
            (unsigned int)challenge_digest[6],
            (unsigned int)challenge_digest[7]
        ) < 0) goto done;
    operation = create_operation(NULL, NULL);
    if (operation == NULL) goto done;
    result = create_system(
        compute_system_id, plamen_empty_vm_configuration, operation, NULL,
        &compute_system
    );
    if (FAILED(result) || compute_system == NULL) {
        exit_code = PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE;
        goto done;
    }
    result = wait_result(operation, 30000, &result_document);
    if (FAILED(result)) {
        exit_code = PLAMEN_WINDOWS_HCS_HOST_UNAVAILABLE;
        goto done;
    }
    if (result_document != NULL) {
        LocalFree(result_document);
        result_document = NULL;
    }
    close_operation(operation);
    operation = NULL;

    operation = create_operation(NULL, NULL);
    if (operation == NULL) goto done;
    result = get_properties(compute_system, operation, NULL);
    if (FAILED(result)) goto done;
    result = wait_result(operation, 30000, &result_document);
    if (FAILED(result)) goto done;
    if (!hash_wide_utf8(result_document, empty_vm_properties_digest))
        goto done;
    LocalFree(result_document);
    result_document = NULL;
    close_operation(operation);
    operation = NULL;

    operation = create_operation(NULL, NULL);
    if (operation == NULL) goto done;
    result = terminate_system(compute_system, operation, NULL);
    if (FAILED(result)) goto done;
    result = wait_result(operation, 30000, &result_document);
    if (FAILED(result)) goto done;
    compute_system_terminated = 1;
    if (result_document != NULL) {
        LocalFree(result_document);
        result_document = NULL;
    }
    close_operation(operation);
    operation = NULL;
    close_system(compute_system);
    compute_system = NULL;
    observed_at = current_windows_filetime();

    fputs("{\"schema\":\"" PLAMEN_WINDOWS_HCS_DIAGNOSTIC_SCHEMA
          "\",\"challenge_sha256\":\"", stdout);
    print_hex(challenge_digest, sizeof(challenge_digest));
    fputs("\",\"provider_identity\":{\"path\":", stdout);
    if (!print_json_wide_string(module_path)) goto done;
    printf(",\"size\":%" PRIu64 ",\"sha256\":\"",
           (uint64_t)file_size.QuadPart);
    print_hex(provider_digest, sizeof(provider_digest));
    fputs("\"},\"provider_file_identity\":{\"volume_serial\":", stdout);
    printf("%lu,\"file_index_high\":%lu,\"file_index_low\":%lu,"
           "\"number_of_links\":%lu,\"last_write_filetime\":%" PRIu64 "},",
           (unsigned long)before.dwVolumeSerialNumber,
           (unsigned long)before.nFileIndexHigh,
           (unsigned long)before.nFileIndexLow,
           (unsigned long)before.nNumberOfLinks,
           ((uint64_t)before.ftLastWriteTime.dwHighDateTime << 32) |
               before.ftLastWriteTime.dwLowDateTime);
    fputs("\"hcs_api_surface_available\":true,"
          "\"hcs_service_probe\":\"ENUMERATE_COMPUTE_SYSTEMS_OK\","
          "\"hcs_enumeration_sha256\":\"", stdout);
    print_hex(inventory_digest, sizeof(inventory_digest));
    fputs("\",\"disposable_empty_vm_probe\":{"
          "\"configuration_sha256\":\"", stdout);
    print_hex(
        empty_vm_configuration_digest,
        sizeof(empty_vm_configuration_digest)
    );
    fputs("\",\"properties_sha256\":\"", stdout);
    print_hex(empty_vm_properties_digest, sizeof(empty_vm_properties_digest));
    fputs("\",\"created\":true,\"started\":false,"
          "\"terminated\":true}", stdout);
    printf(",\"observed_at_windows_filetime\":%" PRIu64 ",",
           observed_at);
    fputs(
          "\"production_ready\":false,"
          "\"limitation\":\"LIVE_GUEST_STORAGE_JOB_NETWORK_PROBE_NOT_IMPLEMENTED\"}\n",
          stdout);
    if (fflush(stdout) != 0) goto done;
    exit_code = PLAMEN_WINDOWS_HCS_INCOMPLETE;
done:
    SecureZeroMemory(challenge, sizeof(challenge));
    SecureZeroMemory(provider_digest, sizeof(provider_digest));
    SecureZeroMemory(inventory_digest, sizeof(inventory_digest));
    SecureZeroMemory(
        empty_vm_configuration_digest,
        sizeof(empty_vm_configuration_digest)
    );
    SecureZeroMemory(
        empty_vm_properties_digest,
        sizeof(empty_vm_properties_digest)
    );
    if (result_document != NULL) LocalFree(result_document);
    if (operation != NULL && close_operation != NULL) close_operation(operation);
    if (
        compute_system != NULL && terminate_system != NULL &&
        create_operation != NULL && wait_result != NULL &&
        !compute_system_terminated
    ) {
        HCS_OPERATION cleanup_operation = create_operation(NULL, NULL);
        if (cleanup_operation != NULL) {
            PWSTR cleanup_document = NULL;
            if (SUCCEEDED(terminate_system(
                    compute_system, cleanup_operation, NULL
                ))) {
                (void)wait_result(
                    cleanup_operation, 30000, &cleanup_document
                );
            }
            if (cleanup_document != NULL) LocalFree(cleanup_document);
            if (close_operation != NULL) close_operation(cleanup_operation);
        }
    }
    if (compute_system != NULL && close_system != NULL)
        close_system(compute_system);
    if (compute_core != NULL) FreeLibrary(compute_core);
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    return exit_code;
}

int wmain(int argc, wchar_t **argv) {
    if (
        argc != 4 || wcscmp(argv[1], L"doctor") != 0 ||
        wcscmp(argv[2], L"--challenge-hex") != 0
    ) {
        fputs("usage: plamen_windows_hcs_provider.exe doctor "
              "--challenge-hex HEX\n", stderr);
        return PLAMEN_WINDOWS_HCS_USAGE;
    }
    return run_doctor(argv[3]);
}
