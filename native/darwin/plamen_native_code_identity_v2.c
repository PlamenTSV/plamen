#define _DARWIN_C_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "plamen_native_code_identity_v2.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif

struct observed_code_identity_v2 {
    char identifier[PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX + 1U];
    char team[PLAMEN_INSTALL_RECEIPT_TEAM_ID_MAX + 1U];
    uint8_t cdhash[PLAMEN_INSTALL_RECEIPT_CDHASH_MAX];
    size_t cdhash_size;
};

#ifdef PLAMEN_NATIVE_CODE_IDENTITY_V2_TESTING
static plamen_native_code_identity_swap_hook_v2 test_swap_hook;

void
plamen_native_code_identity_test_swap_hook_v2(
    plamen_native_code_identity_swap_hook_v2 hook)
{
    test_swap_hook = hook;
}
#endif

static int
same_vnode(const struct stat *left, const struct stat *right)
{
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino
        && left->st_mode == right->st_mode && left->st_uid == right->st_uid
        && left->st_gid == right->st_gid && left->st_nlink == right->st_nlink
        && left->st_size == right->st_size;
}

static int
copy_string(CFTypeRef value, char *output, size_t capacity, int optional)
{
    CFIndex utf8_size;
    if (value == NULL)
        return optional ? 0 : -1;
    if (CFGetTypeID(value) != CFStringGetTypeID()
        || (utf8_size = CFStringGetMaximumSizeForEncoding(
            CFStringGetLength((CFStringRef)value), kCFStringEncodingUTF8)) < 0
        || (size_t)utf8_size + 1U > capacity
        || !CFStringGetCString((CFStringRef)value, output,
            (CFIndex)capacity, kCFStringEncodingUTF8)
        || output[0] == '\0')
        return -1;
    return 0;
}

static int
copy_identity(CFDictionaryRef information,
    struct observed_code_identity_v2 *identity)
{
    CFTypeRef identifier, team, unique;
    CFIndex size;
    memset(identity, 0, sizeof(*identity));
    identifier = CFDictionaryGetValue(information, kSecCodeInfoIdentifier);
    team = CFDictionaryGetValue(information, kSecCodeInfoTeamIdentifier);
    unique = CFDictionaryGetValue(information, kSecCodeInfoUnique);
    if (copy_string(identifier, identity->identifier,
            sizeof(identity->identifier), 0) != 0
        || copy_string(team, identity->team, sizeof(identity->team), 1) != 0
        || unique == NULL || CFGetTypeID(unique) != CFDataGetTypeID()
        || ((size = CFDataGetLength((CFDataRef)unique)) != 20 && size != 32))
        return -1;
    memcpy(identity->cdhash, CFDataGetBytePtr((CFDataRef)unique),
        (size_t)size);
    identity->cdhash_size = (size_t)size;
    return 0;
}

static int
observe_static_code(const char *path, const char *identifier,
    struct observed_code_identity_v2 *identity)
{
    CFURLRef url = NULL;
    CFStringRef requirement_text = NULL;
    SecRequirementRef requirement = NULL;
    SecStaticCodeRef code = NULL;
    CFDictionaryRef information = NULL;
    char text[PLAMEN_INSTALL_RECEIPT_SIGNING_ID_MAX + 32U];
    int result = -1;
    if (snprintf(text, sizeof(text), "identifier \"%s\"", identifier)
            >= (int)sizeof(text))
        goto done;
    url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *)path, (CFIndex)strlen(path), false);
    requirement_text = CFStringCreateWithCString(kCFAllocatorDefault, text,
        kCFStringEncodingUTF8);
    if (url == NULL || requirement_text == NULL
        || SecRequirementCreateWithString(requirement_text,
            kSecCSDefaultFlags, &requirement) != errSecSuccess
        || SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags,
            &code) != errSecSuccess
        || SecStaticCodeCheckValidity(code,
            kSecCSStrictValidate | kSecCSCheckAllArchitectures
                | kSecCSRestrictSymlinks,
            requirement) != errSecSuccess
        || SecCodeCopySigningInformation(code, kSecCSSigningInformation,
            &information) != errSecSuccess
        || copy_identity(information, identity) != 0)
        goto done;
    result = 0;
done:
    if (information != NULL) CFRelease(information);
    if (code != NULL) CFRelease(code);
    if (requirement != NULL) CFRelease(requirement);
    if (requirement_text != NULL) CFRelease(requirement_text);
    if (url != NULL) CFRelease(url);
    memset(text, 0, sizeof(text));
    if (result != 0 && errno == 0) errno = EPERM;
    return result;
}

static int
validate_member(const struct plamen_install_receipt *receipt,
    int generation_fd, size_t index)
{
    const struct plamen_install_receipt_member *member =
        &receipt->members[index];
    struct observed_code_identity_v2 observed;
    struct stat retained_before, retained_after, named_before, named_after;
    char path[PLAMEN_INSTALL_RECEIPT_PATH_MAX
        + PLAMEN_INSTALL_RECEIPT_RELATIVE_PATH_MAX + 2U];
    int retained = -1, named = -1, reopened = -1, result = -1;
    memset(&observed, 0, sizeof(observed)); memset(path, 0, sizeof(path));
    if (member->signing_identifier[0] == '\0'
        || snprintf(path, sizeof(path), "%s/%s", receipt->generation_path,
            member->relative_path) >= (int)sizeof(path)
        || plamen_install_receipt_open_member(generation_fd, member,
            &retained) != 0
        || (named = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || fstat(retained, &retained_before) != 0
        || fstat(named, &named_before) != 0
        || !same_vnode(&retained_before, &named_before)
        || observe_static_code(path, member->signing_identifier,
            &observed) != 0
#ifdef PLAMEN_NATIVE_CODE_IDENTITY_V2_TESTING
        || (test_swap_hook != NULL && (test_swap_hook(path), 0))
#endif
        || (reopened = open(path,
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) < 0
        || strcmp(observed.identifier, member->signing_identifier) != 0
        || strcmp(observed.team, member->team_identifier) != 0
        || observed.cdhash_size != member->cdhash_size
        || memcmp(observed.cdhash, member->cdhash,
            observed.cdhash_size) != 0
        || plamen_install_receipt_member_revalidate(retained, member) != 0
        || fstat(retained, &retained_after) != 0
        || fstat(named, &named_after) != 0
        || fstat(reopened, &named_before) != 0
        || !same_vnode(&retained_before, &retained_after)
        || !same_vnode(&retained_after, &named_after)
        || !same_vnode(&retained_after, &named_before))
        goto done;
    result = 0;
done:
    {
        int saved = result == 0 ? 0 : (errno == 0 ? EPERM : errno);
        if (reopened >= 0) close(reopened);
        if (named >= 0) close(named);
        if (retained >= 0) close(retained);
        memset(&observed, 0, sizeof(observed)); memset(path, 0, sizeof(path));
        if (result != 0) errno = saved;
        return result;
    }
}

int
plamen_native_darwin_validate_signed_closure_v2(
    const struct plamen_install_receipt *receipt, int generation_fd)
{
    static const size_t signed_indexes[] = { 0U, 1U, 2U, 5U };
    struct stat generation_before, generation_after;
    size_t index;
    if (receipt == NULL || generation_fd < 0
        || fstat(generation_fd, &generation_before) != 0
        || !S_ISDIR(generation_before.st_mode)
        || (generation_before.st_mode & 07777) != 0500) {
        errno = EINVAL; return -1;
    }
    for (index = 0; index < sizeof(signed_indexes) / sizeof(signed_indexes[0]);
            ++index)
        if (validate_member(receipt, generation_fd,
                signed_indexes[index]) != 0)
            return -1;
    if (fstat(generation_fd, &generation_after) != 0
        || !same_vnode(&generation_before, &generation_after)) {
        errno = EPERM; return -1;
    }
    return 0;
}
