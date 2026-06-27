// iOSSpoof System-Level Hooks
// Runs inside systemhook.dylib — BEFORE app code runs
// Uses litehook (instruction patching) — no substrate/ellekit needed
// Invisible to app: no MSHookFunction, no dyld injection, no DYLD_INSERT_LIBRARIES

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <errno.h>
#include <spawn.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

#include "litehook.h"
#include "common.h"

// ============================================================================
// Config: read from iOSSpoof plist (jbroot path)
// ============================================================================

static bool sc_enabled = false;
static bool sc_hideJailbreak = true;
static char sc_productType[64] = "iPhone14,5";
static char sc_hardwareModel[64] = "D63AP";
static char sc_marketingName[64] = "iPhone 13";
static char sc_serial[64] = "";
static char sc_udid[64] = "";
static char sc_systemVersion[16] = "17.5";
static char sc_buildID[16] = "21F90";
static char sc_carrierName[64] = "Viettel";
static char sc_carrierMCC[8] = "452";
static char sc_carrierMNC[8] = "04";
static char sc_carrierISO[8] = "vn";
static char sc_radioTech[64] = "CTRadioAccessTechnologyLTE";
static int sc_networkMode = 0; // 0=default, 1=wifi, 2=cellular
static char sc_wifiSSID[128] = "MyWiFi";
static char sc_wifiBSSID[32] = "02:00:00:00:00:00";
static char sc_locale[32] = "";
static char sc_timezone[64] = "";
static bool sc_configLoaded = false;

static void sc_load_config(void) {
    if (sc_configLoaded) return;
    sc_configLoaded = true;

    // Try multiple paths for config
    const char *paths[] = {
        "/var/jb/var/mobile/Library/Preferences/com.iosspoof.tweak.plist",
        "/var/mobile/Library/Preferences/com.iosspoof.tweak.plist",
        NULL
    };

    // Use CFDictionary to read plist
    CFURLRef url = NULL;
    CFReadStreamRef stream = NULL;
    CFPropertyListRef plist = NULL;

    for (int i = 0; paths[i]; i++) {
        url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (const UInt8 *)paths[i], strlen(paths[i]), false);
        if (!url) continue;
        stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
        if (!stream) { CFRelease(url); continue; }
        if (!CFReadStreamOpen(stream)) { CFRelease(stream); CFRelease(url); continue; }
        plist = CFPropertyListCreateWithStream(kCFAllocatorDefault, stream, 0, kCFPropertyListMutableContainers, NULL, NULL);
        CFReadStreamClose(stream);
        CFRelease(stream);
        CFRelease(url);
        if (plist) break;
    }

    if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        if (plist) CFRelease(plist);
        return;
    }

    CFDictionaryRef d = (CFDictionaryRef)plist;

    CFBooleanRef en = CFDictionaryGetValue(d, CFSTR("enabled"));
    if (en) sc_enabled = CFBooleanGetValue(en);

    CFBooleanRef hj = CFDictionaryGetValue(d, CFSTR("hideJailbreak"));
    if (hj) sc_hideJailbreak = CFBooleanGetValue(hj);

    CFStringRef pt = CFDictionaryGetValue(d, CFSTR("productType"));
    if (pt) CFStringGetCString(pt, sc_productType, sizeof(sc_productType), kCFStringEncodingUTF8);

    CFStringRef hm = CFDictionaryGetValue(d, CFSTR("hardwareModel"));
    if (hm) CFStringGetCString(hm, sc_hardwareModel, sizeof(sc_hardwareModel), kCFStringEncodingUTF8);

    CFStringRef mn = CFDictionaryGetValue(d, CFSTR("marketingName"));
    if (mn) CFStringGetCString(mn, sc_marketingName, sizeof(sc_marketingName), kCFStringEncodingUTF8);

    CFStringRef sv = CFDictionaryGetValue(d, CFSTR("systemVersion"));
    if (sv) CFStringGetCString(sv, sc_systemVersion, sizeof(sc_systemVersion), kCFStringEncodingUTF8);

    CFStringRef bi = CFDictionaryGetValue(d, CFSTR("buildID"));
    if (bi) CFStringGetCString(bi, sc_buildID, sizeof(sc_buildID), kCFStringEncodingUTF8);

    CFStringRef cn = CFDictionaryGetValue(d, CFSTR("carrierName"));
    if (cn) CFStringGetCString(cn, sc_carrierName, sizeof(sc_carrierName), kCFStringEncodingUTF8);

    CFStringRef mcc = CFDictionaryGetValue(d, CFSTR("carrierMCC"));
    if (mcc) CFStringGetCString(mcc, sc_carrierMCC, sizeof(sc_carrierMCC), kCFStringEncodingUTF8);

    CFStringRef mnc = CFDictionaryGetValue(d, CFSTR("carrierMNC"));
    if (mnc) CFStringGetCString(mnc, sc_carrierMNC, sizeof(sc_carrierMNC), kCFStringEncodingUTF8);

    CFStringRef iso = CFDictionaryGetValue(d, CFSTR("carrierISO"));
    if (iso) CFStringGetCString(iso, sc_carrierISO, sizeof(sc_carrierISO), kCFStringEncodingUTF8);

    CFStringRef rt = CFDictionaryGetValue(d, CFSTR("radioTech"));
    if (rt) CFStringGetCString(rt, sc_radioTech, sizeof(sc_radioTech), kCFStringEncodingUTF8);

    CFNumberRef nm = CFDictionaryGetValue(d, CFSTR("networkMode"));
    if (nm) CFNumberGetValue(nm, kCFNumberIntType, &sc_networkMode);

    CFStringRef ssid = CFDictionaryGetValue(d, CFSTR("wifiSSID"));
    if (ssid) CFStringGetCString(ssid, sc_wifiSSID, sizeof(sc_wifiSSID), kCFStringEncodingUTF8);

    CFStringRef bssid = CFDictionaryGetValue(d, CFSTR("wifiBSSID"));
    if (bssid) CFStringGetCString(bssid, sc_wifiBSSID, sizeof(sc_wifiBSSID), kCFStringEncodingUTF8);

    CFStringRef loc = CFDictionaryGetValue(d, CFSTR("localeIdentifier"));
    if (loc) CFStringGetCString(loc, sc_locale, sizeof(sc_locale), kCFStringEncodingUTF8);

    CFStringRef tz = CFDictionaryGetValue(d, CFSTR("timezoneIdentifier"));
    if (tz) CFStringGetCString(tz, sc_timezone, sizeof(sc_timezone), kCFStringEncodingUTF8);

    // Read target bundles — if empty and enabled, spoof for ALL apps
    CFArrayRef tb = CFDictionaryGetValue(d, CFSTR("targetBundles"));
    if (tb && CFArrayGetCount(tb) > 0) {
        // Check if current bundle is in target list
        // We'll check in the hook functions
    }

    CFRelease(plist);
}

// Check if current process should be spoofed
static bool sc_should_spoof(void) {
    if (!sc_enabled) return false;

    // Protected bundles — never spoof
    const char *bid = getenv("SC_BUNDLE_ID");
    if (!bid) {
        // Try to get bundle ID from executable path
        static char execPath[PATH_MAX];
        uint32_t size = PATH_MAX;
        if (_NSGetExecutablePath(execPath, &size) == 0) {
            // Check if this is a protected system process
            if (strstr(execPath, "SpringBoard") || strstr(execPath, "Preferences") ||
                strstr(execPath, "cfprefsd") || strstr(execPath, "lsd") ||
                strstr(execPath, "installd") || strstr(execPath, "debugserver")) {
                return false;
            }
        }
        return true; // No bundle ID check — spoof all
    }

    if (strcmp(bid, "com.apple.springboard") == 0) return false;
    if (strcmp(bid, "com.apple.Preferences") == 0) return false;
    if (strcmp(bid, "com.iosspoof.app") == 0) return false;

    return true;
}

// ============================================================================
// sysctl hooks — device spoof
// ============================================================================

int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
int sc_sysctlbyname_hook(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int r = orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);

    if (!sc_should_spoof() || !name) return r;

    // Device identity
    if (strcmp(name, "hw.machine") == 0) {
        const char *val = sc_productType;
        size_t need = strlen(val) + 1;
        if (oldlenp) { if (oldp && *oldlenp >= need) memcpy(oldp, val, need); *oldlenp = need; }
        return 0;
    }
    if (strcmp(name, "hw.model") == 0) {
        const char *val = sc_hardwareModel;
        size_t need = strlen(val) + 1;
        if (oldlenp) { if (oldp && *oldlenp >= need) memcpy(oldp, val, need); *oldlenp = need; }
        return 0;
    }
    if (strcmp(name, "hw.serialnumber") == 0 || strcmp(name, "hw.serialno") == 0) {
        if (sc_serial[0]) {
            size_t need = strlen(sc_serial) + 1;
            if (oldlenp) { if (oldp && *oldlenp >= need) memcpy(oldp, sc_serial, need); *oldlenp = need; }
            return 0;
        }
    }
    if (strcmp(name, "hw.UUID") == 0 || strcmp(name, "hw.uuid") == 0) {
        if (sc_udid[0]) {
            size_t need = strlen(sc_udid) + 1;
            if (oldlenp) { if (oldp && *oldlenp >= need) memcpy(oldp, sc_udid, need); *oldlenp = need; }
            return 0;
        }
    }
    if (strcmp(name, "hw.product") == 0 || strcmp(name, "hw.productname") == 0) {
        const char *val = sc_productType;
        size_t need = strlen(val) + 1;
        if (oldlenp) { if (oldp && *oldlenp >= need) memcpy(oldp, val, need); *oldlenp = need; }
        return 0;
    }
    if (strcmp(name, "kern.bootargs") == 0) {
        if (oldlenp) { *oldlenp = 1; if (oldp && *oldlenp >= 1) ((char*)oldp)[0] = 0; }
        return 0;
    }

    return r;
}

// ============================================================================
// access/stat/open — hide jailbreak files
// ============================================================================

static bool sc_is_jb_path(const char *path) {
    if (!path) return false;

    // statfs-based check (like roothide)
    struct statfs fs;
    if (statfs(path, &fs) == 0) {
        if (strcmp(fs.f_mntonname, "/") != 0) {
            // Not on rootfs — likely jailbreak
            if (strstr(fs.f_mntonname, "/var/jb") || strstr(fs.f_mntonname, "/private/preboot")) {
                return true;
            }
            if (strlen(fs.f_mntonname) > 1) return true;
        }
    }

    // Hardcoded paths
    static const char *jb_paths[] = {
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Applications/Installer.app",
        "/Applications/Filza.app", "/Applications/NewTerm.app",
        "/bin/bash", "/usr/sbin/sshd", "/usr/bin/ssh",
        "/etc/apt", "/etc/ssh/sshd_config",
        "/Library/MobileSubstrate", "/usr/lib/substitute",
        "/usr/lib/ellekit", "/usr/lib/TweakInject",
        "/var/lib/apt", "/var/cache/apt",
        "/var/checkra1n.dmg", "/.bootstrapped", "/.file",
        NULL
    };

    for (int i = 0; jb_paths[i]; i++) {
        if (strcmp(path, jb_paths[i]) == 0) return true;
    }

    static const char *jb_prefixes[] = {
        "/var/jb/", "/private/preboot/", "/usr/lib/ellekit",
        "/var/checkra1n", NULL
    };

    for (int i = 0; jb_prefixes[i]; i++) {
        if (strncmp(path, jb_prefixes[i], strlen(jb_prefixes[i])) == 0) return true;
    }

    return false;
}

int (*orig_access_sc)(const char *, int);
int sc_access_hook(const char *path, int mode) {
    if (sc_should_spoof() && sc_hideJailbreak && sc_is_jb_path(path)) return -1;
    return orig_access_sc(path, mode);
}

int (*orig_stat_sc)(const char *, struct stat *);
int sc_stat_hook(const char *path, struct stat *buf) {
    if (sc_should_spoof() && sc_hideJailbreak && sc_is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_stat_sc(path, buf);
}

int (*orig_lstat_sc)(const char *, struct stat *);
int sc_lstat_hook(const char *path, struct stat *buf) {
    if (sc_should_spoof() && sc_hideJailbreak && sc_is_jb_path(path)) { errno = ENOENT; return -1; }
    return orig_lstat_sc(path, buf);
}

// ============================================================================
// getenv — hide DYLD_INSERT_LIBRARIES
// ============================================================================

char *(*orig_getenv_sc)(const char *);
char *sc_getenv_hook(const char *name) {
    char *r = orig_getenv_sc(name);
    if (sc_should_spoof() && sc_hideJailbreak && name) {
        if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0 ||
            strcmp(name, "_MSSafeMode") == 0 ||
            strcmp(name, "ELLEKIT_HOME") == 0 ||
            strcmp(name, "SUBSTRATE_HOME") == 0 ||
            strcmp(name, "TWEAKS_ROOT") == 0 ||
            strcmp(name, "DOPAMINE_JB") == 0 ||
            strcmp(name, "ROOTHIDE_JB") == 0) {
            return NULL;
        }
    }
    return r;
}

// ============================================================================
// csops — hide CS_PLATFORM_BINARY, CS_DEBUGGED
// ============================================================================

extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int (*orig_csops_sc)(pid_t, unsigned int, void *, size_t);
int sc_csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int r = orig_csops_sc(pid, ops, useraddr, usersize);
    if (r == 0 && sc_should_spoof() && sc_hideJailbreak && ops == 0 && useraddr && usersize >= sizeof(uint32_t)) {
        uint32_t *flags = (uint32_t *)useraddr;
        *flags &= ~0x04000000; // CS_PLATFORM_BINARY
        *flags &= ~0x10000000; // CS_DEBUGGED
    }
    return r;
}

// ============================================================================
// fork — return -1 (jailbroken devices can fork)
// ============================================================================

pid_t (*orig_fork_sc)(void);
pid_t sc_fork_hook(void) {
    if (sc_should_spoof() && sc_hideJailbreak) { errno = ENOSYS; return -1; }
    return orig_fork_sc();
}

// ============================================================================
// _dyld_image_count / _dyld_get_image_name — hide injected dylibs
// ============================================================================

uint32_t (*orig_dyld_image_count_sc)(void);
uint32_t sc_dyld_image_count_hook(void) {
    uint32_t count = orig_dyld_image_count_sc();
    if (sc_should_spoof() && sc_hideJailbreak && count > 2) count -= 2;
    return count;
}

const char *(*orig_dyld_get_image_name_sc)(uint32_t);
const char *sc_dyld_get_image_name_hook(uint32_t image_index) {
    const char *name = orig_dyld_get_image_name_sc(image_index);
    if (sc_should_spoof() && sc_hideJailbreak && name) {
        if (strstr(name, "substrate") || strstr(name, "Substrate") ||
            strstr(name, "ellekit") || strstr(name, "ElleKit") ||
            strstr(name, "iOSSpoof") || strstr(name, "systemhook") ||
            strstr(name, "TweakLoader") || strstr(name, "tweakinject") ||
            strstr(name, "libhooker") || strstr(name, "Substitute")) {
            return "/System/Library/Frameworks/Foundation.framework/Foundation";
        }
    }
    return name;
}

// ============================================================================
// fork hook via syscall (for arm64 where fork() may be inlined)
// ============================================================================

int (*orig_task_for_pid_sc)(pid_t, mach_port_t *);
int sc_task_for_pid_hook(pid_t pid, mach_port_t *t) {
    if (sc_should_spoof() && sc_hideJailbreak) {
        if (t) *t = MACH_PORT_NULL;
        return 5; // KERN_FAILURE
    }
    return orig_task_for_pid_sc(pid, t);
}

// ============================================================================
// Init — called from systemhook main.c
// ============================================================================

__attribute__((visibility("default")))
void iosspoof_system_init(void) {
    sc_load_config();
    if (!sc_enabled) return;

    // Use litehook — instruction patching, no substrate needed
    // These hooks are invisible to app (no MSHookFunction pattern)

    // sysctl — device identity spoof
    litehook_hook_function(sysctlbyname, sc_sysctlbyname_hook);
    // Note: __sysctlbyname is already hooked by roothide for path remap
    // We hook the public sysctlbyname which calls __sysctlbyname internally

    // File access — hide jailbreak
    if (sc_hideJailbreak) {
        litehook_hook_function(access, sc_access_hook);
        litehook_hook_function(stat, sc_stat_hook);
        litehook_hook_function(lstat, sc_lstat_hook);
        litehook_hook_function(getenv, sc_getenv_hook);
        litehook_hook_function(fork, sc_fork_hook);
        litehook_hook_function(_dyld_image_count, sc_dyld_image_count_hook);
        litehook_hook_function(_dyld_get_image_name, sc_dyld_get_image_name_hook);

        // csops — already hooked by roothide on arm64, but we add our own layer
#ifndef __arm64e__
        litehook_hook_function(csops, sc_csops_hook);
#endif
    }
}
