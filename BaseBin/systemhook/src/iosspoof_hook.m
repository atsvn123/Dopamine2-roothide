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
#include <sys/statvfs.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <spawn.h>
#include <dlfcn.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <net/if.h>
#include <time.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <CoreFoundation/CoreFoundation.h>
#include <UIKit/UIKit.h>
#include <SystemConfiguration/SystemConfiguration.h>

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
static char sc_cellularServiceID[64] = "00000000-0000-0000-0000-000000000000";
static char sc_cellularIPv4[32] = "10.23.42.10";
static char sc_cellularRouter[32] = "10.23.42.1";
static char sc_locale[32] = "";
static char sc_timezone[64] = "";
static bool sc_configLoaded = false;

static bool sc_is_wifi_ifname(const char *name) {
    return name && (!strcmp(name, "en0") || !strncmp(name, "awdl", 4) || !strncmp(name, "llw", 3));
}

static bool sc_is_cell_ifname(const char *name) {
    return name && (!strncmp(name, "pdp_ip", 6) || !strncmp(name, "ipsec", 5));
}

static NSDictionary *sc_cellular_ipv4_dictionary(void) {
    return @{
        @"PrimaryInterface": @"pdp_ip0",
        @"PrimaryService": [NSString stringWithUTF8String:sc_cellularServiceID],
        @"InterfaceName": @"pdp_ip0",
        @"Addresses": @[ [NSString stringWithUTF8String:sc_cellularIPv4] ],
        @"SubnetMasks": @[ @"255.255.255.255" ],
        @"Router": [NSString stringWithUTF8String:sc_cellularRouter],
        @"ConfigMethod": @"DHCP",
        @"ConfirmedInterfaceName": @"pdp_ip0"
    };
}

static void sc_set_sockaddr_ipv4(struct sockaddr *addr, const char *ip) {
    if (!addr || addr->sa_family != AF_INET || !ip) return;
    struct sockaddr_in *sin = (struct sockaddr_in *)addr;
    inet_pton(AF_INET, ip, &sin->sin_addr);
}

typedef const void * nw_path_t;
typedef const void * nw_interface_t;
typedef int32_t nw_path_status_t;
typedef int32_t nw_interface_type_t;

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

    CFStringRef csid = CFDictionaryGetValue(d, CFSTR("cellularServiceID"));
    if (csid) CFStringGetCString(csid, sc_cellularServiceID, sizeof(sc_cellularServiceID), kCFStringEncodingUTF8);

    CFStringRef cip = CFDictionaryGetValue(d, CFSTR("cellularIPv4"));
    if (cip) CFStringGetCString(cip, sc_cellularIPv4, sizeof(sc_cellularIPv4), kCFStringEncodingUTF8);

    CFStringRef cr = CFDictionaryGetValue(d, CFSTR("cellularRouter"));
    if (cr) CFStringGetCString(cr, sc_cellularRouter, sizeof(sc_cellularRouter), kCFStringEncodingUTF8);

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
// statfs / statvfs — storage spoof
// ============================================================================

static unsigned long long sc_fake_total_bytes = 0;
static unsigned long long sc_fake_free_bytes = 0;

static void sc_calc_storage(void) {
    if (sc_fake_total_bytes > 0) return;
    // Default: 256GB total, 85GB free
    sc_fake_total_bytes = 256ULL * 1024ULL * 1024ULL * 1024ULL;
    sc_fake_free_bytes = 85ULL * 1024ULL * 1024ULL * 1024ULL;
}

int (*orig_statfs_sc)(const char *, struct statfs *);
int sc_statfs_hook(const char *path, struct statfs *buf) {
    int r = orig_statfs_sc(path, buf);
    if (r == 0 && sc_should_spoof() && buf) {
        sc_calc_storage();
        if (buf->f_bsize > 0) {
            buf->f_blocks = sc_fake_total_bytes / buf->f_bsize;
            buf->f_bfree = sc_fake_free_bytes / buf->f_bsize;
            buf->f_bavail = sc_fake_free_bytes / buf->f_bsize;
        }
    }
    return r;
}

int (*orig_statvfs_sc)(const char *, struct statvfs *);
int sc_statvfs_hook(const char *path, struct statvfs *buf) {
    int r = orig_statvfs_sc(path, buf);
    if (r == 0 && sc_should_spoof() && buf) {
        sc_calc_storage();
        if (buf->f_frsize > 0) {
            buf->f_blocks = sc_fake_total_bytes / buf->f_frsize;
            buf->f_bfree = sc_fake_free_bytes / buf->f_frsize;
            buf->f_bavail = sc_fake_free_bytes / buf->f_frsize;
        }
    }
    return r;
}

// ============================================================================
// uname — device identity
// ============================================================================

int (*orig_uname_sc)(struct utsname *);
int sc_uname_hook(struct utsname *buf) {
    int r = orig_uname_sc(buf);
    if (r == 0 && sc_should_spoof()) {
        strlcpy(buf->machine, sc_productType, sizeof(buf->machine));
        strlcpy(buf->nodename, "iPhone", sizeof(buf->nodename));
    }
    return r;
}

// ============================================================================
// readlink / realpath — hide jbroot symlinks
// ============================================================================

ssize_t (*orig_readlink_sc)(const char *, char *, size_t);
ssize_t sc_readlink_hook(const char *path, char *buf, size_t bufsize) {
    ssize_t r = orig_readlink_sc(path, buf, bufsize);
    if (r > 0 && sc_should_spoof() && sc_hideJailbreak && path) {
        if (strstr(path, "/var/jb") || strstr(path, "/private/preboot")) {
            if (strstr(buf, "/var/jb") || strstr(buf, "jbroot") || strstr(buf, "substrate") || strstr(buf, "ellekit")) {
                strlcpy(buf, "/usr/lib", bufsize);
                r = strlen(buf);
            }
        }
    }
    return r;
}

char *(*orig_realpath_sc)(const char *, char *);
char *sc_realpath_hook(const char *path, char *resolved) {
    char *r = orig_realpath_sc(path, resolved);
    if (r && sc_should_spoof() && sc_hideJailbreak && path) {
        if (strstr(path, "/var/jb") || strstr(path, "/private/preboot")) {
            if (strstr(r, "/var/jb") || strstr(r, "jbroot") || strstr(r, "/private/preboot")) {
                strlcpy(r, path, PATH_MAX);
            }
        }
    }
    return r;
}

// ============================================================================
// time / gettimeofday — timestamp spoof
// ============================================================================

static long sc_timestamp_offset = 0;

time_t (*orig_time_sc)(time_t *);
time_t sc_time_hook(time_t *t) {
    time_t r = orig_time_sc(t);
    if (sc_should_spoof() && sc_timestamp_offset != 0) {
        r += sc_timestamp_offset;
        if (t) *t = r;
    }
    return r;
}

int (*orig_gettimeofday_sc)(struct timeval *, struct timezone *);
int sc_gettimeofday_hook(struct timeval *tv, struct timezone *tz) {
    int r = orig_gettimeofday_sc(tv, tz);
    if (r == 0 && sc_should_spoof() && sc_timestamp_offset != 0 && tv) {
        tv->tv_sec += sc_timestamp_offset;
    }
    return r;
}

// ============================================================================
// ObjC hooks — use method_exchangeImplementations (NOT MSHookFunction)
// This is invisible to banking apps — no instruction pattern to detect
// ============================================================================

// UIDevice
static NSString *(*orig_UIDevice_model)(id, SEL);
static NSString *sc_UIDevice_model(id self, SEL _cmd) {
    if (sc_should_spoof()) return @"iPhone";
    return orig_UIDevice_model(self, _cmd);
}

static NSString *(*orig_UIDevice_localizedModel)(id, SEL);
static NSString *sc_UIDevice_localizedModel(id self, SEL _cmd) {
    if (sc_should_spoof()) return [NSString stringWithUTF8String:sc_marketingName];
    return orig_UIDevice_localizedModel(self, _cmd);
}

static NSString *(*orig_UIDevice_systemVersion)(id, SEL);
static NSString *sc_UIDevice_systemVersion(id self, SEL _cmd) {
    if (sc_should_spoof()) return [NSString stringWithUTF8String:sc_systemVersion];
    return orig_UIDevice_systemVersion(self, _cmd);
}

// NSProcessInfo
static NSString *(*orig_NSProcessInfo_operatingSystemVersionString)(id, SEL);
static NSString *sc_NSProcessInfo_operatingSystemVersionString(id self, SEL _cmd) {
    if (sc_should_spoof()) {
        return [NSString stringWithFormat:@"Version %s (Build %s)", sc_systemVersion, sc_buildID];
    }
    return orig_NSProcessInfo_operatingSystemVersionString(self, _cmd);
}

static uint64_t (*orig_NSProcessInfo_physicalMemory)(id, SEL);
static uint64_t sc_NSProcessInfo_physicalMemory(id self, SEL _cmd) {
    if (sc_should_spoof()) return 6ULL * 1024ULL * 1024ULL * 1024ULL;
    return orig_NSProcessInfo_physicalMemory(self, _cmd);
}

static NSUInteger (*orig_NSProcessInfo_processorCount)(id, SEL);
static NSUInteger sc_NSProcessInfo_processorCount(id self, SEL _cmd) {
    if (sc_should_spoof()) return 6;
    return orig_NSProcessInfo_processorCount(self, _cmd);
}

// NWPath / NWInterface — cellular fake
// NWPathMonitor uses these to determine WiFi vs Cellular
static int32_t (*orig_NWPath_status)(id, SEL);
static int32_t sc_NWPath_status(id self, SEL _cmd) {
    if (sc_should_spoof()) return 1; // satisfied
    return orig_NWPath_status ? orig_NWPath_status(self, _cmd) : 1;
}

static BOOL (*orig_NWPath_isExpensive)(id, SEL);
static BOOL sc_NWPath_isExpensive(id self, SEL _cmd) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) return YES; // cellular = expensive
        if (sc_networkMode == 1) return NO;  // wifi = not expensive
    }
    return orig_NWPath_isExpensive ? orig_NWPath_isExpensive(self, _cmd) : NO;
}

static BOOL (*orig_NWPath_usesInterfaceType)(id, SEL, int32_t);
static BOOL sc_NWPath_usesInterfaceType(id self, SEL _cmd, int32_t interfaceType) {
    if (sc_should_spoof()) {
        // NWInterfaceType: 1=WiFi, 2=Cellular, 3=Wired, 4=Loopback
        if (sc_networkMode == 2) { // cellular mode
            if (interfaceType == 2) return YES; // cellular
            if (interfaceType == 1) return NO;  // wifi
        } else if (sc_networkMode == 1) { // wifi mode
            if (interfaceType == 1) return YES; // wifi
            if (interfaceType == 2) return NO;  // cellular
        }
    }
    return orig_NWPath_usesInterfaceType ? orig_NWPath_usesInterfaceType(self, _cmd, interfaceType) : NO;
}

static int32_t (*orig_NWInterface_type)(id, SEL);
static int32_t sc_NWInterface_type(id self, SEL _cmd) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) return 2; // Cellular
        if (sc_networkMode == 1) return 1; // WiFi
    }
    return orig_NWInterface_type ? orig_NWInterface_type(self, _cmd) : 0;
}

static NSString *(*orig_NWInterface_name)(id, SEL);
static NSString *sc_NWInterface_name(id self, SEL _cmd) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) return @"pdp_ip0";
        if (sc_networkMode == 1) return @"en0";
    }
    return orig_NWInterface_name ? orig_NWInterface_name(self, _cmd) : nil;
}

// SCNetworkReachability — cellular/WiFi flags
static Boolean (*orig_SCNetworkReachabilityGetFlags)(SCNetworkReachabilityRef, SCNetworkReachabilityFlags *);
static Boolean sc_SCNetworkReachabilityGetFlags_hook(SCNetworkReachabilityRef ref, SCNetworkReachabilityFlags *flags) {
    if (sc_should_spoof() && flags) {
        *flags = kSCNetworkReachabilityFlagsReachable;
        if (sc_networkMode == 2) {
            *flags |= kSCNetworkReachabilityFlagsIsWWAN;
            *flags &= ~kSCNetworkReachabilityFlagsIsDirect;
        } else if (sc_networkMode == 1) {
            *flags &= ~kSCNetworkReachabilityFlagsIsWWAN;
        }
        return true;
    }
    return false;
}

// CNCopyCurrentNetworkInfo — WiFi SSID/BSSID spoof
static CFDictionaryRef (*orig_CNCopyCurrentNetworkInfo)(CFStringRef);
static CFDictionaryRef sc_CNCopyCurrentNetworkInfo_hook(CFStringRef interfaceName) {
    if (!sc_should_spoof()) return NULL;
    // cellular mode: return NULL (no WiFi)
    if (sc_networkMode == 2) {
        return NULL;
    }
    // wifi mode: replace SSID/BSSID
    if (sc_networkMode == 1) {
        CFStringRef ssid = CFStringCreateWithCString(kCFAllocatorDefault, sc_wifiSSID, kCFStringEncodingUTF8);
        CFStringRef bssid = CFStringCreateWithCString(kCFAllocatorDefault, sc_wifiBSSID, kCFStringEncodingUTF8);
        return CFDictionaryCreate(NULL,
            (const void *[]){ CFSTR("SSID"), CFSTR("BSSID") },
            (const void *[]){ ssid, bssid },
            2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
    return NULL;
}

// getifaddrs / if_nametoindex / if_indextoname — hide WiFi/private IPv4 when fake cellular
static int (*orig_getifaddrs)(struct ifaddrs **);
static int sc_getifaddrs_hook(struct ifaddrs **ifap) {
    int r = orig_getifaddrs ? orig_getifaddrs(ifap) : -1;
    if (r != 0 || !ifap || !*ifap || !sc_should_spoof()) return r;

    struct ifaddrs *cur = *ifap;
    while (cur) {
        if (sc_networkMode == 2 && sc_is_wifi_ifname(cur->ifa_name)) {
            strlcpy(cur->ifa_name, "pdp_ip0", IFNAMSIZ);
            sc_set_sockaddr_ipv4(cur->ifa_addr, sc_cellularIPv4);
            sc_set_sockaddr_ipv4(cur->ifa_netmask, "255.255.255.255");
            sc_set_sockaddr_ipv4(cur->ifa_dstaddr, sc_cellularRouter);
        } else if (sc_networkMode == 1 && sc_is_cell_ifname(cur->ifa_name)) {
            strlcpy(cur->ifa_name, "en0", IFNAMSIZ);
        }
        cur = cur->ifa_next;
    }
    return r;
}

static unsigned int (*orig_if_nametoindex)(const char *);
static unsigned int sc_if_nametoindex_hook(const char *ifname) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2 && sc_is_wifi_ifname(ifname)) {
            unsigned int idx = orig_if_nametoindex ? orig_if_nametoindex("pdp_ip0") : 0;
            return idx ?: 0;
        }
        if (sc_networkMode == 1 && sc_is_cell_ifname(ifname)) {
            unsigned int idx = orig_if_nametoindex ? orig_if_nametoindex("en0") : 0;
            return idx ?: 0;
        }
    }
    return orig_if_nametoindex ? orig_if_nametoindex(ifname) : 0;
}

static char *(*orig_if_indextoname)(unsigned int, char *);
static char *sc_if_indextoname_hook(unsigned int ifindex, char *ifname) {
    char *r = orig_if_indextoname ? orig_if_indextoname(ifindex, ifname) : NULL;
    if (r && sc_should_spoof()) {
        if (sc_networkMode == 2 && sc_is_wifi_ifname(r)) {
            strlcpy(ifname, "pdp_ip0", IFNAMSIZ);
            return ifname;
        }
        if (sc_networkMode == 1 && sc_is_cell_ifname(r)) {
            strlcpy(ifname, "en0", IFNAMSIZ);
            return ifname;
        }
    }
    return r;
}

// Network.framework C API used by Swift NWPathMonitor.
static nw_path_status_t (*orig_nw_path_get_status)(nw_path_t);
static nw_path_status_t sc_nw_path_get_status_hook(nw_path_t path) {
    return 1; // satisfied
}

static bool (*orig_nw_path_is_expensive)(nw_path_t);
static bool sc_nw_path_is_expensive_hook(nw_path_t path) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) return true;
        if (sc_networkMode == 1) return false;
    }
    return false;
}

static bool (*orig_nw_path_is_constrained)(nw_path_t);
static bool sc_nw_path_is_constrained_hook(nw_path_t path) {
    return false;
}

static bool (*orig_nw_path_uses_interface_type)(nw_path_t, nw_interface_type_t);
static bool sc_nw_path_uses_interface_type_hook(nw_path_t path, nw_interface_type_t type) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) {
            if (type == 2) return true;
            if (type == 1) return false;
        } else if (sc_networkMode == 1) {
            if (type == 1) return true;
            if (type == 2) return false;
        }
    }
    return false;
}

static nw_interface_type_t (*orig_nw_interface_get_type)(nw_interface_t);
static nw_interface_type_t sc_nw_interface_get_type_hook(nw_interface_t interface) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) return 2;
        if (sc_networkMode == 1) return 1;
    }
    return 0;
}

static const char *(*orig_nw_interface_get_name)(nw_interface_t);
static const char *sc_nw_interface_get_name_hook(nw_interface_t interface) {
    if (sc_should_spoof()) {
        if (sc_networkMode == 2) return "pdp_ip0";
        if (sc_networkMode == 1) return "en0";
    }
    return NULL;
}

static CFPropertyListRef (*orig_SCDynamicStoreCopyValue)(SCDynamicStoreRef, CFStringRef);
static CFPropertyListRef sc_SCDynamicStoreCopyValue_hook(SCDynamicStoreRef store, CFStringRef key) {
    if (sc_should_spoof() && key) {
        NSString *k = (__bridge NSString *)key;
        if (sc_networkMode == 2) {
            if ([k containsString:@"State:/Network/Global/IPv4"]) {
                return CFBridgingRetain(sc_cellular_ipv4_dictionary());
            }
            if (([k containsString:@"State:/Network/Service"] && [k containsString:@"/IPv4"]) ||
                [k containsString:@"State:/Network/Interface/pdp_ip0/IPv4"]) {
                return CFBridgingRetain(sc_cellular_ipv4_dictionary());
            }
            if ([k containsString:@"State:/Network/Interface/en0"] ||
                [k containsString:@"State:/Network/Interface/awdl"] ||
                [k containsString:@"State:/Network/Interface/llw"] ||
                [k containsString:@"Setup:/Network/Interface/en0"] ||
                [k containsString:@"Setup:/Network/Interface/awdl"] ||
                [k containsString:@"Setup:/Network/Interface/llw"]) {
                return NULL;
            }
        } else if (sc_networkMode == 1) {
            if ([k containsString:@"State:/Network/Interface/pdp_ip"] ||
                [k containsString:@"Setup:/Network/Interface/pdp_ip"]) {
                return NULL;
            }
        }
    }
    return NULL;
}

static CFArrayRef (*orig_SCDynamicStoreCopyKeyList)(SCDynamicStoreRef, CFStringRef);
static CFArrayRef sc_SCDynamicStoreCopyKeyList_hook(SCDynamicStoreRef store, CFStringRef pattern) {
    return CFArrayCreate(NULL, NULL, 0, NULL);
}

static void sc_hook_objc_method(Class cls, SEL sel, IMP newImp, IMP *origImp) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    *origImp = method_setImplementation(m, newImp);
}

static void sc_hook_objc_class_method(Class cls, SEL sel, IMP newImp, IMP *origImp) {
    Method m = class_getClassMethod(cls, sel);
    if (!m) return;
    *origImp = method_setImplementation(m, newImp);
}

static void sc_install_objc_hooks(void) {
    // UIDevice
    Class uiDevice = objc_getClass("UIDevice");
    if (uiDevice) {
        sc_hook_objc_method(uiDevice, @selector(model), (IMP)sc_UIDevice_model, (IMP *)&orig_UIDevice_model);
        sc_hook_objc_method(uiDevice, @selector(localizedModel), (IMP)sc_UIDevice_localizedModel, (IMP *)&orig_UIDevice_localizedModel);
        sc_hook_objc_method(uiDevice, @selector(systemVersion), (IMP)sc_UIDevice_systemVersion, (IMP *)&orig_UIDevice_systemVersion);
    }

    // NSProcessInfo
    Class procInfo = objc_getClass("NSProcessInfo");
    if (procInfo) {
        sc_hook_objc_method(procInfo, @selector(operatingSystemVersionString), (IMP)sc_NSProcessInfo_operatingSystemVersionString, (IMP *)&orig_NSProcessInfo_operatingSystemVersionString);
        sc_hook_objc_method(procInfo, @selector(physicalMemory), (IMP)sc_NSProcessInfo_physicalMemory, (IMP *)&orig_NSProcessInfo_physicalMemory);
        sc_hook_objc_method(procInfo, @selector(processorCount), (IMP)sc_NSProcessInfo_processorCount, (IMP *)&orig_NSProcessInfo_processorCount);
    }

    // NWPath / NWInterface — cellular fake
    Class nwPath = objc_getClass("NWPath");
    if (nwPath) {
        sc_hook_objc_method(nwPath, @selector(status), (IMP)sc_NWPath_status, (IMP *)&orig_NWPath_status);
        sc_hook_objc_method(nwPath, @selector(isExpensive), (IMP)sc_NWPath_isExpensive, (IMP *)&orig_NWPath_isExpensive);
        sc_hook_objc_method(nwPath, @selector(usesInterfaceType:), (IMP)sc_NWPath_usesInterfaceType, (IMP *)&orig_NWPath_usesInterfaceType);
    }
    Class nwInterface = objc_getClass("NWInterface");
    if (nwInterface) {
        sc_hook_objc_method(nwInterface, @selector(type), (IMP)sc_NWInterface_type, (IMP *)&orig_NWInterface_type);
        sc_hook_objc_method(nwInterface, @selector(name), (IMP)sc_NWInterface_name, (IMP *)&orig_NWInterface_name);
    }
}

// ============================================================================
// Init — called from systemhook main.c
// ============================================================================

__attribute__((visibility("default")))
void iosspoof_system_init(void) {
    // Marker must be set even when spoofing is disabled, so the companion app
    // can reliably report that the custom systemhook is installed and loaded.
    setenv("SC_SYSTEMHOOK_ACTIVE", "1", 1);
    int marker = open("/var/mobile/Library/Preferences/com.iosspoof.systemhook.active", O_CREAT | O_WRONLY, 0644);
    if (marker >= 0) {
        write(marker, "1\n", 2);
        close(marker);
    }

    sc_load_config();
    if (!sc_enabled) return;

    // C function hooks via litehook (invisible to banking apps)
    litehook_hook_function(sysctlbyname, sc_sysctlbyname_hook);

    if (sc_hideJailbreak) {
        litehook_hook_function(access, sc_access_hook);
        litehook_hook_function(stat, sc_stat_hook);
        litehook_hook_function(lstat, sc_lstat_hook);
        litehook_hook_function(getenv, sc_getenv_hook);
        litehook_hook_function(fork, sc_fork_hook);
        litehook_hook_function(_dyld_image_count, sc_dyld_image_count_hook);
        litehook_hook_function(_dyld_get_image_name, sc_dyld_get_image_name_hook);
        litehook_hook_function(readlink, sc_readlink_hook);
        litehook_hook_function(realpath, sc_realpath_hook);

#ifndef __arm64e__
        litehook_hook_function(csops, sc_csops_hook);
#endif
        litehook_hook_function(task_for_pid, sc_task_for_pid_hook);
    }

    // Storage spoof
    litehook_hook_function(statfs, sc_statfs_hook);
    litehook_hook_function(statvfs, sc_statvfs_hook);

    // Device identity
    litehook_hook_function(uname, sc_uname_hook);

    // Interface/IP rewrite via getifaddrs needs an original trampoline.
    // litehook only exposes a 2-argument API, so keep this in user-space mode
    // until a safe trampoline wrapper is added for systemhook.

    // Timestamp spoof
    if (sc_timestamp_offset != 0) {
        litehook_hook_function(time, sc_time_hook);
        litehook_hook_function(gettimeofday, sc_gettimeofday_hook);
    }

    // Network hooks — SCNetworkReachability + CaptiveNetwork
    void *scFramework = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_NOW);
    if (scFramework) {
        void *scReach = dlsym(scFramework, "SCNetworkReachabilityGetFlags");
        if (scReach) litehook_hook_function(scReach, sc_SCNetworkReachabilityGetFlags_hook);

        void *cnInfo = dlsym(scFramework, "CNCopyCurrentNetworkInfo");
        if (cnInfo) litehook_hook_function(cnInfo, sc_CNCopyCurrentNetworkInfo_hook);

        void *copyValue = dlsym(scFramework, "SCDynamicStoreCopyValue");
        if (copyValue) litehook_hook_function(copyValue, sc_SCDynamicStoreCopyValue_hook);
        void *copyKeyList = dlsym(scFramework, "SCDynamicStoreCopyKeyList");
        if (copyKeyList) litehook_hook_function(copyKeyList, sc_SCDynamicStoreCopyKeyList_hook);
    }

    void *networkFramework = dlopen("/System/Library/Frameworks/Network.framework/Network", RTLD_NOW);
    if (networkFramework) {
        void *sym = dlsym(networkFramework, "nw_path_get_status");
        if (sym) litehook_hook_function(sym, sc_nw_path_get_status_hook);
        sym = dlsym(networkFramework, "nw_path_is_expensive");
        if (sym) litehook_hook_function(sym, sc_nw_path_is_expensive_hook);
        sym = dlsym(networkFramework, "nw_path_is_constrained");
        if (sym) litehook_hook_function(sym, sc_nw_path_is_constrained_hook);
        sym = dlsym(networkFramework, "nw_path_uses_interface_type");
        if (sym) litehook_hook_function(sym, sc_nw_path_uses_interface_type_hook);
        sym = dlsym(networkFramework, "nw_interface_get_type");
        if (sym) litehook_hook_function(sym, sc_nw_interface_get_type_hook);
        sym = dlsym(networkFramework, "nw_interface_get_name");
        if (sym) litehook_hook_function(sym, sc_nw_interface_get_name_hook);
    }

    // ObjC hooks — use method_setImplementation (NOT MSHookFunction)
    // This is invisible to banking apps — no instruction pattern to detect
    sc_install_objc_hooks();
}
