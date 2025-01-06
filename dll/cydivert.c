/*
 * cydivert.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of CyDivert.
 *
 * CyDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * CyDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef UNICODE
#define UNICODE
#endif

#include <winsock2.h>
#include <windows.h>
#include <winioctl.h>

#include <stdio.h>
#include <stdlib.h>

#ifndef CYDIVERTEXPORT
#define CYDIVERTEXPORT extern
#endif
#include "cydivert.h"
#include "cydivert_device.h"

#define CYDIVERT_DRIVER_NAME           L"CyDivert"
#define CYDIVERT_DRIVER_SYS          L"\\" CYDIVERT_DRIVER_NAME L".sys"

#ifndef ERROR_DRIVER_FAILED_PRIOR_UNLOAD
#define ERROR_DRIVER_FAILED_PRIOR_UNLOAD    ((DWORD)654)
#endif

static BOOLEAN CyDivertIsDigit(char c);
static BOOLEAN CyDivertIsXDigit(char c);
static BOOLEAN CyDivertIsSpace(char c);
static BOOLEAN CyDivertIsAlNum(char c);
static char CyDivertToLower(char c);
static BOOLEAN CyDivertStrLen(const wchar_t *s, size_t maxlen,
    size_t *lenptr);
static BOOLEAN CyDivertStrCpy(wchar_t *dst, size_t dstlen,
    const wchar_t *src);
static int CyDivertStrCmp(const char *s, const char *t);
static BOOLEAN CyDivertAToI(const char *str, char **endptr, UINT32 *intptr,
    UINT size);
static BOOLEAN CyDivertAToX(const char *str, char **endptr, UINT32 *intptr,
    UINT size, BOOL prefix);
static UINT32 CyDivertDivTen128(UINT32 *a);

/*
 * Misc.
 */
#ifndef UINT8_MAX
#define UINT8_MAX       0xFF
#endif
#ifndef UINT16_MAX
#define UINT16_MAX      0xFFFF
#endif
#ifndef UINT32_MAX
#define UINT32_MAX      0xFFFFFFFF
#endif

#define IPPROTO_MH      135

#ifdef _MSC_VER

#pragma intrinsic(memcpy)
#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        ((UINT8 *)dst)[i] = ((const UINT8 *)src)[i];
    return dst;
}

#pragma intrinsic(memset)
#pragma function(memset)
void *memset(void *dst, int c, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++)
        ((UINT8 *)dst)[i] = (UINT8)c;
    return dst;
}

#define CYDIVERT_INLINE    __forceinline

#else       /* _MSC_VER */

#define CYDIVERT_INLINE    __attribute__((__always_inline__)) inline

#endif      /* _MSC_VER */

/*
 * Filter interpreter config.
 */
static BOOL CyDivertGetData(const VOID *packet, UINT packet_len, INT min,
    INT max, INT idx, PVOID data, UINT size);
#define CYDIVERT_GET_DATA(packet, packet_len, min, max, index, data, size) \
    CyDivertGetData((packet), (packet_len), (min), (max), (index), (data), \
        (size))

/*
 * Prototypes.
 */
static BOOLEAN CyDivertUse32Bit(void);
static BOOLEAN CyDivertGetDriverFileName(LPWSTR sys_str);
static BOOLEAN CyDivertDriverInstall(VOID);

/*
 * Include the helper API implementation.
 */
#include "cydivert_shared.c"
#include "cydivert_helper.c"

/*
 * Thread local.
 */
static DWORD cydivert_tls_idx;

/*
 * Current DLL hmodule.
 */
static HMODULE module = NULL;

/*
 * Dll Entry
 */
BOOL APIENTRY CyDivertDllEntry(HANDLE module0, DWORD reason, LPVOID reserved)
{
    HANDLE event;
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            module = module0;
            if ((cydivert_tls_idx = TlsAlloc()) == TLS_OUT_OF_INDEXES)
            {
                return FALSE;
            }
            // Fallthrough
        case DLL_THREAD_ATTACH:
            event = CreateEvent(NULL, FALSE, FALSE, NULL);
            if (event == NULL)
            {
                return FALSE;
            }
            TlsSetValue(cydivert_tls_idx, (LPVOID)event);
            break;

        case DLL_PROCESS_DETACH:
            event = (HANDLE)TlsGetValue(cydivert_tls_idx);
            if (event != (HANDLE)NULL)
            {
                CloseHandle(event);
            }
            TlsFree(cydivert_tls_idx);
            break;

        case DLL_THREAD_DETACH:
            event = (HANDLE)TlsGetValue(cydivert_tls_idx);
            if (event != (HANDLE)NULL)
            {
                CloseHandle(event);
            }
            break;
    }
    return TRUE;
}

/*
 * Test if we should use the 32-bit or 64-bit driver.
 */
static BOOLEAN CyDivertUse32Bit(void)
{
    BOOL is_wow64;

    if (sizeof(void *) == sizeof(UINT64))
    {
        return FALSE;
    }
    if (!IsWow64Process(GetCurrentProcess(), &is_wow64))
    {
        // Just guess:
        return FALSE;
    }
    return (is_wow64? FALSE: TRUE);
}

/*
 * Locate the CyDivert driver files.
 */
static BOOLEAN CyDivertGetDriverFileName(LPWSTR sys_str)
{
    size_t dir_len, sys_len;

    if (!CyDivertStrLen(CYDIVERT_DRIVER_SYS, MAX_PATH, &sys_len))
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    dir_len = (size_t)GetModuleFileName(module, sys_str, MAX_PATH);
    if (dir_len == 0)
    {
        return FALSE;
    }
    for (; dir_len > 0 && sys_str[dir_len] != L'\\'; dir_len--)
        ;
    if (sys_str[dir_len] != L'\\' || dir_len + sys_len + 1 >= MAX_PATH)
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }
    if (!CyDivertStrCpy(sys_str + dir_len, MAX_PATH-dir_len-1, CYDIVERT_DRIVER_SYS))
    {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    return TRUE;
}

/*
 * Register event log.  It is not an error if this function fails.
 */
static void CyDivertRegisterEventSource(const wchar_t *cydivert_sys)
{
    HKEY key;
    size_t len;
    DWORD types = 7;

    if (!CyDivertStrLen(cydivert_sys, MAX_PATH, &len))
    {
        return;
    }
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "System\\CurrentControlSet\\Services\\EventLog\\System\\CyDivert",
            0, NULL, REG_OPTION_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL)
                != ERROR_SUCCESS)
    {
        return;
    }
    RegSetValueExW(key, L"EventMessageFile", 0, REG_SZ, (LPBYTE)cydivert_sys,
            (len + 1) * sizeof(wchar_t));
    RegSetValueExA(key, "TypesSupported", 0, REG_DWORD, (LPBYTE)&types,
            sizeof(types));
    RegCloseKey(key);
}

/*
 * Install the CyDivert driver.
 */
static BOOLEAN CyDivertDriverInstall(VOID)
{
    DWORD err;
    SC_HANDLE manager = NULL, service = NULL;
    wchar_t cydivert_sys[MAX_PATH+1];
    HANDLE mutex = NULL;
    BOOL success = TRUE;

    // Create & lock a named mutex.  This is to stop two processes trying
    // to start the driver at the same time.
    mutex = CreateMutex(NULL, FALSE, L"CyDivertDriverInstallMutex");
    if (mutex == NULL)
    {
        return FALSE;
    }
    switch (WaitForSingleObject(mutex, INFINITE))
    {
        case WAIT_OBJECT_0: case WAIT_ABANDONED:
            break;
        default:
            return FALSE;
    }

    // Open the service manager:
    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (manager == NULL)
    {
        goto CyDivertDriverInstallExit;
    }

    // Check if the CyDivert service already exists; if so, start it.
    service = OpenService(manager, CYDIVERT_DEVICE_NAME, SERVICE_ALL_ACCESS);
    if (service != NULL)
    {
        goto CyDivertDriverInstallExit;
    }

    // Get driver file:
    if (!CyDivertGetDriverFileName(cydivert_sys))
    {
        goto CyDivertDriverInstallExit;
    }

    // Create the service:
    service = CreateService(manager, CYDIVERT_DEVICE_NAME,
        CYDIVERT_DEVICE_NAME, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, cydivert_sys, NULL, NULL,
        NULL, NULL, NULL);
    if (service == NULL)
    {
        if (GetLastError() == ERROR_SERVICE_EXISTS) 
        {
            service = OpenService(manager, CYDIVERT_DEVICE_NAME,
                SERVICE_ALL_ACCESS);
        }
        goto CyDivertDriverInstallExit;
    }

    // Register event logging:
    CyDivertRegisterEventSource(cydivert_sys);

CyDivertDriverInstallExit:

    success = (service != NULL);
    if (service != NULL)
    {
        // Start the service:
        success = StartService(service, 0, NULL);
        if (!success)
        {
            success = (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING);
        }
        else
        {
            // Mark the service for deletion.  This will cause the driver to
            // unload if (1) there are no more open handles, and (2) the
            // service is STOPPED or on system reboot.
            (VOID)DeleteService(service);
        }
    }

    err = GetLastError();
    if (manager != NULL)
    {
        CloseServiceHandle(manager);
    }
    if (service != NULL)
    {
        CloseServiceHandle(service);
    }
    ReleaseMutex(mutex);
    CloseHandle(mutex);
    SetLastError(err);

    return success;
}

/*
 * Perform an (overlapped) DeviceIoControl.
 */
static BOOL CyDivertIoControlEx(HANDLE handle, DWORD code,
    PCYDIVERT_IOCTL ioctl, PVOID buf, UINT len, UINT *iolen,
    LPOVERLAPPED overlapped)
{
    BOOL result;
    DWORD iolen0;

    result = DeviceIoControl(handle, code, ioctl, sizeof(CYDIVERT_IOCTL), buf,
        (DWORD)len, &iolen0, overlapped);
    if (result && iolen != NULL)
    {
        *iolen = (UINT)iolen0;
    }
    return result;
}

/*
 * Perform a DeviceIoControl.
 */
static BOOL CyDivertIoControl(HANDLE handle, DWORD code,
    PCYDIVERT_IOCTL ioctl, PVOID buf, UINT len, UINT *iolen)
{
    OVERLAPPED overlapped;
    DWORD iolen0;
    HANDLE event;

    event = (HANDLE)TlsGetValue(cydivert_tls_idx);
    if (event == (HANDLE)NULL)
    {
        event = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (event == NULL)
        {
            return FALSE;
        }
        TlsSetValue(cydivert_tls_idx, (LPVOID)event);
    }

    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.hEvent = event;
    if (!CyDivertIoControlEx(handle, code, ioctl, buf, len, iolen,
            &overlapped))
    {
        if (GetLastError() != ERROR_IO_PENDING ||
            !GetOverlappedResult(handle, &overlapped, &iolen0, TRUE))
        {
            return FALSE;
        }
        if (iolen != NULL)
        {
            *iolen = (UINT)iolen0;
        }
    }
    return TRUE;
}

/*
 * Open a CyDivert handle.
 */
HANDLE CyDivertOpen(const char *filter, CYDIVERT_LAYER layer, INT16 priority,
    UINT64 flags)
{
    CYDIVERT_FILTER *object;
    UINT obj_len;
    ERROR comp_err;
    DWORD err;
    HANDLE handle, pool;
    UINT64 filter_flags;
    CYDIVERT_IOCTL ioctl;
    CYDIVERT_VERSION version;

    // Static checks (should be compiled away if TRUE):
    if (sizeof(CYDIVERT_ADDRESS) != 80 ||
        sizeof(CYDIVERT_DATA_NETWORK) != 8 ||
        offsetof(CYDIVERT_DATA_FLOW, Protocol) != 56 ||
        offsetof(CYDIVERT_DATA_SOCKET, Protocol) != 56 ||
        offsetof(CYDIVERT_DATA_REFLECT, Priority) != 24 ||
        sizeof(CYDIVERT_FILTER) != 24 ||
        offsetof(CYDIVERT_ADDRESS, Reserved3) != 16)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    // Parameter checking:
    switch (layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
        case CYDIVERT_LAYER_FLOW:
        case CYDIVERT_LAYER_SOCKET:
        case CYDIVERT_LAYER_REFLECT:
            break;
        default:
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
    }
    if (!CYDIVERT_FLAGS_VALID(flags))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    if (priority < CYDIVERT_PRIORITY_MIN ||
        priority > CYDIVERT_PRIORITY_MAX)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }

    // Compile & analyze the filter:
    pool = HeapCreate(HEAP_NO_SERIALIZE, CYDIVERT_MIN_POOL_SIZE,
        CYDIVERT_MAX_POOL_SIZE);
    if (pool == NULL)
    {
        return FALSE;
    }
    object = HeapAlloc(pool, 0,
        CYDIVERT_FILTER_MAXLEN * sizeof(CYDIVERT_FILTER));
    if (object == NULL)
    {
        err = GetLastError();
        HeapDestroy(pool);
        SetLastError(err);
        return FALSE;
    }
    comp_err = CyDivertCompileFilter(filter, pool, layer, object, &obj_len);
    if (IS_ERROR(comp_err))
    {
        HeapDestroy(pool);
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    filter_flags = CyDivertAnalyzeFilter(layer, object, obj_len);

    // Attempt to open the CyDivert device:
    handle = CreateFile(L"\\\\.\\" CYDIVERT_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, INVALID_HANDLE_VALUE);
    if (handle == INVALID_HANDLE_VALUE)
    {
        err = GetLastError();
        if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND)
        {
            HeapDestroy(pool);
            SetLastError(err);
            return INVALID_HANDLE_VALUE;
        }

        // Open failed because the device isn't installed; install it now.
        if ((flags & CYDIVERT_FLAG_NO_INSTALL) != 0)
        {
            HeapDestroy(pool);
            SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
            return INVALID_HANDLE_VALUE;
        }
        SetLastError(0);
        if (!CyDivertDriverInstall())
        {
            err = GetLastError();
            err = (err == 0? ERROR_OPEN_FAILED: err);
            HeapDestroy(pool);
            SetLastError(err);
            return INVALID_HANDLE_VALUE;
        }
        handle = CreateFile(L"\\\\.\\" CYDIVERT_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            INVALID_HANDLE_VALUE);
        if (handle == INVALID_HANDLE_VALUE)
        {
            err = GetLastError();
            HeapDestroy(pool);
            SetLastError(err);
            return INVALID_HANDLE_VALUE;
        }
    }

    // Initialize the handle:
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.initialize.layer    = layer;
    ioctl.initialize.priority = (INT32)priority + CYDIVERT_PRIORITY_MAX;
    ioctl.initialize.flags    = flags;
    memset(&version, 0, sizeof(version));
    version.magic             = CYDIVERT_MAGIC_DLL;
    version.major             = CYDIVERT_VERSION_MAJOR;
    version.minor             = CYDIVERT_VERSION_MINOR;
    version.bits              = 8 * sizeof(void *);
    if (!CyDivertIoControl(handle, IOCTL_CYDIVERT_INITIALIZE, &ioctl,
            &version, sizeof(version), NULL))
    {
        err = GetLastError();
        CloseHandle(handle);
        HeapDestroy(pool);
        SetLastError(err);
        return INVALID_HANDLE_VALUE;
    }
    if (version.magic != CYDIVERT_MAGIC_SYS ||
        version.major != CYDIVERT_VERSION_MAJOR)
    {
        CloseHandle(handle);
        HeapDestroy(pool);
        SetLastError(ERROR_DRIVER_FAILED_PRIOR_UNLOAD);
        return INVALID_HANDLE_VALUE;
    }

    // Start the filter:
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.startup.flags = filter_flags;
    if (!CyDivertIoControl(handle, IOCTL_CYDIVERT_STARTUP, &ioctl,
            object, obj_len * sizeof(CYDIVERT_FILTER), NULL))
    {
        err = GetLastError();
        CloseHandle(handle);
        HeapDestroy(pool);
        SetLastError(err);
        return INVALID_HANDLE_VALUE;
    }
    HeapDestroy(pool);

    // Success!
    return handle;
}

/*
 * Receive a CyDivert packet.
 */
BOOL CyDivertRecv(HANDLE handle, PVOID pPacket, UINT packetLen, UINT *readLen,
    PCYDIVERT_ADDRESS addr)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.recv.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.recv.addr_len_ptr = (UINT64)(ULONG_PTR)NULL;
    return CyDivertIoControl(handle, IOCTL_CYDIVERT_RECV, &ioctl,
        pPacket, packetLen, readLen);
}

/*
 * Receive a CyDivert packet.
 */
BOOL CyDivertRecvEx(HANDLE handle, PVOID pPacket, UINT packetLen,
    UINT *readLen, UINT64 flags, PCYDIVERT_ADDRESS addr, UINT *pAddrLen,
    LPOVERLAPPED overlapped)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.recv.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.recv.addr_len_ptr = (UINT64)(ULONG_PTR)pAddrLen;
    if (flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (overlapped == NULL)
    {
        return CyDivertIoControl(handle, IOCTL_CYDIVERT_RECV, &ioctl,
            pPacket, packetLen, readLen);
    }
    else
    {
        return CyDivertIoControlEx(handle, IOCTL_CYDIVERT_RECV, &ioctl,
            pPacket, packetLen, readLen, overlapped);
    }
}

/*
 * Send a CyDivert packet.
 */
BOOL CyDivertSend(HANDLE handle, const VOID *pPacket, UINT packetLen,
    UINT *writeLen, const CYDIVERT_ADDRESS *addr)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.send.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.send.addr_len = sizeof(CYDIVERT_ADDRESS);
    return CyDivertIoControl(handle, IOCTL_CYDIVERT_SEND, &ioctl,
        (PVOID)pPacket, packetLen, writeLen);
}

/*
 * Send a CyDivert packet.
 */
BOOL CyDivertSendEx(HANDLE handle, const VOID *pPacket, UINT packetLen,
    UINT *writeLen, UINT64 flags, const CYDIVERT_ADDRESS *addr, UINT addrLen,
    LPOVERLAPPED overlapped)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.send.addr = (UINT64)(ULONG_PTR)addr;
    ioctl.send.addr_len = addrLen;
    if (flags != 0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (overlapped == NULL)
    {
        return CyDivertIoControl(handle, IOCTL_CYDIVERT_SEND, &ioctl,
            (PVOID)pPacket, packetLen, writeLen);
    }
    else
    {
        return CyDivertIoControlEx(handle, IOCTL_CYDIVERT_SEND, &ioctl,
            (PVOID)pPacket, packetLen, writeLen, overlapped);
    }
}

/*
 * Shutdown a CyDivert handle.
 */
BOOL CyDivertShutdown(HANDLE handle, CYDIVERT_SHUTDOWN how)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.shutdown.how = (UINT32)how;
    return CyDivertIoControl(handle, IOCTL_CYDIVERT_SHUTDOWN, &ioctl, NULL,
        0, NULL);
}

/*
 * Close a CyDivert handle.
 */
BOOL CyDivertClose(HANDLE handle)
{
    return CloseHandle(handle);
}

/*
 * Set a CyDivert parameter.
 */
BOOL CyDivertSetParam(HANDLE handle, CYDIVERT_PARAM param, UINT64 value)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.set_param.param = (UINT32)param;
    ioctl.set_param.val   = value;
    return CyDivertIoControl(handle, IOCTL_CYDIVERT_SET_PARAM, &ioctl, NULL,
        0, NULL);
}

/*
 * Get a CyDivert parameter.
 */
BOOL CyDivertGetParam(HANDLE handle, CYDIVERT_PARAM param, UINT64 *pValue)
{
    CYDIVERT_IOCTL ioctl;
    memset(&ioctl, 0, sizeof(ioctl));
    ioctl.get_param.param = (UINT32)param;
    return CyDivertIoControl(handle, IOCTL_CYDIVERT_GET_PARAM, &ioctl,
        pValue, sizeof(UINT64), NULL);
}

/*****************************************************************************/
/* REPLACEMENTS                                                              */
/*****************************************************************************/

static BOOLEAN CyDivertIsDigit(char c)
{
    return (c >= '0' && c <= '9');
}

static BOOLEAN CyDivertIsXDigit(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

static BOOLEAN CyDivertIsSpace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
            c == '\v');
}

static BOOLEAN CyDivertIsAlNum(char c)
{
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9');
}

static char CyDivertToLower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return 'a' + (c - 'A');
    return c;
}

static BOOLEAN CyDivertStrLen(const wchar_t *s, size_t maxlen,
    size_t *lenptr)
{
    size_t i;
    for (i = 0; s[i]; i++)
    {
        if (i > maxlen)
        {
            return FALSE;
        }
    }
    *lenptr = i;
    return TRUE;
}

static BOOLEAN CyDivertStrCpy(wchar_t *dst, size_t dstlen, const wchar_t *src)
{
    size_t i;
    for (i = 0; src[i]; i++)
    {
        if (i > dstlen)
        {
            return FALSE;
        }
        dst[i] = src[i];
    }
    if (i > dstlen)
    {
        return FALSE;
    }
    dst[i] = src[i];
    return TRUE;
}

static int CyDivertStrCmp(const char *s, const char *t)
{
    int cmp;
    size_t i;
    for (i = 0; ; i++)
    {
        cmp = s[i] - t[i];
        if (cmp != 0)
        {
            return cmp;
        }
        if (s[i] == '\0')
        {
            return 0;
        }
    }
}

static BOOLEAN CyDivertMul128(UINT32 *n, UINT32 m)
{
    UINT64 n64 = (UINT64)n[0] * (UINT64)m;
    n[0] = (UINT32)n64;
    n64 = (UINT64)n[1] * (UINT64)m + (n64 >> 32);
    n[1] = (UINT32)n64;
    n64 = (UINT64)n[2] * (UINT64)m + (n64 >> 32);
    n[2] = (UINT32)n64;
    n64 = (UINT64)n[3] * (UINT64)m + (n64 >> 32);
    n[3] = (UINT32)n64;
    return ((n64 >> 32) == 0);
}

static BOOLEAN CyDivertAdd128(UINT32 *n, UINT32 a)
{
    UINT64 n64 = (UINT64)n[0] + (UINT64)a;
    n[0] = (UINT32)n64;
    n64 = (UINT64)n[1] + (n64 >> 32);
    n[1] = (UINT32)n64;
    n64 = (UINT64)n[2] + (n64 >> 32);
    n[2] = (UINT32)n64;
    n64 = (UINT64)n[3] + (n64 >> 32);
    n[3] = (UINT32)n64;
    return ((n64 >> 32) == 0);
}

static BOOLEAN CyDivertAToI(const char *str, char **endptr, UINT32 *intptr,
    UINT size)
{
    size_t i = 0;
    UINT32 n[4] = {0};
    BOOLEAN result = TRUE;
    for (; str[i] && CyDivertIsDigit(str[i]); i++)
    {
        if (!CyDivertMul128(n, 10) || !CyDivertAdd128(n, str[i] - '0'))
        {
            return FALSE;
        }
    }
    if (i == 0)
    {
        return FALSE;
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    for (i = 0; i < size; i++)
    {
        intptr[i] = n[i];
    }
    for (; result && i < size && i < 4; i++)
    {
        result = result && (n[i] == 0);
    }
    return result;
}

static BOOLEAN CyDivertAToX(const char *str, char **endptr, UINT32 *intptr,
    UINT size, BOOL prefix)
{
    size_t i = 0;
    UINT32 n[4] = {0}, dig;
    BOOLEAN result = TRUE;
    if (prefix)
    {
        if (str[i] == '0' && str[i+1] == 'x')
        {
            i += 2;
        }
        else
        {
            return FALSE;
        }
    }
    for (; str[i] && CyDivertIsXDigit(str[i]); i++)
    {
        if (CyDivertIsDigit(str[i]))
        {
            dig = (UINT32)(str[i] - '0');
        }
        else
        {
            dig = (UINT32)(CyDivertToLower(str[i]) - 'a') + 0x0A;
        }
        if (!CyDivertMul128(n, 16) || !CyDivertAdd128(n, dig))
        {
            return FALSE;
        }
    }
    if (i == 0)
    {
        return FALSE;
    }
    if (endptr != NULL)
    {
        *endptr = (char *)str + i;
    }
    for (i = 0; i < size; i++)
    {
        intptr[i] = n[i];
    }
    for (; result && i < size && i < 4; i++)
    {
        result = result && (n[i] == 0);
    }
    return result;
}

/*
 * Divide by 10 and return the remainder.
 */
#define CYDIVERT_BIG_MUL_ROUND(a, c, r, i)                                 \
    do {                                                                    \
        UINT64 t = CYDIVERT_MUL64((UINT64)(a), (UINT64)(c));               \
        UINT k;                                                             \
        for (k = (i); k < 9 && t != 0; k++)                                 \
        {                                                                   \
            UINT64 s = (UINT64)(r)[k] + (t & 0xFFFFFFFF);                   \
            (r)[k] = (UINT32)s;                                             \
            t = (t >> 32) + (s >> 32);                                      \
        }                                                                   \
    } while (FALSE)
static UINT32 CyDivertDivTen128(UINT32 *a)
{
    const UINT32 c[5] =
    {
        0x9999999A, 0x99999999, 0x99999999, 0x99999999, 0x19999999
    };
    UINT32 r[9] = {0}, m[6] = {0};
    UINT i, j;

    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 5; j++)
        {
            CYDIVERT_BIG_MUL_ROUND(a[i], c[j], r, i+j);
        }
    }

    a[0] = r[5];
    a[1] = r[6];
    a[2] = r[7];
    a[3] = r[8];
    
    for (i = 0; i < 5; i++)
    {
        CYDIVERT_BIG_MUL_ROUND(r[i], 10, m, i);
    }
    
    return m[5];
}

