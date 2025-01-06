/*
 * cydivert.c
 * (C) 2022, all rights reserved,
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

#include <ntdef.h>

 // Required for a single driver binary to support multiple Windows versions using the POOL_NX_OPTIN opt-in mechanism.
 // (See: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/single-binary-opt-in-pool-nx-optin)
#define POOL_NX_OPTIN 1

// Required for deprecation of ExAllocatePool
// (See: https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/updating-deprecated-exallocatepool-calls)
#define POOL_ZERO_DOWN_LEVEL_SUPPORT

#include <ntifs.h>
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdf.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#define INITGUID
#include <guiddef.h>

#include "cydivert_device.h"
#include "cydivert_log.h"

/*
 * WDK function declaration cruft.
 */
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD cydivert_unload;
EVT_WDF_IO_IN_CALLER_CONTEXT cydivert_caller_context;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL cydivert_ioctl;
EVT_WDF_DEVICE_FILE_CREATE cydivert_create;
EVT_WDF_FILE_CLEANUP cydivert_cleanup;
EVT_WDF_FILE_CLOSE cydivert_close;
EVT_WDF_OBJECT_CONTEXT_DESTROY cydivert_destroy;
EVT_WDF_WORKITEM cydivert_worker;
EVT_WDF_WORKITEM cydivert_reflect_worker;

/*
 * Debugging macros.
 */
// #define DEBUG_ON
#ifdef DEBUG_ON
#define DEBUG(format, ...)                                                  \
    DbgPrint("CYDIVERT: " format "\n", ##__VA_ARGS__)
#define DEBUG_ERROR(format, status, ...)                                    \
    DbgPrint("CYDIVERT: *** ERROR ***: (status = 0x%x): " format "\n",     \
        (status), ##__VA_ARGS__)
static void DEBUG_BOUNDS_CHECK(PVOID start, PVOID end, PVOID access_start,
    PVOID access_end)
{
    if (access_end > end || access_start < start)
    {
        DbgPrint("CYDIVERT: *** BOUNDS ERROR ***: access %p..%p outside "
            "of buffer bounds %p..%p", access_start, access_end, start, end);
    }
}
#else       // DEBUG_ON
#define DEBUG(format, ...)
#define DEBUG_ERROR(format, status, ...)
#define DEBUG_BOUNDS_CHECK(start, end, access_start, access_end)
#endif

#define CYDIVERT_TAG                           'viDW'

/*
 * CyDivert reflect event.
 */
typedef struct context_s *context_t;
struct reflect_event_s
{
    LIST_ENTRY entry;                           // Entry.
    context_t context;                          // Context.
    CYDIVERT_EVENT event;                      // Event.
};
typedef struct reflect_event_s *reflect_event_t;

/*
 * CyDivert reflect context information.
 */
struct reflect_context_s
{
    LIST_ENTRY entry;                           // Open handle entry.
    LONGLONG timestamp;                         // Open timestamp.
    CYDIVERT_DATA_REFLECT data;                // Reflect data.
    struct reflect_event_s open_event;          // Open event.
    struct reflect_event_s close_event;         // Close event
    BOOL open;                                  // Seen open event?
};

/*
 * CyDivert context information.
 */
#define CYDIVERT_CONTEXT_SIZE                  (sizeof(struct context_s))
#define CYDIVERT_CONTEXT_MAXLAYERS             12
typedef enum
{
    CYDIVERT_CONTEXT_STATE_OPENING = 0xA0,     // Context is opening.
    CYDIVERT_CONTEXT_STATE_OPEN    = 0xB1,     // Context is open.
    CYDIVERT_CONTEXT_STATE_CLOSING = 0xC2,     // Context is closing.
    CYDIVERT_CONTEXT_STATE_CLOSED  = 0xD3,     // Context is closed.
} context_state_t;
struct context_s
{
    context_state_t state;                      // Context's state.
    KSPIN_LOCK lock;                            // Context-wide lock.
    WDFDEVICE device;                           // Context's device.
    WDFFILEOBJECT object;                       // Context's parent object.
    PEPROCESS process;                          // Context's process.
    LIST_ENTRY flow_set;                        // All active flows.
    UINT32 flow_v4_callout_id;                  // Flow established callout id.
    UINT32 flow_v6_callout_id;                  // Flow established callout id.
    LIST_ENTRY work_queue;                      // Work queue.
    LIST_ENTRY packet_queue;                    // Packet queue.
    ULONGLONG work_queue_length;                // Work queue length.
    ULONGLONG packet_queue_length;              // Packet queue length.
    ULONGLONG packet_queue_maxlength;           // Packet queue max length.
    ULONGLONG packet_queue_size;                // Packet queue size (in bytes).
    ULONGLONG packet_queue_maxsize;             // Packet queue max size.
    LONGLONG packet_queue_maxcounts;            // Packet queue max counts.
    ULONGLONG packet_queue_maxtime;             // Packet queue max time.
    WDFQUEUE read_queue;                        // Read queue.
    WDFWORKITEM worker;                         // Read worker.
    CYDIVERT_LAYER layer;                      // Context's layer.
    UINT64 flags;                               // Context's flags.
    BOOL initialized;                           // Context initialized?
    BOOL shutdown_recv;                         // Shutdown recv.
    BOOL shutdown_send;                         // Shutdown send.
    BOOL shutdown_recv_enabled;                 // Shutdown recv enabled?
    UINT32 priority;                            // Context (internal) priority.
    INT16 priority16;                           // Context (user) priority.
    GUID callout_guid[CYDIVERT_CONTEXT_MAXLAYERS];
                                                // Callout GUIDs.
    GUID filter_guid[CYDIVERT_CONTEXT_MAXLAYERS];
                                                // Filter GUIDs.
    BOOL installed[CYDIVERT_CONTEXT_MAXLAYERS];// What is installed?
    HANDLE engine_handle;                       // WFP engine handle.
    const CYDIVERT_FILTER *filter;             // Packet filter.
    UINT16 filter_len;                          // Length of filter.
    UINT64 filter_flags;                        // Filter flags.
    struct reflect_context_s reflect;           // Reflection info.
};
typedef struct context_s context_s;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(context_s, cydivert_context_get);

#define CYDIVERT_TIMEOUT(context, t0, t1)                                  \
     (((t1) >= (t0)? (t1) - (t0): (t0) - (t1)) >                            \
        (context)->packet_queue_maxcounts)

/*
 * CyDivert Layer information.
 */
typedef void (*cydivert_classify_t)(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
typedef void (*cydivert_flow_delete_notify_t)(
    IN UINT16 layer_id, IN UINT32 callout_id, IN UINT64 flow_context);
struct layer_s
{
    wchar_t *sublayer_name;                 // Sub-layer name.
    wchar_t *sublayer_desc;                 // Sub-layer description.
    wchar_t *callout_name;                  // Call-out name.
    wchar_t *callout_desc;                  // Call-out description.
    wchar_t *filter_name;                   // Filter name.
    wchar_t *filter_desc;                   // Filter description.
    const GUID *layer_guid;                 // WFP layer GUID.
    const GUID *sublayer_guid;              // Sub-layer GUID.
    cydivert_classify_t classify;          // Classify function.
    cydivert_flow_delete_notify_t flow_delete;
                                            // Flow delete function.
    UINT16 sublayer_weight;                 // Sub-layer weight.
};
typedef const struct layer_s *layer_t;

/*
 * CyDivert request context.
 */
struct req_context_s
{
    PCYDIVERT_ADDRESS addr;                // Pointer to address structure.
    UINT *addr_len_ptr;                     // Pointer to address length.
    UINT addr_len;                          // Address length (in bytes).
};
typedef struct req_context_s req_context_s;
typedef struct req_context_s *req_context_t;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(req_context_s, cydivert_req_context_get);

/*
 * CyDivert packet structure.  Layout is as follows:
 *
 *     +-----------------+------------+-------------+
 *     | struct packet_s | layer data | packet data |
 *     +-----------------+------------+-------------+
 *
 * Note the packet data must be pointer-aligned.
 */
#define CYDIVERT_WORK_QUEUE_LENGTH_MAX     4096
#ifdef _WIN64
#define CYDIVERT_ALIGN_SIZE                8
#define CYDIVERT_DATA_ALIGN                __declspec(align(8))
#else
#define CYDIVERT_ALIGN_SIZE                4
#define CYDIVERT_DATA_ALIGN                __declspec(align(4))
#endif
struct packet_s
{
    LIST_ENTRY entry;                       // Entry for queue.
    LONGLONG timestamp;                     // Packet timestamp.
    UINT32 layer:8;                         // Layer.
    UINT32 event:8;                         // Event.
    UINT32 sniffed:1;                       // Packet was sniffed?
    UINT32 outbound:1;                      // Packet is outound?
    UINT32 loopback:1;                      // Packet is loopback?
    UINT32 impostor:1;                      // Packet is impostor?
    UINT32 ipv6:1;                          // Packet is IPv6?
    UINT32 ip_checksum:1;                   // Packet has IPv4 checksum?
    UINT32 tcp_checksum:1;                  // Packet has TCP checksum?
    UINT32 udp_checksum:1;                  // Packet has UDP checksum?
    UINT32 icmp_checksum:1;                 // Packet has ICMP(V6) checksum?
    UINT32 match:1;                         // Packet matches filter?
    UINT32 padding:6;                       // Padding for alignment.
    UINT32 packet_size;                     // Packet total size.
    PVOID object;                           // Object associated with packet.
    UINT32 priority;                        // Packet priority.
    UINT32 packet_len;                      // Length of the packet.
    CYDIVERT_DATA_ALIGN UINT8 data[1];     // Packet/layer data.
};
typedef struct packet_s *packet_t;

#define CYDIVERT_DATA_SIZE(size)                                           \
    ((((size) + CYDIVERT_ALIGN_SIZE - 1) / CYDIVERT_ALIGN_SIZE) *         \
        CYDIVERT_ALIGN_SIZE)
#define CYDIVERT_PACKET_SIZE(layer_type, packet_len)                       \
    (sizeof(struct packet_s)-1 + CYDIVERT_DATA_SIZE(sizeof(layer_type)) +  \
        (packet_len))
#define CYDIVERT_LAYER_DATA_PTR(packet)                                    \
    ((packet)->data)
#define CYDIVERT_PACKET_DATA_PTR(layer_type, packet)                       \
    ((packet)->data + CYDIVERT_DATA_SIZE(sizeof(layer_type)))

/*
 * CyDivert flow structure.
 */
struct flow_s
{
    LIST_ENTRY entry;                       // Entry for tracking.
    context_t context;                      // Context.
    UINT64 flow_id;                         // WFP flow ID.
    UINT32 callout_id;                      // WFP callout ID.
    UINT16 layer_id;                        // WFP layout ID.
    BOOL inserted:1;                        // Flow inserted into context?
    BOOL deleted:1;                         // Flow deleted from context?
    BOOL outbound:1;                        // Flow is outound?
    BOOL loopback:1;                        // Flow is loopback?
    BOOL ipv6:1;                            // Flow is ipv6?
    CYDIVERT_DATA_FLOW data;               // Flow data.
};
typedef struct flow_s *flow_t;

/*
 * Misc.
 */
#define UINT8_MAX       0xFF
#define UINT16_MAX      0xFFFF
#define UINT32_MAX      0xFFFFFFFF
#define IPPROTO_MH      135

/*
 * Global state.
 */
static HANDLE inject_handle_forward = NULL;
static HANDLE injectv6_handle_forward = NULL;
static HANDLE inject_handle_in = NULL;
static HANDLE inject_handle_out = NULL;
static HANDLE injectv6_handle_in = NULL;
static HANDLE injectv6_handle_out = NULL;
static NDIS_HANDLE nbl_pool_handle = NULL;
static NDIS_HANDLE nb_pool_handle = NULL;
static HANDLE engine_handle = NULL;
static LONG priority_counter = 0;
static LONGLONG counts_per_ms = 0;
static MM_PAGE_PRIORITY no_write_flag = 0;
static MM_PAGE_PRIORITY no_exec_flag  = 0;
static LONG64 num_opens = 0;

/*
 * Priorities.
 */
static UINT32 cydivert_context_priority(UINT32 priority)
{
    UINT32 increment;
    priority = (priority << 16);
    increment = (UINT32)InterlockedIncrement(&priority_counter);
    priority |= (increment & 0x0000FFFF);
    return priority;
}

/*
 * Prototypes.
 */
static void cydivert_driver_unload(void);
extern VOID cydivert_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
    IN size_t in_length, IN size_t out_len, IN ULONG code);
static NTSTATUS cydivert_read(context_t context, WDFREQUEST request);
extern VOID cydivert_worker(IN WDFWORKITEM item);
static void cydivert_read_service(context_t context);
extern VOID cydivert_create(IN WDFDEVICE device, IN WDFREQUEST request,
    IN WDFFILEOBJECT object);
static NTSTATUS cydivert_install_provider(void);
static NTSTATUS cydivert_install_sublayer(layer_t layer);
static NTSTATUS cydivert_install_callouts(context_t context, UINT8 layer,
    UINT64 flags);
static NTSTATUS cydivert_install_callout(context_t context, UINT idx,
    layer_t layer, UINT32 *callout_id_ptr);
static void cydivert_uninstall_callouts(context_t context,
    context_state_t state);
extern VOID cydivert_cleanup(IN WDFFILEOBJECT object);
extern VOID cydivert_close(IN WDFFILEOBJECT object);
extern VOID cydivert_destroy(IN WDFOBJECT object);
static NTSTATUS cydivert_write(context_t context, WDFREQUEST request,
    req_context_t req_context);
static void NTAPI cydivert_inject_complete(VOID *context,
    NET_BUFFER_LIST *packets, BOOLEAN dispatch_level);
static void cydivert_inject_packet_too_big(packet_t packet);
static NTSTATUS cydivert_notify(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter);
static void cydivert_outbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_inbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_outbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_inbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_forward_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_forward_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_flow_established_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_flow_established_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_resource_assignment_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_resource_assignment_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_resource_release_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_resource_release_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_auth_connect_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_auth_connect_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_endpoint_closure_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_endpoint_closure_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_auth_listen_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_auth_listen_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_auth_recv_accept_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_auth_recv_accept_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_flow_established_classify(context_t context, 
    IN UINT64 flow_id, IN PCYDIVERT_DATA_FLOW flow_data, IN BOOL ipv4,
    IN BOOL outbound, IN BOOL loopback, OUT FWPS_CLASSIFY_OUT0 *result);
static void cydivert_flow_delete_notify(UINT16 layer_id, UINT32 callout_id,
    UINT64 flow_context);
static void cydivert_socket_classify(context_t context,
    PCYDIVERT_DATA_SOCKET socket_data, CYDIVERT_EVENT event, BOOL ipv4,
    BOOL outbound, BOOL loopback, FWPS_CLASSIFY_OUT0 *result);
static void cydivert_network_classify(context_t context,
    IN PCYDIVERT_DATA_NETWORK network_data, IN BOOL ipv4, IN BOOL outbound,
    IN BOOL loopback, IN BOOL reassembled, IN UINT advance, IN OUT void *data,
    OUT FWPS_CLASSIFY_OUT0 *result);
static BOOL cydivert_queue_work(context_t context, PVOID packet,
    ULONG packet_len, PNET_BUFFER_LIST buffers, PVOID object,
    CYDIVERT_LAYER layer, PVOID layer_data, CYDIVERT_EVENT event,
    UINT64 flags, UINT32 priority, BOOL ipv4, BOOL outbound, BOOL loopback,
    BOOL impostor, BOOL match, LONGLONG timestamp);
static void cydivert_queue_packet(context_t context, packet_t packet);
static NTSTATUS cydivert_inject_packet(packet_t packet);
static void cydivert_free_packet(packet_t packet);
static BOOL cydivert_copy_data(PNET_BUFFER buffer, PVOID data, UINT size);
static BOOL cydivert_get_data(PNET_BUFFER buffer, UINT length, INT min,
    INT max, INT idx, PVOID data, UINT size);
static BOOL cydivert_parse_headers(PNET_BUFFER buffer, BOOL ipv4,
    BOOL *fragment_ptr, PCYDIVERT_IPHDR *ip_header_ptr,
    PCYDIVERT_IPV6HDR *ipv6_header_ptr, PCYDIVERT_ICMPHDR *icmp_header_ptr,
    PCYDIVERT_ICMPV6HDR *icmpv6_header_ptr, PCYDIVERT_TCPHDR *tcp_header_ptr,
    PCYDIVERT_UDPHDR *udp_header_ptr, UINT8 *proto_ptr, UINT *header_len_ptr,
    UINT *payload_len_ptr);
static BOOL cydivert_filter(PNET_BUFFER buffer, CYDIVERT_LAYER layer,
    const VOID *layer_data, LONGLONG timestamp, CYDIVERT_EVENT event,
    BOOL ipv4, BOOL outbound, BOOL loopback, BOOL impostor, BOOL frag_mode,
    const CYDIVERT_FILTER *filter);
static const CYDIVERT_FILTER *cydivert_filter_compile(
    const CYDIVERT_FILTER *ioctl_filter, size_t ioctl_filter_len,
    CYDIVERT_LAYER layer);
static NTSTATUS cydivert_reflect_init(WDFOBJECT parent);
static void cydivert_reflect_close(void);
static void cydivert_reflect_open_event(context_t context);
static void cydivert_reflect_close_event(context_t context);
static void cydivert_reflect_event_notify(context_t context,
    LONGLONG timestamp, CYDIVERT_EVENT event);
static void cydivert_reflect_established_notify(context_t context,
    LONGLONG timestamp);
extern void cydivert_reflect_worker(IN WDFWORKITEM item);
static void cydivert_log_event(PEPROCESS process, PDRIVER_OBJECT driver,
    const wchar_t *msg_str);

/*
 * CyDivert provider GUIDs
 */
DEFINE_GUID(CYDIVERT_PROVIDER_GUID,
    0x450EC398, 0x1EAF, 0x49F5,
    0x85, 0xE0, 0x22, 0x8F, 0x0D, 0x29, 0x39, 0x21);
#define CYDIVERT_PROVIDER_NAME CYDIVERT_DEVICE_NAME
#define CYDIVERT_PROVIDER_DESC CYDIVERT_DEVICE_NAME L" provider"

/*
 * CyDivert sublayer GUIDs
 */
DEFINE_GUID(CYDIVERT_SUBLAYER_INBOUND_IPV4_GUID,
    0x82A99281, 0x0389, 0x4DE2,
    0xAE, 0x2D, 0xA4, 0x51, 0x59, 0x16, 0x26, 0x06);
DEFINE_GUID(CYDIVERT_SUBLAYER_OUTBOUND_IPV4_GUID,
    0xB0BB07C6, 0x3B3B, 0x41FE,
    0x83, 0x8B, 0xD8, 0x37, 0xDD, 0xB8, 0x75, 0x41);
DEFINE_GUID(CYDIVERT_SUBLAYER_INBOUND_IPV6_GUID,
    0xD7674846, 0x3AB5, 0x4E93,
    0x82, 0xD0, 0x2F, 0xCC, 0x03, 0xA2, 0x88, 0x7A);
DEFINE_GUID(CYDIVERT_SUBLAYER_OUTBOUND_IPV6_GUID,
    0x6672F761, 0xA0F2, 0x4578,
    0x92, 0x50, 0x09, 0x03, 0x0D, 0x4E, 0x8C, 0x46);
DEFINE_GUID(CYDIVERT_SUBLAYER_FORWARD_IPV4_GUID,
    0x4622DCC6, 0xBD71, 0x48ED,
    0x9D, 0x1A, 0x72, 0xC9, 0x0D, 0xEB, 0xA1, 0x74);
DEFINE_GUID(CYDIVERT_SUBLAYER_FORWARD_IPV6_GUID,
    0x7E5B39EC, 0xB54C, 0x41B3,
    0xA7, 0x99, 0x47, 0x5E, 0x57, 0x41, 0xA4, 0x33);
DEFINE_GUID(CYDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV4_GUID,
    0x53D6C270, 0xEB79, 0x44CD,
    0x83, 0xCD, 0x14, 0x34, 0xE6, 0x13, 0x91, 0x68);
DEFINE_GUID(CYDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV6_GUID,
    0x44B0CDED, 0xAA11, 0x4704,
    0x92, 0xA7, 0x99, 0xD2, 0xB7, 0x59, 0x7A, 0x68);
DEFINE_GUID(CYDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV4_GUID,
    0x736848B6, 0xBE0D, 0x4A8D,
    0xA0, 0xC2, 0xE2, 0x02, 0xDC, 0x29, 0x32, 0xBC);
DEFINE_GUID(CYDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV6_GUID,
    0xF3458E58, 0xD123, 0x439B,
    0xB6, 0x40, 0x74, 0x3C, 0xC7, 0x53, 0x9E, 0x36);
DEFINE_GUID(CYDIVERT_SUBLAYER_RESOURCE_RELEASE_IPV4_GUID,
    0x02366282, 0x9099, 0x43A7,
    0x95, 0xC3, 0xAB, 0x52, 0x87, 0xB3, 0xF2, 0xDC);
DEFINE_GUID(CYDIVERT_SUBLAYER_RESOURCE_RELEASE_IPV6_GUID,
    0x60FCA14A, 0x7677, 0x45D2,
    0xBB, 0x5C, 0x15, 0xDB, 0xAE, 0x4B, 0x7B, 0x6B);
DEFINE_GUID(CYDIVERT_SUBLAYER_AUTH_CONNECT_IPV4_GUID,
    0x2F97411F, 0x6350, 0x450A,
    0xBF, 0x45, 0x4C, 0x0B, 0xC1, 0xDB, 0x3F, 0x7E);
DEFINE_GUID(CYDIVERT_SUBLAYER_AUTH_CONNECT_IPV6_GUID,
    0x7BAFEEEB, 0x84F0, 0x4BB0,
    0x91, 0x1F, 0x7E, 0x62, 0x2D, 0x73, 0x24, 0x2C);
DEFINE_GUID(CYDIVERT_SUBLAYER_ENDPOINT_CLOSURE_IPV4_GUID,
    0x8180D216, 0xB3BD, 0x4014,
    0x99, 0x69, 0xA3, 0xDF, 0x0F, 0x3E, 0x61, 0x85);
DEFINE_GUID(CYDIVERT_SUBLAYER_ENDPOINT_CLOSURE_IPV6_GUID,
    0x2535A264, 0xEC8B, 0x49CC,
    0xA4, 0xD6, 0x83, 0x81, 0xD7, 0x5F, 0xAB, 0xE6);
DEFINE_GUID(CYDIVERT_SUBLAYER_AUTH_LISTEN_IPV4_GUID,
    0x49F2A9AD, 0x805E, 0x4328,
    0xBB, 0xDA, 0x92, 0x57, 0xB5, 0x18, 0x3A, 0x40);
DEFINE_GUID(CYDIVERT_SUBLAYER_AUTH_LISTEN_IPV6_GUID,
    0xC1BB250E, 0xDE07, 0x41AB,
    0x82, 0xEE, 0xAD, 0x7B, 0xFF, 0x13, 0xCE, 0x35);
DEFINE_GUID(CYDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV4_GUID,
    0x7A012579, 0xC75A, 0x4D29,
    0xB7, 0x47, 0x04, 0xAD, 0x3C, 0x7B, 0x32, 0x69);
DEFINE_GUID(CYDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV6_GUID,
    0x1C51DD53, 0x6BA4, 0x4149,
    0x89, 0x97, 0x1C, 0xD4, 0x8B, 0x51, 0x1B, 0x7D);

/*
 * CyDivert supported layers.
 */
static const struct layer_s cydivert_layer_inbound_network_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerInboundNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer network (inbound IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutInboundNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout network (inbound IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterInboundNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter network (inbound IPv4)",
    &FWPM_LAYER_INBOUND_IPPACKET_V4,
    &CYDIVERT_SUBLAYER_INBOUND_IPV4_GUID,
    cydivert_inbound_network_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_INBOUND_NETWORK_IPV4                                \
    (&cydivert_layer_inbound_network_ipv4)

static const struct layer_s cydivert_layer_outbound_network_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerOutboundNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer network (outbound IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutOutboundNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout network (outbound IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterOutboundNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter network (outbound IPv4)",
    &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
    &CYDIVERT_SUBLAYER_OUTBOUND_IPV4_GUID,
    cydivert_outbound_network_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV4                               \
    (&cydivert_layer_outbound_network_ipv4)

static const struct layer_s cydivert_layer_inbound_network_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerInboundNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer network (inbound IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutInboundNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout network (inbound IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterInboundNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter network (inbound IPv6)",
    &FWPM_LAYER_INBOUND_IPPACKET_V6,
    &CYDIVERT_SUBLAYER_INBOUND_IPV6_GUID,
    cydivert_inbound_network_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_INBOUND_NETWORK_IPV6                                \
    (&cydivert_layer_inbound_network_ipv6)

static const struct layer_s cydivert_layer_outbound_network_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerOutboundNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer network (outbound IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutOutboundNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout network (outbound IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterOutboundNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter network (outbound IPv6)",
    &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
    &CYDIVERT_SUBLAYER_OUTBOUND_IPV6_GUID,
    cydivert_outbound_network_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV6                               \
    (&cydivert_layer_outbound_network_ipv6)

static const struct layer_s cydivert_layer_forward_network_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerForwardNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer network (forward IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutForwardNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout network (forward IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterForwardNetworkIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter network (forward IPv4)",
    &FWPM_LAYER_IPFORWARD_V4,
    &CYDIVERT_SUBLAYER_FORWARD_IPV4_GUID,
    cydivert_forward_network_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_FORWARD_NETWORK_IPV4                                \
    (&cydivert_layer_forward_network_ipv4)

static const struct layer_s cydivert_layer_forward_network_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerForwardNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer network (forward IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutForwardNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout network (forward IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterForwardNetworkIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter network (forward IPv6)",
    &FWPM_LAYER_IPFORWARD_V6,
    &CYDIVERT_SUBLAYER_FORWARD_IPV6_GUID,
    cydivert_forward_network_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_FORWARD_NETWORK_IPV6                                \
    (&cydivert_layer_forward_network_ipv6)

static const struct layer_s cydivert_layer_resource_assignment_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerResourceAssignmentIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer resource assignment (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutResourceAssignmentIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout resource assignment (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterResourceAssignmentIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter resource assignment (IPv4)",
    &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
    &CYDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV4_GUID,
    cydivert_resource_assignment_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV4                            \
    (&cydivert_layer_resource_assignment_ipv4)

static const struct layer_s cydivert_layer_resource_assignment_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerResourceAssignmentIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer resource assignment (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutResourceAssignmentIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout resource assignment (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterResourceAssignmentIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter resource assignment (IPv6)",
    &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
    &CYDIVERT_SUBLAYER_RESOURCE_ASSIGNMENT_IPV6_GUID,
    cydivert_resource_assignment_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV6                            \
    (&cydivert_layer_resource_assignment_ipv6)

static const struct layer_s cydivert_layer_resource_release_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerResourceReleaseIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer resource release (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutResourceReleaseIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout resource release (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterResourceReleaseIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter resource release (IPv4)",
    &FWPM_LAYER_ALE_RESOURCE_RELEASE_V4,
    &CYDIVERT_SUBLAYER_RESOURCE_RELEASE_IPV4_GUID,
    cydivert_resource_release_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_RESOURCE_RELEASE_IPV4                              \
    (&cydivert_layer_resource_release_ipv4)

static const struct layer_s cydivert_layer_resource_release_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerResourceReleaseIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer resource release (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutResourceReleaseIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout resource release (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterResourceReleaseIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter resource release (IPv6)",
    &FWPM_LAYER_ALE_RESOURCE_RELEASE_V6,
    &CYDIVERT_SUBLAYER_RESOURCE_RELEASE_IPV6_GUID,
    cydivert_resource_release_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_RESOURCE_RELEASE_IPV6                              \
    (&cydivert_layer_resource_release_ipv6)

static const struct layer_s cydivert_layer_auth_connect_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerAuthConnectIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer auth connect (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutAuthConnectIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout auth connect (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterAuthConnectIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter auth connect (IPv4)",
    &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
    &CYDIVERT_SUBLAYER_AUTH_CONNECT_IPV4_GUID,
    cydivert_auth_connect_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_AUTH_CONNECT_IPV4                                   \
    (&cydivert_layer_auth_connect_ipv4)

static const struct layer_s cydivert_layer_auth_connect_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerAuthConnectIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer auth connect (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutAuthConnectIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout auth connect (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterAuthConnectIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter auth connect (IPv6)",
    &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    &CYDIVERT_SUBLAYER_AUTH_CONNECT_IPV6_GUID,
    cydivert_auth_connect_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_AUTH_CONNECT_IPV6                                   \
    (&cydivert_layer_auth_connect_ipv6)

static const struct layer_s cydivert_layer_endpoint_closure_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerEndpointClosureIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer endpoint closure (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutEndpointClosureIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout endpoint closure (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterEndpointClosureIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter endpoint closure (IPv4)",
    &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V4,
    &CYDIVERT_SUBLAYER_ENDPOINT_CLOSURE_IPV4_GUID,
    cydivert_endpoint_closure_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV4                               \
    (&cydivert_layer_endpoint_closure_ipv4)

static const struct layer_s cydivert_layer_endpoint_closure_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerEndpointClosureIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer endpoint closure (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutEndpointClosureIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout endpoint closure (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterEndpointClosureIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter endpoint closure (IPv6)",
    &FWPM_LAYER_ALE_ENDPOINT_CLOSURE_V6,
    &CYDIVERT_SUBLAYER_ENDPOINT_CLOSURE_IPV6_GUID,
    cydivert_endpoint_closure_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV6                               \
    (&cydivert_layer_endpoint_closure_ipv6)

static const struct layer_s cydivert_layer_auth_listen_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerAuthListenIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer auth listen (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutAuthListenIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout auth listen (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterAuthListenIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter auth listen (IPv4)",
    &FWPM_LAYER_ALE_AUTH_LISTEN_V4,
    &CYDIVERT_SUBLAYER_AUTH_LISTEN_IPV4_GUID,
    cydivert_auth_listen_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_AUTH_LISTEN_IPV4                                    \
    (&cydivert_layer_auth_listen_ipv4)

static const struct layer_s cydivert_layer_auth_listen_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerAuthListenIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer auth listen (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutAuthListenIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout auth listen (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterAuthListenIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter auth listen (IPv6)",
    &FWPM_LAYER_ALE_AUTH_LISTEN_V6,
    &CYDIVERT_SUBLAYER_AUTH_LISTEN_IPV6_GUID,
    cydivert_auth_listen_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_AUTH_LISTEN_IPV6                                    \
    (&cydivert_layer_auth_listen_ipv6)

static const struct layer_s cydivert_layer_auth_recv_accept_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerAuthRecvAcceptIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer auth recv accept (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutAuthRecvAcceptIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout auth recv accept (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterAuthRecvAcceptIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter auth recv accept (IPv4)",
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    &CYDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV4_GUID,
    cydivert_auth_recv_accept_v4_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV4                               \
    (&cydivert_layer_auth_recv_accept_ipv4)

static const struct layer_s cydivert_layer_auth_recv_accept_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerAuthRecvAcceptIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer auth recv accept (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutAuthRecvAcceptIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout auth recv accept (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterAuthRecvAcceptIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter auth recv accept (IPv6)",
    &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    &CYDIVERT_SUBLAYER_AUTH_RECV_ACCEPT_IPV6_GUID,
    cydivert_auth_recv_accept_v6_classify,
    NULL,
    UINT16_MAX
};
#define CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV6                               \
    (&cydivert_layer_auth_recv_accept_ipv6)

static const struct layer_s cydivert_layer_flow_established_ipv4 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerFlowEstablishedIPv4",
    L"" CYDIVERT_LAYER_NAME L" sublayer flow established (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutFlowEstablishedIPv4",
    L"" CYDIVERT_LAYER_NAME L" callout flow established (IPv4)",
    L"" CYDIVERT_LAYER_NAME L"_FilterFlowEstablishedIPv4",
    L"" CYDIVERT_LAYER_NAME L" filter flow established (IPv4)",
    &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4,
    &CYDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV4_GUID,
    cydivert_flow_established_v4_classify,
    cydivert_flow_delete_notify,
    UINT16_MAX
};
#define CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV4                               \
    (&cydivert_layer_flow_established_ipv4)

static const struct layer_s cydivert_layer_flow_established_ipv6 =
{
    L"" CYDIVERT_LAYER_NAME L"_SubLayerFlowEstablishedIPv6",
    L"" CYDIVERT_LAYER_NAME L" sublayer flow established (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_CalloutFlowEstablishedIPv6",
    L"" CYDIVERT_LAYER_NAME L" callout flow established (IPv6)",
    L"" CYDIVERT_LAYER_NAME L"_FilterFlowEstablishedIPv6",
    L"" CYDIVERT_LAYER_NAME L" filter flow established (IPv6)",
    &FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6,
    &CYDIVERT_SUBLAYER_FLOW_ESTABLISHED_IPV6_GUID,
    cydivert_flow_established_v6_classify,
    cydivert_flow_delete_notify,
    UINT16_MAX
};
#define CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV6                               \
    (&cydivert_layer_flow_established_ipv6)

/*
 * Filter interpreter config.
 */
#define CYDIVERT_INLINE    __forceinline
#define CYDIVERT_GET_DATA(packet, packet_len, min, max, index, data, size) \
    cydivert_get_data((PNET_BUFFER)(packet), (packet_len), (min), (max),   \
        (index), (data), (size))

/*
 * Shared functions.
 */
#include "cydivert_shared.c"

/*
 * CyDivert malloc/free.
 */
static PVOID cydivert_malloc(SIZE_T size, BOOL paged)
{
    PVOID retval = NULL;
    POOL_TYPE pool = (paged ? PagedPool : NonPagedPool);
    if (size == 0)
    {
        return NULL;
    }

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    retval = ExAllocatePool2(pool, size, CYDIVERT_TAG);
#else
    retval = ExAllocatePoolZero(pool, size, CYDIVERT_TAG);
#endif

    return retval;
}
static VOID cydivert_free(PVOID ptr)
{
    if (ptr != NULL)
    {
        ExFreePoolWithTag(ptr, CYDIVERT_TAG);
    }
}

/*
 * CyDivert driver entry routine.
 */
extern NTSTATUS DriverEntry(IN PDRIVER_OBJECT driver_obj,
    IN PUNICODE_STRING reg_path)
{
    WDF_DRIVER_CONFIG config;
    WDFDRIVER driver;
    PWDFDEVICE_INIT device_init;
    WDFDEVICE device;
    WDF_FILEOBJECT_CONFIG file_config;
    WDF_IO_QUEUE_CONFIG queue_config;
    WDFQUEUE queue;
    WDF_OBJECT_ATTRIBUTES obj_attrs;
    NET_BUFFER_LIST_POOL_PARAMETERS nbl_pool_params;
    NET_BUFFER_POOL_PARAMETERS nb_pool_params;
    RTL_OSVERSIONINFOW version;
    LARGE_INTEGER freq;
    NTSTATUS status;

    // Must be called before any memory allocation occurs
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    DECLARE_CONST_UNICODE_STRING(device_name,
        L"\\Device\\" CYDIVERT_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(dos_device_name,
        L"\\??\\" CYDIVERT_DEVICE_NAME);

    DEBUG("LOAD: loading CyDivert driver");

    // Use the "no execute" pool if available:
    status = RtlGetVersion(&version);
    if (NT_SUCCESS(status))
    {
        if (version.dwMajorVersion > 6 ||
            (version.dwMajorVersion == 6 && version.dwMinorVersion >= 2))
        {
            no_exec_flag   = (MM_PAGE_PRIORITY)0x40000000;
                                                // MdlMappingNoExecute
            no_write_flag  = (MM_PAGE_PRIORITY)0x80000000;
                                                // MdlMappingNoWrite
        }
    }
    
    // Initialize timer info.
    KeQueryPerformanceCounter(&freq);
    counts_per_ms = freq.QuadPart / 1000;
    counts_per_ms = (counts_per_ms == 0? 1: counts_per_ms);

    // Configure ourself as a non-PnP driver:
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = cydivert_unload;
    status = WdfDriverCreate(driver_obj, reg_path, WDF_NO_OBJECT_ATTRIBUTES,
        &config, &driver);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF driver", status);
        goto driver_entry_exit;
    }
    device_init = WdfControlDeviceInitAllocate(driver,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    if (device_init == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate WDF control device init structure",
            status);
        goto driver_entry_exit;
    }
    WdfDeviceInitSetDeviceType(device_init, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetIoType(device_init, WdfDeviceIoDirect);
    status = WdfDeviceInitAssignName(device_init, &device_name);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF device name", status);
        WdfDeviceInitFree(device_init);
        goto driver_entry_exit;
    }
    WDF_FILEOBJECT_CONFIG_INIT(&file_config, cydivert_create, cydivert_close,
        cydivert_cleanup);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&obj_attrs, context_s);
    obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
    obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
    obj_attrs.EvtDestroyCallback = cydivert_destroy;
    WdfDeviceInitSetFileObjectConfig(device_init, &file_config, &obj_attrs);
    WdfDeviceInitSetIoInCallerContextCallback(device_init,
        cydivert_caller_context);
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    status = WdfDeviceCreate(&device_init, &obj_attrs, &device);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WDF control device", status);
        WdfDeviceInitFree(device_init);
        goto driver_entry_exit;
    }
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue_config,
        WdfIoQueueDispatchParallel);
    queue_config.EvtIoRead          = NULL;
    queue_config.EvtIoWrite         = NULL;
    queue_config.EvtIoDeviceControl = cydivert_ioctl;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    obj_attrs.ExecutionLevel = WdfExecutionLevelPassive;
    obj_attrs.SynchronizationScope = WdfSynchronizationScopeNone;
    status = WdfIoQueueCreate(device, &queue_config, &obj_attrs, &queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create default WDF queue", status);
        goto driver_entry_exit;
    }
    status = WdfDeviceCreateSymbolicLink(device, &dos_device_name);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create device symbolic link", status);
        goto driver_entry_exit;
    }
    WdfControlFinishInitializing(device);

    // Create the packet injection handles.
    status = FwpsInjectionHandleCreate0(AF_INET,
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &inject_handle_forward);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP forward packet injection handle",
            status);
        goto driver_entry_exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET6,
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &injectv6_handle_forward);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP ipv6 forward packet injection handle",
            status);
        goto driver_entry_exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET,
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &inject_handle_in);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP inbound packet injection handle",
            status);
        goto driver_entry_exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET,
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &inject_handle_out);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP outbound packet injection handle",
            status);
        goto driver_entry_exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET6,
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &injectv6_handle_in);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP ipv6 inbound packet injection handle",
            status);
        goto driver_entry_exit;
    }
    status = FwpsInjectionHandleCreate0(AF_INET6,
        FWPS_INJECTION_TYPE_NETWORK | FWPS_INJECTION_TYPE_FORWARD,
        &injectv6_handle_out);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP ipv6 outbound packet injection handle",
            status);
        goto driver_entry_exit;
    }

    // Create a NET_BUFFER_LIST pool handle.
    RtlZeroMemory(&nbl_pool_params, sizeof(nbl_pool_params));
    nbl_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nbl_pool_params.Header.Revision =
        NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    nbl_pool_params.Header.Size = sizeof(nbl_pool_params);
    nbl_pool_params.fAllocateNetBuffer = TRUE;
    nbl_pool_params.PoolTag = CYDIVERT_TAG;
    nbl_pool_params.DataSize = 0;
    nbl_pool_handle = NdisAllocateNetBufferListPool(NULL, &nbl_pool_params);
    if (nbl_pool_handle == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate net buffer list pool", status);
        goto driver_entry_exit;
    }

    // Create a NET_BUFFER pool handle.
    RtlZeroMemory(&nb_pool_params, sizeof(nb_pool_params));
    nb_pool_params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    nb_pool_params.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.Header.Size =
        NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
    nb_pool_params.PoolTag = CYDIVERT_TAG;
    nb_pool_params.DataSize = 0;
    nb_pool_handle = NdisAllocateNetBufferPool(NULL, &nb_pool_params);
    if (nb_pool_handle == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate net buffer pool", status);
        goto driver_entry_exit;
    }

    // Open a handle to the filter engine:
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL,
        &engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP engine handle", status);
        goto driver_entry_exit;
    }

    // Register WFP sub-layers:
    status = FwpmTransactionBegin0(engine_handle, 0);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to begin WFP transaction", status);
        FwpmTransactionAbort0(engine_handle);
        goto driver_entry_exit;
    }
    status = cydivert_install_provider();
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to install provider", status);
        FwpmTransactionAbort0(engine_handle);
        goto driver_entry_exit;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_INBOUND_NETWORK_IPV4);
    if (!NT_SUCCESS(status))
    {
driver_entry_sublayer_error:
        DEBUG_ERROR("failed to install WFP sub-layer", status);
        FwpmTransactionAbort0(engine_handle);
        goto driver_entry_exit;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_INBOUND_NETWORK_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_FORWARD_NETWORK_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_FORWARD_NETWORK_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(
        CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(
        CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_RESOURCE_RELEASE_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_RESOURCE_RELEASE_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_AUTH_CONNECT_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_AUTH_CONNECT_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_AUTH_LISTEN_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_AUTH_LISTEN_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV4);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = cydivert_install_sublayer(CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV6);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_sublayer_error;
    }
    status = FwpmTransactionCommit0(engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        FwpmTransactionAbort0(engine_handle);
        goto driver_entry_exit;
    }

    status = cydivert_reflect_init((WDFOBJECT)device);
    if (!NT_SUCCESS(status))
    {
        goto driver_entry_exit;
    }

driver_entry_exit:

    if (!NT_SUCCESS(status))
    {
        cydivert_driver_unload();
    }

    return status;
}

/*
 * CyDivert driver unload routine.
 */
extern VOID cydivert_unload(IN WDFDRIVER driver_0)
{
    PDRIVER_OBJECT driver = WdfDriverWdmGetDriverObject(driver_0);
    cydivert_driver_unload();
    cydivert_log_event(PsGetCurrentProcess(), driver, L"UNLOAD");
}

/*
 * CyDivert driver unload.
 */
static void cydivert_driver_unload(void)
{
    NTSTATUS status;

    DEBUG("UNLOAD: unloading the CyDivert driver");

    if (inject_handle_forward != NULL)
    {
        FwpsInjectionHandleDestroy0(inject_handle_forward);
    }
    if (injectv6_handle_forward != NULL)
    {
        FwpsInjectionHandleDestroy0(injectv6_handle_forward);
    }
    if (inject_handle_in != NULL)
    {
        FwpsInjectionHandleDestroy0(inject_handle_in);
    }
    if (inject_handle_out != NULL)
    {
        FwpsInjectionHandleDestroy0(inject_handle_out);
    }
    if (injectv6_handle_in != NULL)
    {
        FwpsInjectionHandleDestroy0(injectv6_handle_in);
    }
    if (injectv6_handle_out != NULL)
    {
        FwpsInjectionHandleDestroy0(injectv6_handle_out);
    }
    if (nbl_pool_handle != NULL)
    {
        NdisFreeNetBufferListPool(nbl_pool_handle);
    }
    if (nb_pool_handle != NULL)
    {
        NdisFreeNetBufferPool(nb_pool_handle);
    }
    if (engine_handle != NULL)
    {
        status = FwpmTransactionBegin0(engine_handle, 0);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to begin WFP transaction", status);
            FwpmTransactionAbort0(engine_handle);
            FwpmEngineClose0(engine_handle);
            return;
        }
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_INBOUND_NETWORK_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_INBOUND_NETWORK_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_FORWARD_NETWORK_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_FORWARD_NETWORK_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_RESOURCE_RELEASE_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_RESOURCE_RELEASE_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_AUTH_CONNECT_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_AUTH_CONNECT_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_AUTH_LISTEN_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_AUTH_LISTEN_IPV6->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV4->sublayer_guid);
        FwpmSubLayerDeleteByKey0(engine_handle,
            CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV6->sublayer_guid);

        FwpmProviderDeleteByKey0(engine_handle,
            &CYDIVERT_PROVIDER_GUID);

        status = FwpmTransactionCommit0(engine_handle);
        if (!NT_SUCCESS(status))
        {
            FwpmTransactionAbort0(engine_handle);
            DEBUG_ERROR("failed to commit WFP transaction", status);
        }
        FwpmEngineClose0(engine_handle);
    }
}

/*
 * Register provider.
 */
static NTSTATUS cydivert_install_provider()
{
    FWPM_PROVIDER0 provider;

    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey             = CYDIVERT_PROVIDER_GUID;
    provider.displayData.name        = CYDIVERT_PROVIDER_NAME;
    provider.displayData.description = CYDIVERT_PROVIDER_DESC;

    // We don't care about the install result as this provider
    // is only for passing HLK test.
    FwpmProviderAdd0(engine_handle, &provider, NULL);
    return STATUS_SUCCESS;
}

/*
 * Register a sub-layer.
 */
static NTSTATUS cydivert_install_sublayer(layer_t layer)
{
    FWPM_SUBLAYER0 sublayer;
    NTSTATUS status;

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey             = *(layer->sublayer_guid);
    sublayer.displayData.name        = layer->sublayer_name;
    sublayer.displayData.description = layer->sublayer_desc;
    sublayer.weight                  = layer->sublayer_weight;

    status = FwpmSubLayerAdd0(engine_handle, &sublayer, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP sub-layer", status);
    }
    
    return status;
}

/*
 * CyDivert create routine.
 */
extern VOID cydivert_create(IN WDFDEVICE device, IN WDFREQUEST request,
    IN WDFFILEOBJECT object)
{
    WDF_IO_QUEUE_CONFIG queue_config;
    WDF_WORKITEM_CONFIG item_config;
    WDF_OBJECT_ATTRIBUTES obj_attrs;
    FWPM_SESSION0 session;
    PIRP irp;
    NTSTATUS status = STATUS_SUCCESS;
    UINT8 i;
    context_t context = cydivert_context_get(object);

    DEBUG("CREATE: creating a new CyDivert context (context=%p)", context);

    // Initialise the new context:
    RtlZeroMemory(context, sizeof(struct context_s));
    context->state  = CYDIVERT_CONTEXT_STATE_OPENING;
    context->device = device;
    context->object = object;
    context->work_queue_length = 0;
    context->packet_queue_length = 0;
    context->packet_queue_maxlength = CYDIVERT_PARAM_QUEUE_LENGTH_DEFAULT;
    context->packet_queue_size = 0;
    context->packet_queue_maxsize = CYDIVERT_PARAM_QUEUE_SIZE_DEFAULT;
    context->packet_queue_maxcounts =
        CYDIVERT_PARAM_QUEUE_TIME_DEFAULT * counts_per_ms;
    context->packet_queue_maxtime = CYDIVERT_PARAM_QUEUE_TIME_DEFAULT;
    context->layer = 0;
    context->flags = 0;
    context->initialized = FALSE;
    context->shutdown_recv = FALSE;
    context->shutdown_recv_enabled = FALSE;
    context->shutdown_send = FALSE;
    context->priority = 0;
    context->priority16 = 0;
    context->filter = NULL;
    context->filter_len = 0;
    context->filter_flags = 0;
    context->worker = NULL;
    context->process = NULL;
    for (i = 0; i < CYDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        context->installed[i] = FALSE;
    }
    KeInitializeSpinLock(&context->lock);
    InitializeListHead(&context->flow_set);
    context->flow_v4_callout_id = 0;
    context->flow_v6_callout_id = 0;
    InitializeListHead(&context->work_queue);
    InitializeListHead(&context->packet_queue);
    for (i = 0; i < CYDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        status = ExUuidCreate(&context->callout_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create callout GUID", status);
            goto cydivert_create_exit;
        }
        status = ExUuidCreate(&context->filter_guid[i]);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to create filter GUID", status);
            goto cydivert_create_exit;
        }
    }
    WDF_IO_QUEUE_CONFIG_INIT(&queue_config, WdfIoQueueDispatchManual);
    status = WdfIoQueueCreate(device, &queue_config, WDF_NO_OBJECT_ATTRIBUTES,
        &context->read_queue);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create I/O read queue", status);
        goto cydivert_create_exit;
    }
    WDF_WORKITEM_CONFIG_INIT(&item_config, cydivert_worker);
    item_config.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    obj_attrs.ParentObject = (WDFOBJECT)object;
    status = WdfWorkItemCreate(&item_config, &obj_attrs, &context->worker);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create read service work item", status);
        goto cydivert_create_exit;
    }
    RtlZeroMemory(&session, sizeof(session));
    session.flags |= FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session,
        &context->engine_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create WFP engine handle", status);
        goto cydivert_create_exit;
    }
    RtlZeroMemory(&context->reflect, sizeof(context->reflect));
    irp = WdfRequestWdmGetIrp(request);
    context->process = IoGetRequestorProcess(irp);
    if (context->process == NULL)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        DEBUG_ERROR("no process associated with IRP", status);
        goto cydivert_create_exit;
    }
    ObfReferenceObject(context->process);

cydivert_create_exit:

    // Clean-up on error:
    if (!NT_SUCCESS(status))
    {
        context->state = CYDIVERT_CONTEXT_STATE_CLOSED;
        if (context->read_queue != NULL)
        {
            WdfObjectDelete(context->read_queue);
        }
        if (context->worker != NULL)
        {
            WdfObjectDelete(context->worker);
        }
        // process/engine_handle handled by cydivert_destroy()
    }

    WdfRequestComplete(request, status);
}

/*
 * Register all WFP callouts.
 */
static NTSTATUS cydivert_install_callouts(context_t context, UINT8 layer,
    UINT64 flags)
{
    UINT8 i, j;
    layer_t layers[CYDIVERT_CONTEXT_MAXLAYERS];
    UINT32 *callout_ids[CYDIVERT_CONTEXT_MAXLAYERS] = {NULL};
    BOOL inbound, outbound, ipv4, ipv6, bind, connect, listen,
        accept, close;
    NTSTATUS status = STATUS_SUCCESS;

    inbound  = ((flags & CYDIVERT_FILTER_FLAG_INBOUND) != 0);
    outbound = ((flags & CYDIVERT_FILTER_FLAG_OUTBOUND) != 0);
    ipv4     = ((flags & CYDIVERT_FILTER_FLAG_IP) != 0);
    ipv6     = ((flags & CYDIVERT_FILTER_FLAG_IPV6) != 0);
    bind     = ((flags & CYDIVERT_FILTER_FLAG_EVENT_SOCKET_BIND) != 0);
    connect  = ((flags & CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CONNECT) != 0);
    listen   = ((flags & CYDIVERT_FILTER_FLAG_EVENT_SOCKET_LISTEN) != 0);
    accept   = ((flags & CYDIVERT_FILTER_FLAG_EVENT_SOCKET_ACCEPT) != 0);
    close    = ((flags & CYDIVERT_FILTER_FLAG_EVENT_SOCKET_CLOSE) != 0);

    i = 0;
    switch (layer)
    {
        case CYDIVERT_LAYER_NETWORK:
            if (inbound && ipv4)
            {
                layers[i++] = CYDIVERT_LAYER_INBOUND_NETWORK_IPV4;
            }
            if (outbound && ipv4)
            {
                layers[i++] = CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV4;
            }
            if (inbound && ipv6)
            {
                layers[i++] = CYDIVERT_LAYER_INBOUND_NETWORK_IPV6;
            }
            if (outbound && ipv6)
            {
                layers[i++] = CYDIVERT_LAYER_OUTBOUND_NETWORK_IPV6;
            }
            break;

        case CYDIVERT_LAYER_NETWORK_FORWARD:
            if (ipv4)
            {
                layers[i++] = CYDIVERT_LAYER_FORWARD_NETWORK_IPV4;
            }
            if (ipv6)
            {
                layers[i++] = CYDIVERT_LAYER_FORWARD_NETWORK_IPV6;
            }
            break;
        
        case CYDIVERT_LAYER_FLOW:
            if (ipv4)
            {
                callout_ids[i] = &context->flow_v4_callout_id;
                layers[i++] = CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV4;
            }
            if (ipv6)
            {
                callout_ids[i] = &context->flow_v6_callout_id;
                layers[i++] = CYDIVERT_LAYER_FLOW_ESTABLISHED_IPV6;
            }
            break;

        case CYDIVERT_LAYER_SOCKET:
            if (ipv4 && bind)
            {
                layers[i++] = CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV4;
            }
            if (ipv4 && connect)
            {
                layers[i++] = CYDIVERT_LAYER_AUTH_CONNECT_IPV4;
            }
            if (ipv4 && listen)
            {
                layers[i++] = CYDIVERT_LAYER_AUTH_LISTEN_IPV4;
            }
            if (ipv4 && accept)
            {
                layers[i++] = CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV4;
            }
            if (ipv4 && close)
            {
                layers[i++] = CYDIVERT_LAYER_RESOURCE_RELEASE_IPV4;
                layers[i++] = CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV4;
            }
            if (ipv6 && bind)
            {
                layers[i++] = CYDIVERT_LAYER_RESOURCE_ASSIGNMENT_IPV6;
            }
            if (ipv6 && connect)
            {
                layers[i++] = CYDIVERT_LAYER_AUTH_CONNECT_IPV6;
            }
            if (ipv6 && listen)
            {
                layers[i++] = CYDIVERT_LAYER_AUTH_LISTEN_IPV6;
            }
            if (ipv6 && accept)
            {
                layers[i++] = CYDIVERT_LAYER_AUTH_RECV_ACCEPT_IPV6;
            }
            if (ipv6 && close)
            {
                layers[i++] = CYDIVERT_LAYER_RESOURCE_RELEASE_IPV6;
                layers[i++] = CYDIVERT_LAYER_ENDPOINT_CLOSURE_IPV6;
            }
            break;

        case CYDIVERT_LAYER_REFLECT:
            break;

        default:
            return STATUS_INVALID_PARAMETER;
    }

    for (j = 0; j < i; j++)
    {
        status = cydivert_install_callout(context, j, layers[j],
            callout_ids[j]);
        if (!NT_SUCCESS(status))
        {
            goto cydivert_install_callouts_exit;
        }
    }

cydivert_install_callouts_exit:

    if (!NT_SUCCESS(status))
    {
        cydivert_uninstall_callouts(context, CYDIVERT_CONTEXT_STATE_OPEN);
    }

    return status;
}

/*
 * Register a WFP callout.
 */
static NTSTATUS cydivert_install_callout(context_t context, UINT idx,
    layer_t layer, UINT32 *callout_id_ptr)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_CALLOUT0 scallout;
    FWPM_CALLOUT0 mcallout;
    FWPM_FILTER0 filter;
    UINT64 weight;
    UINT32 priority;
    GUID callout_guid, filter_guid;
    UINT32 callout_id;
    WDFDEVICE device;
    HANDLE engine;
    NTSTATUS status;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        return status;
    }
    priority = context->priority;
    callout_guid = context->callout_guid[idx];
    filter_guid = context->filter_guid[idx];
    device = context->device;
    engine = context->engine_handle;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    weight = (UINT64)priority;
    
    RtlZeroMemory(&scallout, sizeof(scallout));
    scallout.calloutKey              = callout_guid;
    scallout.classifyFn              = layer->classify;
    scallout.notifyFn                = cydivert_notify;
    scallout.flowDeleteFn            = layer->flow_delete;
    RtlZeroMemory(&mcallout, sizeof(mcallout));
    mcallout.calloutKey              = callout_guid;
    mcallout.displayData.name        = layer->callout_name;
    mcallout.displayData.description = layer->callout_desc;
    mcallout.applicableLayer         = *(layer->layer_guid);
    RtlZeroMemory(&filter, sizeof(filter));
    filter.filterKey                 = filter_guid;
    filter.layerKey                  = *(layer->layer_guid);
    filter.displayData.name          = layer->filter_name;
    filter.displayData.description   = layer->filter_desc;
    filter.action.type               = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey         = callout_guid;
    filter.subLayerKey               = *(layer->sublayer_guid);
    filter.weight.type               = FWP_UINT64;
    filter.weight.uint64             = &weight;
    filter.rawContext                = (UINT64)context;
    status = FwpsCalloutRegister0(WdfDeviceWdmGetDeviceObject(device),
        &scallout, &callout_id);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to install WFP callout", status);
        return status;
    }
    if (callout_id_ptr != NULL)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        *callout_id_ptr = callout_id;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
    }
    status = FwpmTransactionBegin0(engine, 0);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to begin WFP transaction", status);
        goto cydivert_install_callout_error;
    }
    status = FwpmCalloutAdd0(engine, &mcallout, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP callout", status);
        goto cydivert_install_callout_error;
    }
    status = FwpmFilterAdd0(engine, &filter, NULL, NULL);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to add WFP filter", status);
        goto cydivert_install_callout_error;
    }
    status = FwpmTransactionCommit0(engine);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        goto cydivert_install_callout_error;
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        FwpsCalloutUnregisterByKey0(&callout_guid);
        status = STATUS_INVALID_DEVICE_STATE;
        return status;
    }
    context->installed[idx] = TRUE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    return STATUS_SUCCESS;

cydivert_install_callout_error:
    FwpmTransactionAbort0(engine);
    FwpsCalloutUnregisterByKey0(&callout_guid);
    return status;
}

/*
 * CyDivert uninstall callouts routine.
 */
static void cydivert_uninstall_callouts(context_t context,
    context_state_t state)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT i;
    HANDLE engine;
    BOOL installed;
    GUID callout_guid, filter_guid;
    NTSTATUS status;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != state)
    {
cydivert_uninstall_callouts_error:
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to delete filters and callouts", status);
        return;
    }
    engine = context->engine_handle;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    status = FwpmTransactionBegin0(engine, 0);
    if (!NT_SUCCESS(status))
    {
        // If the userspace app closes without closing the handle to
        // CyDivert, any actions on engine fail because the
        // RPC handle was closed first. So, this path is "normal" if
        // the user's app crashed or never closed the CyDivert handle.
        DEBUG_ERROR("failed to begin WFP transaction", status);
        FwpmTransactionAbort0(engine);
        goto cydivert_uninstall_callouts_unregister;
    }
    for (i = 0; i < CYDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != state)
        {
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            FwpmTransactionAbort0(engine);
            status = STATUS_INVALID_DEVICE_STATE;
            DEBUG_ERROR("failed to delete filters and callouts", status);
            return;
        }
        installed = context->installed[i];
        callout_guid = context->callout_guid[i];
        filter_guid = context->filter_guid[i];
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        if (!installed)
        {
            continue;
        }
        status = FwpmFilterDeleteByKey0(engine, &filter_guid);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to delete filter", status);
            break;
        }
        status = FwpmCalloutDeleteByKey0(engine, &callout_guid);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to delete callout", status);
            break;
        }
    }
    if (!NT_SUCCESS(status))
    {
        FwpmTransactionAbort0(engine);
        goto cydivert_uninstall_callouts_unregister;
    }
    status = FwpmTransactionCommit0(engine);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to commit WFP transaction", status);
        FwpmTransactionAbort0(engine);
        // continue
    }

cydivert_uninstall_callouts_unregister:
    for (i = 0; i < CYDIVERT_CONTEXT_MAXLAYERS; i++)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != state)
        {
            goto cydivert_uninstall_callouts_error;
        }
        installed = context->installed[i];
        callout_guid = context->callout_guid[i];
        context->installed[i] = FALSE;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        if (!installed)
        {
            continue;
        }
        status = FwpsCalloutUnregisterByKey0(&callout_guid);
        if (!NT_SUCCESS(status))
        {
            DEBUG_ERROR("failed to delete callout", status);
            continue;
        }
    }
}

/*
 * Divert cleanup routine.
 */
extern VOID cydivert_cleanup(IN WDFFILEOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    context_t context = cydivert_context_get(object);
    flow_t flow;
    packet_t work, packet;
    WDFQUEUE read_queue;
    WDFWORKITEM worker;
    LONGLONG timestamp;
    BOOL sniff_mode, timeout, forward;
    NTSTATUS status;
    
    DEBUG("CLEANUP: cleaning up CyDivert context (context=%p)", context);

    cydivert_reflect_close_event(context);
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPENING &&
            context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
cydivert_cleanup_error:
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to verify state for cleanup routine", status);
        return;
    }
    context->state = CYDIVERT_CONTEXT_STATE_CLOSING;
    sniff_mode = ((context->flags & CYDIVERT_FLAG_SNIFF) != 0);
    forward = (context->layer == CYDIVERT_LAYER_NETWORK_FORWARD);
    while (!IsListEmpty(&context->flow_set))
    {
        entry = RemoveHeadList(&context->flow_set);
        flow = CONTAINING_RECORD(entry, struct flow_s, entry);
        flow->deleted = TRUE;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = FwpsFlowRemoveContext0(flow->flow_id, flow->layer_id,
            flow->callout_id);
        if (!NT_SUCCESS(status))
        {
            cydivert_free(flow);
        }
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    while (!IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        context->packet_queue_length--;
        context->packet_queue_size -= packet->packet_size;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        timeout = CYDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        if (!sniff_mode && !timeout)
        {
            cydivert_inject_packet(packet);
        }
        else
        {
            cydivert_free_packet(packet);
        }
        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != CYDIVERT_CONTEXT_STATE_CLOSING)
        {
            goto cydivert_cleanup_error;
        }
    }
    while (!IsListEmpty(&context->work_queue))
    {
        entry = RemoveHeadList(&context->work_queue);
        context->work_queue_length--;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        work = CONTAINING_RECORD(entry, struct packet_s, entry);
        timeout = CYDIVERT_TIMEOUT(context, work->timestamp, timestamp);
        if (!sniff_mode && !timeout)
        {
            cydivert_inject_packet(work);
        }
        else
        {
            cydivert_free_packet(work);
        }
        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state != CYDIVERT_CONTEXT_STATE_CLOSING)
        {
            goto cydivert_cleanup_error;
        }
    }
    read_queue = context->read_queue;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    WdfIoQueuePurge(read_queue, NULL, NULL);
    WdfObjectDelete(read_queue);
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_CLOSING)
    {
        goto cydivert_cleanup_error;
    }
    worker = context->worker;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    WdfWorkItemFlush(worker);
    WdfObjectDelete(worker);
}

/*
 * CyDivert close routine.
 */
extern VOID cydivert_close(IN WDFFILEOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    context_t context = cydivert_context_get(object);
    NTSTATUS status;
    
    DEBUG("CLOSE: closing CyDivert context (context=%p)", context);
    
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_CLOSING)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to verify state for close routine", status);
        return;
    }
    context->state = CYDIVERT_CONTEXT_STATE_CLOSED;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * CyDivert destroy routine.
 */
extern VOID cydivert_destroy(IN WDFOBJECT object)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    context_t context = cydivert_context_get((WDFFILEOBJECT)object);
    const CYDIVERT_FILTER *filter;
    NTSTATUS status;

    DEBUG("DESTROY: destroying CyDivert context (context=%p)", context);

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_CLOSED)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        DEBUG_ERROR("failed to verify state for destroy routine", status);
        return;
    }
    filter = context->filter;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    cydivert_uninstall_callouts(context, CYDIVERT_CONTEXT_STATE_CLOSED);
    if (context->engine_handle != NULL)
    {
        FwpmEngineClose0(context->engine_handle);
    }
    cydivert_free((PVOID)filter);
    if (context->process != NULL)
    {
        ObDereferenceObject(context->process);
    }
}

/*
 * CyDivert read routine.
 */
static NTSTATUS cydivert_read(context_t context, WDFREQUEST request)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    NTSTATUS status = STATUS_SUCCESS;

    DEBUG("READ: reading diverted packet (context=%p, request=%p)", context,
        request);

    // Forward the request to the pending read queue:
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if ((context->flags & CYDIVERT_FLAG_SEND_ONLY) != 0)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("failed to inject; send-only flag is set", status);
        return status;
    }
    status = WdfRequestForwardToIoQueue(request, context->read_queue);
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to forward I/O request to read queue", status);
        return status;
    }

    // Service the read request:
    cydivert_read_service(context);

    return STATUS_SUCCESS;
}

/*
 * CyDivert service a single read request.
 */
static void cydivert_read_service_request(context_t context, packet_t packet,
    LONGLONG timestamp, WDFREQUEST request)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    PMDL dst_mdl;
    UINT8 *layer_data, *src, *dst;
    ULONG dst_len, src_len, read_len = 0;
    BOOL timeout;
    packet_t new_packet;
    req_context_t req_context;
    PCYDIVERT_ADDRESS addr;
    UINT i, addr_len, addr_len_max;
    UINT *addr_len_ptr;
    NTSTATUS status;

    if (request == NULL)
    {
        // This occurs if the packet timed out.
        cydivert_free_packet(packet);
        return;
    }

    DEBUG("SERVICE: servicing read request (request=%p, packet=%p)", request,
        packet);

    // Get the packet and address buffers: 
    switch (packet->layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
        case CYDIVERT_LAYER_REFLECT:

            status = WdfRequestRetrieveOutputWdmMdl(request, &dst_mdl);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("failed to retrieve output MDL", status);
                goto cydivert_read_service_request_exit;
            }
            dst = MmGetSystemAddressForMdlSafe(dst_mdl,
                NormalPagePriority | no_exec_flag);
            if (dst == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                DEBUG_ERROR("failed to get address of output MDL", status);
                goto cydivert_read_service_request_exit;
            }
            dst_len = MmGetMdlByteCount(dst_mdl);
            break;

        case CYDIVERT_LAYER_FLOW:
        case CYDIVERT_LAYER_SOCKET:

            status = STATUS_SUCCESS;
            dst = NULL;
            dst_len = 0;
            break;

        default:
            status = STATUS_INVALID_DEVICE_STATE;
            DEBUG_ERROR("invalid packet layer", status);
            goto cydivert_read_service_request_exit;
    }

    req_context  = cydivert_req_context_get(request);
    addr         = req_context->addr;
    addr_len     = 0;
    addr_len_max = (UINT)req_context->addr_len;
    addr_len_ptr = req_context->addr_len_ptr;
    i            = 0;
    while (TRUE)
    {
        // Copy the packet data:
        switch (packet->layer)
        {
            case CYDIVERT_LAYER_NETWORK:
            case CYDIVERT_LAYER_NETWORK_FORWARD:
            case CYDIVERT_LAYER_REFLECT:

                if (packet->layer != CYDIVERT_LAYER_REFLECT)
                {
                    src = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_NETWORK,
                        packet);
                }
                else
                {
                    src = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_REFLECT,
                        packet);
                }
                src_len = packet->packet_len;
                if (src_len > dst_len)
                {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                src_len = (src_len < dst_len? src_len: dst_len);
                RtlCopyMemory(dst, src, src_len);
                dst += src_len;
                dst_len -= src_len;
                read_len += src_len;
                break;

            default:
                break;
        }

        // Copy the address data:
        if (addr != NULL)
        {
            DEBUG_BOUNDS_CHECK((PVOID)addr, (UINT8 *)addr + addr_len_max,
                (PVOID)&addr[i], (PVOID)&addr[i+1]);

            addr[i].Timestamp   = (INT64)packet->timestamp;
            addr[i].Layer       = packet->layer;
            addr[i].Event       = packet->event;
            addr[i].Sniffed     = packet->sniffed;
            addr[i].Outbound    = packet->outbound;
            addr[i].Loopback    = packet->loopback;
            addr[i].Impostor    = packet->impostor;
            addr[i].IPv6        = packet->ipv6;
            addr[i].IPChecksum  = packet->ip_checksum;
            addr[i].TCPChecksum = packet->tcp_checksum;
            addr[i].UDPChecksum = packet->udp_checksum;
            addr[i].Reserved1   = 0;
            addr[i].Reserved2   = 0;
            layer_data = (PVOID)packet->data;
            switch (packet->layer)
            {
                case CYDIVERT_LAYER_NETWORK:
                case CYDIVERT_LAYER_NETWORK_FORWARD:
                    RtlCopyMemory(&addr[i].Network, layer_data,
                        sizeof(CYDIVERT_DATA_NETWORK));
                    break;

                case CYDIVERT_LAYER_FLOW:
                    RtlCopyMemory(&addr[i].Flow, layer_data,
                        sizeof(CYDIVERT_DATA_FLOW));
                    break;

                case CYDIVERT_LAYER_SOCKET:
                    RtlCopyMemory(&addr[i].Socket, layer_data,
                        sizeof(CYDIVERT_DATA_SOCKET));
                    break;

                case CYDIVERT_LAYER_REFLECT:
                    RtlCopyMemory(&addr[i].Reflect, layer_data,
                        sizeof(CYDIVERT_DATA_REFLECT));
                    break;

                default:
                    break;
            }
        }

        i++;
        addr_len += sizeof(CYDIVERT_ADDRESS);
        if (addr_len + sizeof(CYDIVERT_ADDRESS) > addr_len_max ||
                i >= CYDIVERT_BATCH_MAX)
        {
            // addr[] is full:
            break;
        }

        // Attempt to fill the buffer with more packets:
        new_packet = NULL;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state == CYDIVERT_CONTEXT_STATE_OPEN &&
                !IsListEmpty(&context->packet_queue))
        {
            entry = RemoveHeadList(&context->packet_queue);
            new_packet = CONTAINING_RECORD(entry, struct packet_s, entry);
            timeout = CYDIVERT_TIMEOUT(context, new_packet->timestamp,
                timestamp);
            if (new_packet->packet_len > dst_len || timeout)
            {
                // Note: timeouts to be handled elsewhere.
                InsertHeadList(&context->packet_queue, entry);
                new_packet = NULL;
            }
            else
            {
                context->packet_queue_length--;
                context->packet_queue_size -= new_packet->packet_size;
            }
        }
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        if (new_packet == NULL)
        {
            // No suitable packet:
            break;
        }

        cydivert_free_packet(packet);
        packet = new_packet;
    }

    if (addr_len_ptr != NULL)
    {
        *addr_len_ptr = addr_len;
    }

cydivert_read_service_request_exit:

    cydivert_free_packet(packet);
    WdfRequestCompleteWithInformation(request, status, read_len);
}

/*
 * Opportunistic read service request.
 */
static void cydivert_fast_read_service_request(PVOID packet, ULONG packet_len,
    PNET_BUFFER_LIST buffers, CYDIVERT_LAYER layer, PVOID layer_data,
    CYDIVERT_EVENT event, UINT64 flags, BOOL ipv4, BOOL outbound,
    BOOL loopback, BOOL impostor, LONGLONG timestamp, WDFREQUEST request)
{
    PNET_BUFFER buffer;
    PMDL dst_mdl;
    UINT dst_len, read_len = 0;
    UINT8 *dst;
    req_context_t req_context;
    PCYDIVERT_ADDRESS addr;
    UINT *addr_len_ptr;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksums;
    BOOL sniffed, ip_checksum, tcp_checksum, udp_checksum;
    NTSTATUS status = STATUS_SUCCESS;

    // This function bypasses the normal work_queue -> packet_queue flow, but
    // is limited to a single packet+request pair.  This eliminates an extra
    // packet copy, allocation+deallocation, and at least one context switch.

    switch (layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
        case CYDIVERT_LAYER_REFLECT:

            status = WdfRequestRetrieveOutputWdmMdl(request, &dst_mdl);
            if (!NT_SUCCESS(status))
            {
                goto cydivert_fast_read_service_request_exit;
            }
            dst = MmGetSystemAddressForMdlSafe(dst_mdl,
                NormalPagePriority | no_exec_flag);
            if (dst == NULL)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto cydivert_fast_read_service_request_exit;
            }
            dst_len = MmGetMdlByteCount(dst_mdl);
            break;

        case CYDIVERT_LAYER_FLOW:
        case CYDIVERT_LAYER_SOCKET:
            status = STATUS_SUCCESS;
            dst = NULL;
            dst_len = 0;
            break;

        default:
            status = STATUS_INVALID_DEVICE_STATE;
            goto cydivert_fast_read_service_request_exit;
    }

    switch (layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
            buffer = (PNET_BUFFER)packet;
            dst_len = (dst_len < packet_len? dst_len: packet_len);
            if (!cydivert_copy_data(buffer, dst, dst_len))
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
            }
            else if (dst_len < packet_len)
            {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            read_len = dst_len;
            checksums.Value = NET_BUFFER_LIST_INFO(buffers,
                TcpIpChecksumNetBufferListInfo);
            if (outbound)
            {
                ip_checksum = (checksums.Transmit.IpHeaderChecksum == 0);
                tcp_checksum = (checksums.Transmit.TcpChecksum == 0);
                udp_checksum = (checksums.Transmit.UdpChecksum == 0);
            }
            else
            {
                ip_checksum = (checksums.Receive.IpChecksumSucceeded == 0);
                tcp_checksum = (checksums.Receive.TcpChecksumSucceeded == 0);
                udp_checksum = (checksums.Receive.UdpChecksumSucceeded == 0);
            }
            break;

        case CYDIVERT_LAYER_REFLECT:
            dst_len = (dst_len < packet_len? dst_len: packet_len);
            RtlCopyMemory(dst, packet, dst_len);
            read_len = dst_len;
            ip_checksum = tcp_checksum = udp_checksum = FALSE;
            break;

        default:
            read_len = 0;
            ip_checksum = tcp_checksum = udp_checksum = FALSE;
            break;
    }

    req_context  = cydivert_req_context_get(request);
    addr         = req_context->addr;
    addr_len_ptr = req_context->addr_len_ptr;

    if (addr != NULL)
    {
        sniffed = ((flags & CYDIVERT_FLAG_SNIFF) != 0 ||
            event == CYDIVERT_EVENT_SOCKET_CLOSE);

        addr->Timestamp   = timestamp;
        addr->Layer       = layer;
        addr->Event       = event;
        addr->Sniffed     = (sniffed? 1: 0);
        addr->Outbound    = (outbound? 1: 0);
        addr->Loopback    = (loopback? 1: 0);
        addr->Impostor    = (impostor? 1: 0);
        addr->IPv6        = (ipv4? 0: 1);
        addr->IPChecksum  = (ip_checksum? 1: 0);
        addr->TCPChecksum = (tcp_checksum? 1: 0);
        addr->UDPChecksum = (udp_checksum? 1: 0);
        addr->Reserved1   = 0;
        addr->Reserved2   = 0;
        switch (layer)
        {
            case CYDIVERT_LAYER_NETWORK:
            case CYDIVERT_LAYER_NETWORK_FORWARD:
                RtlCopyMemory(&addr->Network, layer_data,
                    sizeof(CYDIVERT_DATA_NETWORK));
                break;

            case CYDIVERT_LAYER_FLOW:
                RtlCopyMemory(&addr->Flow, layer_data,
                    sizeof(CYDIVERT_DATA_FLOW));
                break;

            case CYDIVERT_LAYER_SOCKET:
                RtlCopyMemory(&addr->Socket, layer_data,
                    sizeof(CYDIVERT_DATA_SOCKET));
                break;

            case CYDIVERT_LAYER_REFLECT:
                RtlCopyMemory(&addr->Reflect, layer_data,
                    sizeof(CYDIVERT_DATA_REFLECT));
                break;

            default:
                break;
        }
    }
    if (addr_len_ptr != NULL)
    {
        *addr_len_ptr = sizeof(CYDIVERT_ADDRESS);
    }

cydivert_fast_read_service_request_exit:

    WdfRequestCompleteWithInformation(request, status, read_len);
}

/*
 * CyDivert read request service.
 */
static void cydivert_read_service(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFREQUEST request;
    PLIST_ENTRY entry;
    LONGLONG timestamp;
    BOOL timeout;
    NTSTATUS status;
    packet_t packet;

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (context->state == CYDIVERT_CONTEXT_STATE_OPEN &&
           !IsListEmpty(&context->packet_queue))
    {
        entry = RemoveHeadList(&context->packet_queue);
        packet = CONTAINING_RECORD(entry, struct packet_s, entry);
        timeout = CYDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        request = NULL;
        if (!timeout)
        {
            status = WdfIoQueueRetrieveNextRequest(context->read_queue,
                &request);
            if (!NT_SUCCESS(status))
            {
                InsertHeadList(&context->packet_queue, entry);
                break;
            }
        }
        context->packet_queue_length--;
        context->packet_queue_size -= packet->packet_size;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        cydivert_read_service_request(context, packet, timestamp, request);

        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }

    if (context->shutdown_recv && context->shutdown_recv_enabled &&
            IsListEmpty(&context->packet_queue) &&
            IsListEmpty(&context->work_queue))
    {
        // The handle has shutdown, the queue is empty, and no more packets
        // will be queued.  Notify any remaining requests.
        while (context->state == CYDIVERT_CONTEXT_STATE_OPEN)
        {
            status = WdfIoQueueRetrieveNextRequest(context->read_queue,
                &request);
            if (!NT_SUCCESS(status))
            {
                break;
            }
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            WdfRequestComplete(request, STATUS_PIPE_EMPTY);
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        }
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * CyDivert write routine.
 */
static NTSTATUS cydivert_write(context_t context, WDFREQUEST request,
    req_context_t req_context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PMDL mdl = NULL;
    PVOID data, data_copy;
    packet_t packet;
    UINT data_len, packet_len, packet_size, inject_len;
    PCYDIVERT_DATA_NETWORK network_data;
    PCYDIVERT_IPHDR ip_header;
    PCYDIVERT_IPV6HDR ipv6_header;
    UINT8 layer;
    UINT32 priority;
    UINT64 flags;
    PCYDIVERT_ADDRESS addr;
    UINT i, addr_len, addr_len_max, version;
    NTSTATUS status = STATUS_SUCCESS, status_soft_error = STATUS_SUCCESS;

    DEBUG("WRITE: writing/injecting a packet (context=%p, request=%p)",
        context, request);
    
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_INVALID_DEVICE_STATE;
        goto cydivert_write_hard_error;
    }
    if (context->shutdown_send)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        status = STATUS_PIPE_EMPTY;
        goto cydivert_write_hard_error;
    }
    layer = context->layer;
    priority = context->priority;
    flags = context->flags;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    if ((flags & CYDIVERT_FLAG_RECV_ONLY) != 0)
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("failed to inject; recv-only flag is set", status);
        goto cydivert_write_hard_error;
    }

    switch (layer)
    {
        case CYDIVERT_LAYER_FLOW:
        case CYDIVERT_LAYER_SOCKET:
        case CYDIVERT_LAYER_REFLECT:
            status = STATUS_INVALID_PARAMETER;
            DEBUG_ERROR("failed to inject at layer", status);
            goto cydivert_write_hard_error;
        default:
            break;
    }

    status = WdfRequestRetrieveOutputWdmMdl(request, &mdl);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input MDL", status);
        goto cydivert_write_hard_error;
    }

    data = MmGetSystemAddressForMdlSafe(mdl,
        NormalPagePriority | no_write_flag | no_exec_flag);
    if (data == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to get MDL address", status);
        goto cydivert_write_hard_error;
    }
    
    data_len     = MmGetMdlByteCount(mdl);
    inject_len   = 0;
    addr         = req_context->addr;
    addr_len_max = (ULONG)req_context->addr_len;
    addr_len     = 0;

    for (i = 0; addr_len + sizeof(CYDIVERT_ADDRESS) <= addr_len_max &&
            i < CYDIVERT_BATCH_MAX;
            i++, addr_len += sizeof(CYDIVERT_ADDRESS))
    {
        // Get the packet length:
        if (data_len < sizeof(CYDIVERT_IPHDR))
        {
cydivert_write_too_small_packet:
            status = STATUS_BUFFER_TOO_SMALL;
            DEBUG_ERROR("failed to inject partial packet", status);
            goto cydivert_write_hard_error;
        }
        ip_header = (PCYDIVERT_IPHDR)data;
        version = ip_header->Version;
        switch (version)
        {
            case 4:
                packet_len = RtlUshortByteSwap(ip_header->Length);
                if (packet_len < sizeof(CYDIVERT_IPHDR))
                {
                    goto cydivert_write_invalid_packet;
                }
                break;
            case 6:
                if (data_len < sizeof(CYDIVERT_IPV6HDR))
                {
                    goto cydivert_write_too_small_packet;
                }
                ipv6_header = (PCYDIVERT_IPV6HDR)data;
                packet_len = RtlUshortByteSwap(ipv6_header->Length) +
                    sizeof(CYDIVERT_IPV6HDR);
                break;
            default:
cydivert_write_invalid_packet:
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to inject invalid packet", status);
                goto cydivert_write_hard_error;
        }
        if (data_len < packet_len)
        {
            goto cydivert_write_too_small_packet;
        }

        // Copy packet & data:
        packet_size = CYDIVERT_PACKET_SIZE(CYDIVERT_DATA_NETWORK,
            packet_len);
        packet = (packet_t)cydivert_malloc(packet_size, FALSE);
        if (packet == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            DEBUG_ERROR("failed to allocate memory for injected packet",
                status);
            goto cydivert_write_hard_error;
        }
        packet->layer         = layer;
        packet->event         = CYDIVERT_EVENT_NETWORK_PACKET;
        packet->sniffed       = 0;      // Unused
        packet->outbound      = addr[i].Outbound;
        packet->loopback      = 0;      // Unused
        packet->impostor      = addr[i].Impostor;
        packet->ipv6          = (version == 6? 1: 0);
        packet->ip_checksum   = addr[i].IPChecksum;
        packet->tcp_checksum  = addr[i].TCPChecksum;
        packet->udp_checksum  = addr[i].UDPChecksum;
        packet->icmp_checksum = 1;      // Assumed valid
        packet->match         = 0;      // Unused
        packet->packet_size   = packet_size;
        packet->packet_len    = packet_len;
        packet->priority      = priority;
        packet->timestamp     = 0;      // Unused
        packet->object        = NULL;
        network_data =
            (PCYDIVERT_DATA_NETWORK)CYDIVERT_LAYER_DATA_PTR(packet);
        RtlCopyMemory(network_data, &addr[i].Network, sizeof(CYDIVERT_DATA_NETWORK));
        data_copy = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_NETWORK, packet);
        RtlCopyMemory(data_copy, data, packet_len);
        switch (version)
        {
            case 4:
                ip_header = (PCYDIVERT_IPHDR)data_copy;
                if (ip_header->Version != 4 ||
                        packet_len != RtlUshortByteSwap(ip_header->Length))
                {
                    cydivert_free(packet);
                    goto cydivert_write_invalid_packet;
                }
                break;
            case 6:
                ipv6_header = (PCYDIVERT_IPV6HDR)data_copy;
                if (ipv6_header->Version != 6 ||
                        packet_len != RtlUshortByteSwap(ipv6_header->Length) +
                            sizeof(CYDIVERT_IPV6HDR))
                {
                    cydivert_free(packet);
                    goto cydivert_write_invalid_packet;
                }
                break;
        }

        // Check bounds:
        DEBUG_BOUNDS_CHECK((PVOID)addr, (UINT8 *)addr + addr_len_max,
            (PVOID)&addr[i], (PVOID)&addr[i+1]);

        // Inject packet:
        status = cydivert_inject_packet(packet);
        if (!NT_SUCCESS(status))
        {
            if (status == STATUS_INSUFFICIENT_RESOURCES)
            {
                goto cydivert_write_hard_error;
            }
            status_soft_error = status;
        }

        // Reset state:
        inject_len += packet_len;
        data        = (PVOID)((UINT8 *)data + packet_len);
        data_len   -= packet_len;
    }

    // Note: status_soft_error is for "soft" errors that do not prevent other
    //       batched packets from being injected.
    WdfRequestCompleteWithInformation(request, status_soft_error, inject_len);
    return STATUS_SUCCESS;

cydivert_write_hard_error:

    // Request to be completed in cydivert_ioctl()
    return status;
}


/*
 * CyDivert caller context preprocessing.
 */
VOID cydivert_caller_context(IN WDFDEVICE device, IN WDFREQUEST request)
{
    PCHAR inbuf;
    size_t inbuflen;
    WDF_REQUEST_PARAMETERS params;
    WDFMEMORY memobj;
    PCYDIVERT_ADDRESS addr = NULL;
    UINT *addr_len_ptr = NULL;
    UINT64 addr_len = 0;
    PCYDIVERT_IOCTL ioctl;
    WDF_OBJECT_ATTRIBUTES attributes;
    req_context_t req_context = NULL;
    NTSTATUS status;

    WDF_REQUEST_PARAMETERS_INIT(&params);
    WdfRequestGetParameters(request, &params);

    if (params.Type != WdfRequestTypeDeviceControl)
    {
        goto cydivert_caller_context_exit;
    }

    // Get and verify the input buffer.
    status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf, &inbuflen);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to retrieve input buffer", status);
        goto cydivert_caller_context_error;
    }
    if (inbuflen < sizeof(CYDIVERT_IOCTL))
    {
        status = STATUS_INVALID_PARAMETER;
        DEBUG_ERROR("input buffer not an ioctl message header", status);
        goto cydivert_caller_context_error;
    }

    // Probe and lock user buffers here (if required).
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, req_context_s);
    status = WdfObjectAllocateContext(request, &attributes, &req_context);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to allocate request context for ioctl", status);
        goto cydivert_caller_context_error;
    }
    switch (params.Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_CYDIVERT_RECV:
            ioctl        = (PCYDIVERT_IOCTL)inbuf;
            addr         = (PCYDIVERT_ADDRESS)(ULONG_PTR)ioctl->recv.addr;
            addr_len_ptr = (UINT *)(ULONG_PTR)ioctl->recv.addr_len_ptr;
            addr_len     = sizeof(CYDIVERT_ADDRESS);
            if (addr_len_ptr != NULL)
            {
                status = WdfRequestProbeAndLockUserBufferForWrite(request,
                    addr_len_ptr, sizeof(UINT), &memobj);
                if (!NT_SUCCESS(status))
                {
                    DEBUG_ERROR("invalid address length pointer for RECV ioctl",
                        status);
                    goto cydivert_caller_context_error;
                }
                addr_len_ptr = (UINT *)WdfMemoryGetBuffer(memobj, NULL);
                addr_len     = *addr_len_ptr;
                if (addr_len < sizeof(CYDIVERT_ADDRESS) ||
                    addr_len > CYDIVERT_BATCH_MAX * sizeof(CYDIVERT_ADDRESS))
                {
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("out-of-range address length (%u) for RECV "
                        "ioctl", status, addr_len);
                    goto cydivert_caller_context_error;
                }
                if (addr == NULL)
                {
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("null address for RECV ioctl", status);
                    goto cydivert_caller_context_error;
                }
            }
            if (addr != NULL)
            {
                status = WdfRequestProbeAndLockUserBufferForWrite(request,
                    addr, (size_t)addr_len, &memobj);
                if (!NT_SUCCESS(status))
                {
                    DEBUG_ERROR("invalid address for RECV ioctl", status);
                    goto cydivert_caller_context_error;
                }
                addr = (PCYDIVERT_ADDRESS)WdfMemoryGetBuffer(memobj, NULL);
            }
            break;

        case IOCTL_CYDIVERT_SEND:
            ioctl    = (PCYDIVERT_IOCTL)inbuf;
            addr     = (PCYDIVERT_ADDRESS)(ULONG_PTR)ioctl->send.addr;
            addr_len = ioctl->send.addr_len;
            if (addr_len < sizeof(CYDIVERT_ADDRESS) ||
                addr_len > CYDIVERT_BATCH_MAX * sizeof(CYDIVERT_ADDRESS))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("out-of-range address length (%u) for SEND ioctl",
                    status, addr_len);
                goto cydivert_caller_context_error;
            }
            if (addr == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("null address for SEND ioctl", status);
                goto cydivert_caller_context_error;
            }
            status = WdfRequestProbeAndLockUserBufferForRead(request, addr,
                (size_t)addr_len, &memobj);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("invalid address for SEND ioctl", status);
                goto cydivert_caller_context_error;
            }
            addr = (PCYDIVERT_ADDRESS)WdfMemoryGetBuffer(memobj, NULL);
            break;

        case IOCTL_CYDIVERT_INITIALIZE:
        case IOCTL_CYDIVERT_STARTUP:
        case IOCTL_CYDIVERT_SHUTDOWN:
        case IOCTL_CYDIVERT_SET_PARAM:
        case IOCTL_CYDIVERT_GET_PARAM:
            break;
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("failed to complete I/O control; invalid request",
                status);
            goto cydivert_caller_context_error;
    }
    
    req_context->addr         = addr;
    req_context->addr_len     = (UINT)addr_len;
    req_context->addr_len_ptr = addr_len_ptr;

cydivert_caller_context_exit:

    status = WdfDeviceEnqueueRequest(device, request);
    
cydivert_caller_context_error:    
    
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to enqueue request", status);
        WdfRequestComplete(request, status);
    }
}

/*
 * CyDivert I/O control.
 */
extern VOID cydivert_ioctl(IN WDFQUEUE queue, IN WDFREQUEST request,
    IN size_t out_length, IN size_t in_length, IN ULONG code)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PCHAR inbuf, outbuf;
    size_t inbuflen, outbuflen, ioctl_filter_len;
    PCYDIVERT_IOCTL ioctl;
    const CYDIVERT_FILTER *ioctl_filter, *filter;
    req_context_t req_context;
    NTSTATUS status = STATUS_SUCCESS;
    context_t context =
        cydivert_context_get(WdfRequestGetFileObject(request));
    UINT64 *valptr;

    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(out_length);
    UNREFERENCED_PARAMETER(in_length);

    DEBUG("IOCTL: I/O control request (context=%p)", context);

    // Get the buffers and do sanity checks.
    switch (code)
    {
        case IOCTL_CYDIVERT_INITIALIZE:
        case IOCTL_CYDIVERT_STARTUP:
        case IOCTL_CYDIVERT_SHUTDOWN:
        case IOCTL_CYDIVERT_SET_PARAM:
        case IOCTL_CYDIVERT_GET_PARAM:
            status = WdfRequestRetrieveInputBuffer(request, 0, &inbuf,
                &inbuflen);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("failed to retrieve input buffer", status);
                goto cydivert_ioctl_exit;
            }
            if (inbuflen < sizeof(CYDIVERT_IOCTL))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("input buffer too small", status);
                goto cydivert_ioctl_exit;
            }
            break;
        default:
            inbuf = NULL;
            inbuflen = 0;
            break;
    }
    switch (code)
    {
        case IOCTL_CYDIVERT_INITIALIZE:
        case IOCTL_CYDIVERT_STARTUP:
        case IOCTL_CYDIVERT_GET_PARAM:
            status = WdfRequestRetrieveOutputBuffer(request, 0, &outbuf,
                &outbuflen);
            if (!NT_SUCCESS(status))
            {
                DEBUG_ERROR("failed to retrieve output buffer", status);
                goto cydivert_ioctl_exit;
            }
            break;
        default:
            outbuf = NULL;
            outbuflen = 0;
            break;
    }

    // Handle the ioctl:
    switch (code)
    {
        case IOCTL_CYDIVERT_RECV:
            status = cydivert_read(context, request);
            if (NT_SUCCESS(status))
            {
                return;
            }
            break;
        
        case IOCTL_CYDIVERT_SEND:
            
            req_context = cydivert_req_context_get(request);
            status = cydivert_write(context, request, req_context);
            if (NT_SUCCESS(status))
            {
                return;
            }
            break;

        case IOCTL_CYDIVERT_INITIALIZE:
        {
            PCYDIVERT_VERSION version;
            CYDIVERT_LAYER layer;
            UINT32 priority;
            UINT64 flags;
            INT16 priority16;
            
            ioctl = (PCYDIVERT_IOCTL)inbuf;
            version = (CYDIVERT_VERSION *)outbuf;
            if (outbuflen != sizeof(CYDIVERT_VERSION) ||
                version->magic != CYDIVERT_MAGIC_DLL ||
                version->major != CYDIVERT_VERSION_MAJOR ||
                (version->bits != 8 * sizeof(UINT32) &&
                 version->bits != 8 * sizeof(UINT64)))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to initialize; invalid version buffer",
                    status);
                goto cydivert_ioctl_exit;
            }
            
            layer = (CYDIVERT_LAYER)ioctl->initialize.layer;
            priority = ioctl->initialize.priority;
            flags = ioctl->initialize.flags;
            version->magic = CYDIVERT_MAGIC_SYS;
            version->major = CYDIVERT_VERSION_MAJOR;
            version->minor = CYDIVERT_VERSION_MINOR;
            version->bits  = 8 * sizeof(void *);
            
            switch ((UINT32)layer)
            {
                case CYDIVERT_LAYER_NETWORK:
                case CYDIVERT_LAYER_NETWORK_FORWARD:
                case CYDIVERT_LAYER_FLOW:
                case CYDIVERT_LAYER_SOCKET:
                case CYDIVERT_LAYER_REFLECT:
                    break;
                default:
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to set layer; invalid value", status);
                    goto cydivert_ioctl_exit;
            }

            if (priority > 2 * CYDIVERT_PRIORITY_MAX)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set priority; value out of range",
                    status);
                goto cydivert_ioctl_exit;
            }
            priority16 = (INT16)priority - CYDIVERT_PRIORITY_MAX;
            priority = cydivert_context_priority(priority);

            if (!CYDIVERT_FLAGS_VALID(flags))
            {
cydivert_ioctl_bad_flags:
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to set flags; invalid flags value",
                    status);
                goto cydivert_ioctl_exit;
            }
            switch ((UINT32)layer)
            {
                case CYDIVERT_LAYER_FLOW:
                case CYDIVERT_LAYER_REFLECT:
                    if ((flags & CYDIVERT_FLAG_SNIFF) == 0 ||
                        (flags & CYDIVERT_FLAG_RECV_ONLY) == 0)
                    {
                        goto cydivert_ioctl_bad_flags;
                    }
                    break;

                case CYDIVERT_LAYER_SOCKET:
                    if ((flags & CYDIVERT_FLAG_RECV_ONLY) == 0)
                    {
                        goto cydivert_ioctl_bad_flags;
                    }
                    break;

                default:
                    break;
            }

            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != CYDIVERT_CONTEXT_STATE_OPENING ||
                    context->initialized)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto cydivert_ioctl_exit;
            }
            context->layer = (CYDIVERT_LAYER)layer;
            context->priority16 = priority16;
            context->priority = priority;
            context->flags = flags;
            context->initialized = TRUE;
            KeReleaseInStackQueuedSpinLock(&lock_handle);

            break;
        }

        case IOCTL_CYDIVERT_STARTUP:
        {
            PEPROCESS process;
            LONGLONG timestamp;
            UINT64 filter_flags;
            UINT32 process_id;
            CYDIVERT_LAYER layer;
            UINT8 filter_len;
            WDFDEVICE device;

            ioctl = (PCYDIVERT_IOCTL)inbuf;
            filter_flags = ioctl->startup.flags;
            if ((filter_flags & ~CYDIVERT_FILTER_FLAGS_ALL) != 0)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to start filter; invalid flags", status);
                goto cydivert_ioctl_exit;
            }
 
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != CYDIVERT_CONTEXT_STATE_OPENING ||
                    !context->initialized)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto cydivert_ioctl_exit;
            }
            context->state = CYDIVERT_CONTEXT_STATE_OPEN;
            layer = context->layer;
            process = context->process;
            KeReleaseInStackQueuedSpinLock(&lock_handle);

            ioctl_filter = (const CYDIVERT_FILTER *)outbuf;
            ioctl_filter_len = outbuflen;
            filter = cydivert_filter_compile(ioctl_filter, ioctl_filter_len,
                layer);
            if (filter == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to compile filter", status);
                goto cydivert_ioctl_exit;
            }
            filter_len = (UINT8)(ioctl_filter_len / sizeof(CYDIVERT_FILTER));
            process_id = (UINT32)(ULONG_PTR)PsGetProcessId(process);
            timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                cydivert_free((PVOID)filter);
                status = STATUS_INVALID_DEVICE_STATE;
                goto cydivert_ioctl_exit;
            }
            context->filter                 = filter;
            context->filter_len             = filter_len;
            context->filter_flags           = filter_flags;
            context->reflect.data.Timestamp = timestamp;
            context->reflect.data.ProcessId = process_id;
            context->reflect.data.Layer     = context->layer;
            context->reflect.data.Flags     = context->flags;
            context->reflect.data.Priority  = context->priority16;
            context->reflect.open           = FALSE;
            context->shutdown_recv_enabled  =
                (layer != CYDIVERT_LAYER_REFLECT);
            device = context->device;
            KeReleaseInStackQueuedSpinLock(&lock_handle);

            if (InterlockedIncrement64(&num_opens) == 1)
            {
                PDRIVER_OBJECT driver = WdfDriverWdmGetDriverObject(
                    WdfDeviceGetDriver(device));
                cydivert_log_event(process, driver, L"LOAD");
            }
            cydivert_reflect_open_event(context);

            status = cydivert_install_callouts(context, layer, filter_flags);

            break;
        }

        case IOCTL_CYDIVERT_SHUTDOWN:
        {
            CYDIVERT_SHUTDOWN how;

            ioctl = (PCYDIVERT_IOCTL)inbuf;
            how = (CYDIVERT_SHUTDOWN)ioctl->shutdown.how;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto cydivert_ioctl_exit;
            }
            switch ((UINT32)how)
            {
                case CYDIVERT_SHUTDOWN_RECV:
                    context->shutdown_recv = TRUE;
                    break;
                case CYDIVERT_SHUTDOWN_SEND:
                    context->shutdown_send = TRUE;
                    break;
                case CYDIVERT_SHUTDOWN_BOTH:
                    context->shutdown_recv = context->shutdown_send = TRUE;
                    break;
                default:
                    KeReleaseInStackQueuedSpinLock(&lock_handle);
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to shutdown handle; invalid how",
                        status);
                    goto cydivert_ioctl_exit;
            }
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            cydivert_read_service(context);
            break;
        }
 
        case IOCTL_CYDIVERT_SET_PARAM:
        {
            CYDIVERT_PARAM param;
            UINT64 value;

            ioctl = (PCYDIVERT_IOCTL)inbuf;
            param = (CYDIVERT_PARAM)ioctl->set_param.param;
            value = ioctl->set_param.val;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto cydivert_ioctl_exit;
            }
            switch ((UINT32)param)
            {
                case CYDIVERT_PARAM_QUEUE_LENGTH:
                    if (value < CYDIVERT_PARAM_QUEUE_LENGTH_MIN ||
                        value > CYDIVERT_PARAM_QUEUE_LENGTH_MAX)
                    {
                        KeReleaseInStackQueuedSpinLock(&lock_handle);
                        status = STATUS_INVALID_PARAMETER;
                        DEBUG_ERROR("failed to set queue length; invalid "
                            "value", status);
                        goto cydivert_ioctl_exit;
                    }
                    context->packet_queue_maxlength = (ULONG)value;
                    break;

                case CYDIVERT_PARAM_QUEUE_TIME:
                    if (value < CYDIVERT_PARAM_QUEUE_TIME_MIN ||
                        value > CYDIVERT_PARAM_QUEUE_TIME_MAX)
                    {
                        KeReleaseInStackQueuedSpinLock(&lock_handle);
                        status = STATUS_INVALID_PARAMETER;
                        DEBUG_ERROR("failed to set queue time; invalid "
                            "value", status);
                        goto cydivert_ioctl_exit;
                    }
                    context->packet_queue_maxcounts =
                        (LONGLONG)value * counts_per_ms;
                    context->packet_queue_maxtime = (ULONG)value;
                    break;

                case CYDIVERT_PARAM_QUEUE_SIZE:
                    if (value < CYDIVERT_PARAM_QUEUE_SIZE_MIN ||
                        value > CYDIVERT_PARAM_QUEUE_SIZE_MAX)
                    {
                        KeReleaseInStackQueuedSpinLock(&lock_handle);
                        status = STATUS_INVALID_PARAMETER;
                        DEBUG_ERROR("failed to set queue size; invalid "
                            "value", status);
                        goto cydivert_ioctl_exit;
                    }
                    context->packet_queue_maxsize = (ULONG)value;
                    break;

                default:
                    KeReleaseInStackQueuedSpinLock(&lock_handle);
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to set parameter; invalid parameter",
                        status);
                    goto cydivert_ioctl_exit;
            }
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;
        }

        case IOCTL_CYDIVERT_GET_PARAM:
        {
            CYDIVERT_PARAM param;

            ioctl = (PCYDIVERT_IOCTL)inbuf;
            param = (CYDIVERT_PARAM)ioctl->get_param.param;
            if (outbuflen != sizeof(UINT64))
            {
                status = STATUS_INVALID_PARAMETER;
                DEBUG_ERROR("failed to get parameter; invalid output "
                    "buffer size", status);
                goto cydivert_ioctl_exit;
            }
            valptr = (UINT64 *)outbuf;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
            {
                KeReleaseInStackQueuedSpinLock(&lock_handle);
                status = STATUS_INVALID_DEVICE_STATE;
                goto cydivert_ioctl_exit;
            }
            switch ((UINT32)param)
            {
                case CYDIVERT_PARAM_QUEUE_LENGTH:
                    *valptr = context->packet_queue_maxlength;
                    break;
                case CYDIVERT_PARAM_QUEUE_TIME:
                    *valptr = context->packet_queue_maxtime;
                    break;
                case CYDIVERT_PARAM_QUEUE_SIZE:
                    *valptr = context->packet_queue_maxsize;
                    break;
                case CYDIVERT_PARAM_VERSION_MAJOR:
                    *valptr = CYDIVERT_VERSION_MAJOR;
                    break;
                case CYDIVERT_PARAM_VERSION_MINOR:
                    *valptr = CYDIVERT_VERSION_MINOR;
                    break;
                default:
                    KeReleaseInStackQueuedSpinLock(&lock_handle);
                    status = STATUS_INVALID_PARAMETER;
                    DEBUG_ERROR("failed to get parameter; invalid parameter",
                        status);
                    goto cydivert_ioctl_exit;
            }
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            DEBUG_ERROR("failed to complete I/O control; invalid request",
                status);
            break;
    }

cydivert_ioctl_exit:
    WdfRequestComplete(request, status);
}

/*
 * CyDivert notify function.
 */
static NTSTATUS cydivert_notify(IN FWPS_CALLOUT_NOTIFY_TYPE type,
    IN const GUID *filter_key, IN const FWPS_FILTER0 *filter)
{
    UNREFERENCED_PARAMETER(type);
    UNREFERENCED_PARAMETER(filter_key);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

/*
 * CyDivert get fixed values.
 */
static UINT8 cydivert_get_val8(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    return (value.type != FWP_UINT8? 0: value.uint8);
}
static UINT16 cydivert_get_val16(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    return (value.type != FWP_UINT16? 0: value.uint16);
}
static UINT32 cydivert_get_val32(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    return (value.type != FWP_UINT32? 0: value.uint32);
}
static void cydivert_get_ipv4_addr(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx, UINT32 *addr)
{
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    addr[2] = addr[3] = 0;
    if (value.type != FWP_UINT32)
    {
        addr[0] = addr[1] = 0;
    }
    else
    {
        addr[0] = value.uint32;
        addr[1] = 0x0000FFFF;
    }
}
static void cydivert_get_ipv6_addr(const FWPS_INCOMING_VALUES0 *fixed_vals,
    int idx, UINT32 *addr)
{
    UINT8 *addr8 = (UINT8 *)addr;
    INT i;
    FWP_VALUE0 value = fixed_vals->incomingValue[idx].value;
    if (value.type != FWP_BYTE_ARRAY16_TYPE)
    {
        addr[0] = addr[1] = addr[2] = addr[3] = 0;
        return;
    }
    for (i = 16-1; i >= 0; i--)
    {
        addr8[16-i-1] = value.byteArray16->byteArray16[i];
    }
}

/*
 * CyDivert classify outbound IPv4 function.
 */
static void cydivert_outbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_NETWORK network_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(meta_vals);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    network_data.IfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V4_INTERFACE_INDEX);
    network_data.SubIfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX);
    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V4_FLAGS) &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_network_classify(context, &network_data, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, /*reassembled=*/FALSE, /*advance=*/0,
        data, result);
}

/*
 * CyDivert classify outbound IPv6 function.
 */
static void cydivert_outbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_NETWORK network_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;
 
    UNREFERENCED_PARAMETER(meta_vals);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    network_data.IfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V6_INTERFACE_INDEX);
    network_data.SubIfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX);
    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_OUTBOUND_IPPACKET_V6_FLAGS) &
            FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_network_classify(context, &network_data, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, /*reassembled=*/FALSE, /*advance=*/0,
        data, result);
}

/*
 * CyDivert classify inbound IPv4 function.
 */
static void cydivert_inbound_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_NETWORK network_data;
    UINT advance;
    UINT32 flags;
    BOOL fragment, loopback, reassembled;
    context_t context = (context_t)(ULONG_PTR)filter->context;
 
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    flags = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V4_FLAGS);
    fragment = ((flags & FWP_CONDITION_FLAG_IS_FRAGMENT) != 0);
    if (fragment)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    loopback = ((flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    if (loopback)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    reassembled = ((flags & FWP_CONDITION_FLAG_IS_REASSEMBLED) != 0);

    network_data.IfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V4_INTERFACE_INDEX);
    network_data.SubIfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V4_SUB_INTERFACE_INDEX);
    advance = meta_vals->ipHeaderSize;
    
    cydivert_network_classify(context, &network_data, /*ipv4=*/TRUE,
        /*outbound=*/FALSE, loopback, reassembled, advance, data, result);
}

/*
 * CyDivert classify inbound IPv6 function.
 */
static void cydivert_inbound_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_NETWORK network_data;
    UINT advance;
    UINT32 flags;
    BOOL fragment, loopback, reassembled;
    context_t context = (context_t)(ULONG_PTR)filter->context;
 
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }

    flags = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V6_FLAGS);
    fragment = ((flags & FWP_CONDITION_FLAG_IS_FRAGMENT) != 0);
    if (fragment)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    loopback = ((flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    if (loopback)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    reassembled = ((flags & FWP_CONDITION_FLAG_IS_REASSEMBLED) != 0);

    network_data.IfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V6_INTERFACE_INDEX);
    network_data.SubIfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_INBOUND_IPPACKET_V6_SUB_INTERFACE_INDEX);
    advance = meta_vals->ipHeaderSize;
    
    cydivert_network_classify(context, &network_data, /*ipv4=*/FALSE,
        /*outbound=*/FALSE, loopback, reassembled, advance, data, result);
}

/*
 * CyDivert classify forward IPv4 function.
 */
static void cydivert_forward_network_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_NETWORK network_data;
    UINT32 flags;
    BOOL group;
    context_t context = (context_t)(ULONG_PTR)filter->context;
 
    UNREFERENCED_PARAMETER(meta_vals);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }
    flags = cydivert_get_val32(fixed_vals, FWPS_FIELD_IPFORWARD_V4_FLAGS);
    group = ((flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP) != 0);
    if (group)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }
 
    network_data.IfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_IPFORWARD_V4_DESTINATION_INTERFACE_INDEX);
    network_data.SubIfIdx = 0;

    cydivert_network_classify(context, &network_data, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, /*loopback=*/FALSE, /*reassembled=*/FALSE,
        /*advance=*/0, data, result);
}

/*
 * CyDivert classify forward IPv6 function.
 */
static void cydivert_forward_network_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_NETWORK network_data;
    UINT32 flags;
    BOOL group;
    context_t context = (context_t)(ULONG_PTR)filter->context;
 
    UNREFERENCED_PARAMETER(meta_vals);
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0 || data == NULL)
    {
        return;
    }
    flags = cydivert_get_val32(fixed_vals, FWPS_FIELD_IPFORWARD_V6_FLAGS);
    group = ((flags & FWP_CONDITION_FLAG_IS_FRAGMENT_GROUP) != 0);
    if (group)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    network_data.IfIdx = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_IPFORWARD_V6_DESTINATION_INTERFACE_INDEX);
    network_data.SubIfIdx = 0;

    cydivert_network_classify(context, &network_data, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, /*loopback=*/FALSE, /*reassembled=*/FALSE,
        /*advance=*/0, data, result);
}

/*
 * CyDivert network classify function.
 */
static void cydivert_network_classify(context_t context,
    IN PCYDIVERT_DATA_NETWORK network_data, IN BOOL ipv4, IN BOOL outbound,
    IN BOOL loopback, IN BOOL reassembled, IN UINT advance, IN OUT void *data,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    FWPS_PACKET_INJECTION_STATE packet_state;
    HANDLE packet_context;
    UINT32 priority, packet_priority;
    UINT64 flags;
    CYDIVERT_LAYER layer;
    PNET_BUFFER_LIST buffers;
    PNET_BUFFER buffer, buffer_fst, buffer_itr;
    BOOL impostor, sniff_mode, frag_mode, ok;
    WDFOBJECT object;
    const CYDIVERT_FILTER *filter;
    LONGLONG timestamp;
    NTSTATUS status;

    result->actionType = FWP_ACTION_CONTINUE;
    buffers = (PNET_BUFFER_LIST)data;
    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    if (NET_BUFFER_LIST_NEXT_NBL(buffers) != NULL)
    {
        // This is a fragment group.  This can be ignored since each fragment
        // should have already been indicated.
        return;
    }
    if (ipv4)
    {
        if (context->layer == CYDIVERT_LAYER_NETWORK_FORWARD)
        {
            packet_state = FwpsQueryPacketInjectionState0(inject_handle_forward,
                buffers, &packet_context);
        }
        else if (outbound)
        {
            packet_state = FwpsQueryPacketInjectionState0(inject_handle_out,
                buffers, &packet_context);
        }
        else
        {
            packet_state = FwpsQueryPacketInjectionState0(inject_handle_in,
                buffers, &packet_context);
        }
    }
    else
    {
        if (context->layer == CYDIVERT_LAYER_NETWORK_FORWARD)
        {
            packet_state = FwpsQueryPacketInjectionState0(
                injectv6_handle_forward, buffers, &packet_context);
        }
        else if (outbound)
        {
            packet_state = FwpsQueryPacketInjectionState0(injectv6_handle_out,
                buffers, &packet_context);
        }
        else
        {
            packet_state = FwpsQueryPacketInjectionState0(injectv6_handle_in,
                buffers, &packet_context);
        }
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN ||
        context->shutdown_recv)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    flags = context->flags;
    priority = context->priority;
    filter = context->filter;
    layer = context->layer;
    object = (WDFOBJECT)context->object;
    WdfObjectReference(object);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    impostor = FALSE;
    if (packet_state == FWPS_PACKET_INJECTED_BY_SELF ||
        packet_state == FWPS_PACKET_PREVIOUSLY_INJECTED_BY_SELF)
    {
        packet_priority = (UINT32)(ULONG_PTR)packet_context;
        if (packet_priority <= priority)
        {
            WdfObjectDereference(object);
            return;
        }
    }
    else if (packet_state == FWPS_PACKET_INJECTED_BY_OTHER)
    {
        // This is a packet injected by another driver, possibly an older
        // version of CyDivert.  To prevent block-clone-reinject infinite
        // loops, we mark this packet as an "impostor".
        impostor = TRUE;
    }

    // Get the timestamp.
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;

    // Filter fragments or reassembled packets.
    frag_mode =
        (outbound || layer == CYDIVERT_LAYER_NETWORK_FORWARD? TRUE:
            (flags & CYDIVERT_FLAG_FRAGMENTS) != 0);
    if (frag_mode && reassembled)
    {
        WdfObjectDereference(object);
        return;
    }

    // Retreat the NET_BUFFER to the IP header, if necessary.
    // If (advance != 0) then this must be in the inbound path, and the
    // NET_BUFFER_LIST must contain exactly one NET_BUFFER.
    if (advance != 0)
    {
        status = NdisRetreatNetBufferDataStart(buffer, advance, 0, NULL);
        if (!NT_SUCCESS(status))
        {
            WdfObjectDereference(object);
            return;
        }
    }

    /*
     * This code is complicated by the fact the a single NET_BUFFER_LIST
     * may contain several NET_BUFFER structures.  Each NET_BUFFER needs to
     * be filtered independently.  To achieve this we do the following:
     * 1) First check if any NET_BUFFER passes the filter.
     * 2) If no, then CONTINUE the entire NET_BUFFER_LIST.
     * 3) Else, split the NET_BUFFER_LIST into individual NET_BUFFERs; and
     *    either queue or re-inject based on the filter.
     */

    // Find the first NET_BUFFER we need to queue:
    buffer_fst = buffer;
    do
    {
        BOOL match = cydivert_filter(buffer_fst, layer, (PVOID)network_data,
            timestamp, /*event=*/CYDIVERT_EVENT_NETWORK_PACKET, ipv4,
            outbound, loopback, impostor, frag_mode, filter);
        if (match)
        {
            break;
        }
        buffer_fst = NET_BUFFER_NEXT_NB(buffer_fst);
    }
    while (buffer_fst != NULL);

    // If no packet matches the filter, CONTINUE the entire NET_BUFFER_LIST.
    if (buffer_fst == NULL)
    {
        WdfObjectDereference(object);
        if (advance != 0)
        {
            NdisAdvanceNetBufferDataStart(buffer, advance, FALSE, NULL);
        }
        return;
    }

    // At least one packet matches the filter.  Queue or re-inject all
    // packets depending on whether they match the filter or not.

    // STEP (1): Queue all non-matching packets up to buffer_fst.
    buffer_itr = buffer;
    sniff_mode = ((flags & CYDIVERT_FLAG_SNIFF) != 0);
    while (!sniff_mode && buffer_itr != buffer_fst)
    {
        ok = cydivert_queue_work(context, (PVOID)buffer_itr,
            NET_BUFFER_DATA_LENGTH(buffer_itr), buffers, /*object=*/NULL, layer,
            (PVOID)network_data, /*event=*/CYDIVERT_EVENT_NETWORK_PACKET,
            flags, priority, ipv4, outbound, loopback, impostor,
            /*match=*/FALSE, timestamp);
        if (!ok)
        {
            goto cydivert_network_classify_exit;
        }
        buffer_itr = NET_BUFFER_NEXT_NB(buffer_itr);
    }

    // STEP (2): Queue the first matching packet buffer_fst:
    ok = cydivert_queue_work(context, (PVOID)buffer_itr,
        NET_BUFFER_DATA_LENGTH(buffer_itr), buffers, /*object=*/NULL, layer,
        (PVOID)network_data, /*event=*/CYDIVERT_EVENT_NETWORK_PACKET,
        flags, priority, ipv4, outbound, loopback, impostor, /*match=*/TRUE,
        timestamp);
    if (advance != 0)
    {
        // Advance the NET_BUFFER to its original position.  Note that we can
        // do this here, since if (advance != 0) then there is only one
        // NET_BUFFER in the NET_BUFFER_LIST, meaning that STEPS (1) and (3)
        // will be empty.
        NdisAdvanceNetBufferDataStart(buffer, advance, FALSE, NULL);
    }
    if (!ok)
    {
        goto cydivert_network_classify_exit;
    }

    // STEP (3): Queue all remaining packets:
    buffer_itr = NET_BUFFER_NEXT_NB(buffer_fst);
    while (buffer_itr != NULL)
    {
        BOOL match = cydivert_filter(buffer_itr, layer, (PVOID)network_data,
            timestamp, /*event=*/CYDIVERT_EVENT_NETWORK_PACKET, ipv4,
            outbound, loopback, impostor, frag_mode, filter);
        ok = cydivert_queue_work(context, (PVOID)buffer_itr,
            NET_BUFFER_DATA_LENGTH(buffer_itr), buffers, /*object=*/NULL, layer,
            (PVOID)network_data, /*event=*/CYDIVERT_EVENT_NETWORK_PACKET,
            flags, priority, ipv4, outbound, loopback, impostor, match,
            timestamp);
        if (!ok)
        {
            goto cydivert_network_classify_exit;
        }
        buffer_itr = NET_BUFFER_NEXT_NB(buffer_itr);
    }

cydivert_network_classify_exit:

    WdfObjectDereference(object);
    if (!sniff_mode)
    {
        result->actionType = FWP_ACTION_BLOCK;
        result->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

/*
 * CyDivert classify flow established IPv4 function.
 */
static void cydivert_flow_established_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_FLOW flow_data;
    BOOL outbound, loopback;
    UINT64 flow_id;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    flow_data.EndpointId = meta_vals->transportEndpointHandle;
    flow_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    flow_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_ADDRESS,
        flow_data.LocalAddr);
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_ADDRESS,
        flow_data.RemoteAddr);
    flow_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_LOCAL_PORT);
    flow_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_REMOTE_PORT);
    flow_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL);

    outbound = (cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION) ==
        FWP_DIRECTION_OUTBOUND);
    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    flow_id = meta_vals->flowHandle;

    cydivert_flow_established_classify(context, flow_id, &flow_data,
        /*ipv4=*/TRUE, outbound, loopback, result);
}

/*
 * CyDivert classify flow established IPv6 function.
 */
static void cydivert_flow_established_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_FLOW flow_data;
    BOOL outbound, loopback;
    UINT64 flow_id;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    flow_data.EndpointId = meta_vals->transportEndpointHandle;
    flow_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    flow_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_ADDRESS,
        flow_data.LocalAddr);
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_ADDRESS,
        flow_data.RemoteAddr);
    flow_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_LOCAL_PORT);
    flow_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_REMOTE_PORT);
    flow_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL);
    
    outbound = (cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION) ==
        FWP_DIRECTION_OUTBOUND);
    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);
    flow_id = meta_vals->flowHandle;
    
    cydivert_flow_established_classify(context, flow_id, &flow_data,
        /*ipv4=*/FALSE, outbound, loopback, result);
}

/*
 * CyDivert flow established classify function.
 */
static void cydivert_flow_established_classify(context_t context,
    IN UINT64 flow_id, IN PCYDIVERT_DATA_FLOW flow_data, IN BOOL ipv4,
    IN BOOL outbound, IN BOOL loopback, OUT FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT64 flags, filter_flags;
    UINT32 callout_id;
    UINT16 layer_id;
    BOOL match, ok;
    WDFOBJECT object;
    const CYDIVERT_FILTER *filter;
    LONGLONG timestamp;
    flow_t flow;
    NTSTATUS status;

    // Basic checks:
    if (!(result->rights & FWPS_RIGHT_ACTION_WRITE))
    {
        return;
    }

    // Get the timestamp.
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    
    result->actionType = FWP_ACTION_CONTINUE;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN ||
        context->shutdown_recv)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    filter = context->filter;
    flags = context->flags;
    filter_flags = context->filter_flags;
    callout_id = (ipv4? context->flow_v4_callout_id:
        context->flow_v6_callout_id);
    object = (WDFOBJECT)context->object;

    // Reference only released once the flow has been deleted.  This is to
    // prevent the callout being unregistered while flow deletions are still
    // pending, causing the operation to fail with STATUS_DEVICE_BUSY.
    WdfObjectReference(object);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    match = cydivert_filter(/*buffer=*/NULL, /*layer=*/CYDIVERT_LAYER_FLOW,
        (PVOID)flow_data, timestamp,
        /*event=*/CYDIVERT_EVENT_FLOW_ESTABLISHED, ipv4, outbound, loopback,
        /*impostor=*/FALSE, /*frag_mode=*/FALSE, filter);
    if (match)
    {
        ok = cydivert_queue_work(context, /*packet=*/NULL, /*packet_len=*/0,
            /*buffers=*/NULL, /*object=*/NULL, /*layer=*/CYDIVERT_LAYER_FLOW,
            (PVOID)flow_data, /*event=*/CYDIVERT_EVENT_FLOW_ESTABLISHED,
            flags, /*priority=*/0, ipv4, outbound, loopback, /*impostor=*/FALSE,
            match, timestamp);
        if (!ok)
        {
            WdfObjectDereference(object);
            return;
        }
    }

    // Associate a context with the flow.  This is so we can detect the
    // FLOW_DELETED event.
    if ((filter_flags & CYDIVERT_FILTER_FLAG_EVENT_FLOW_DELETED) == 0)
    {
        // We don't care about FLOW_DELETED.
        WdfObjectDereference(object);
        return;
    }
    flow = cydivert_malloc(sizeof(struct flow_s), FALSE);
    if (flow == NULL)
    {
        WdfObjectDereference(object);
        return;
    }
    layer_id = (ipv4? FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4:
                      FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6);
    flow->context = context;
    flow->flow_id = flow_id;
    flow->callout_id = callout_id;
    flow->layer_id = layer_id;
    flow->inserted = FALSE;
    flow->deleted = FALSE;
    flow->outbound = outbound;
    flow->loopback = loopback;
    flow->ipv6 = !ipv4;
    RtlCopyMemory(&flow->data, flow_data, sizeof(flow->data));

    status = FwpsFlowAssociateContext0(flow_id, layer_id, callout_id,
        (UINT64)flow);
    if (!NT_SUCCESS(status))
    {
        cydivert_free(flow);
        WdfObjectDereference(object);
        return;
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN ||
        context->shutdown_recv)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        cydivert_free(flow);
        WdfObjectDereference(object);
        return;
    }
    if (!flow->deleted)
    {
        InsertTailList(&context->flow_set, &flow->entry);
        flow->inserted = TRUE;
    }
    else
    {
        // Flow was deleted before insertion; we are responsible for cleanup.
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        cydivert_free(flow);
        WdfObjectDereference(object);
        return;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * CyDivert flow delete notify function.
 */
static void cydivert_flow_delete_notify(UINT16 layer_id, UINT32 callout_id,
    UINT64 flow_context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT64 flags;
    BOOL match, cleanup;
    WDFOBJECT object;
    context_t context;
    const CYDIVERT_FILTER *filter;
    LONGLONG timestamp;
    flow_t flow;

    UNREFERENCED_PARAMETER(layer_id);
    UNREFERENCED_PARAMETER(callout_id);
 
    flow = (flow_t)(ULONG_PTR)flow_context;
    if (flow == NULL)
    {
        return;
    }

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    context = flow->context;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    object = (WDFOBJECT)context->object; // referenced in flow_established.
    if (flow->inserted && !flow->deleted)
    {
        RemoveEntryList(&flow->entry);
    }
    flow->deleted = TRUE;
    cleanup = flow->inserted;
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN ||
        context->shutdown_recv)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        goto cydivert_flow_delete_notify_exit;
    }
    filter = context->filter;
    flags = context->flags;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    match = cydivert_filter(/*buffer=*/NULL, /*layer=*/CYDIVERT_LAYER_FLOW,
        (PVOID)&flow->data, timestamp, /*event=*/CYDIVERT_EVENT_FLOW_DELETED,
        !flow->ipv6, flow->outbound, flow->loopback, /*impostor=*/FALSE,
        /*frag_mode=*/FALSE, filter);
    if (match)
    {
        (VOID)cydivert_queue_work(context, /*packet=*/NULL, /*packet_len=*/0,
            /*buffers=*/NULL, /*object=*/NULL, /*layer=*/CYDIVERT_LAYER_FLOW,
            (PVOID)&flow->data, /*event=*/CYDIVERT_EVENT_FLOW_DELETED, flags,
            /*priority=*/0, !flow->ipv6, flow->outbound, flow->loopback,
            /*impostor=*/FALSE, match, timestamp);
    }

cydivert_flow_delete_notify_exit:

    if (cleanup)
    {
        cydivert_free(flow);
        WdfObjectDereference(object);
    }
}

/*
 * CyDivert classify resource assignment IPv4 function.
 */
static void cydivert_resource_assignment_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = 0;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_IP_PROTOCOL);

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_BIND, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify resource assignment IPv6 function.
 */
static void cydivert_resource_assignment_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = 0;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_IP_PROTOCOL);

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_ASSIGNMENT_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_BIND, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify resource release IPv4 function.
 */
static void cydivert_resource_release_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = 0;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_IP_PROTOCOL);

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_CLOSE, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify resource release IPv6 function.
 */
static void cydivert_resource_release_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = 0;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_IP_PROTOCOL);

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_RESOURCE_RELEASE_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_CLOSE, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify auth connect IPv4 function.
 */
static void cydivert_auth_connect_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    UINT32 flags;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }
    flags = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_FLAGS);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT);
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL);

    loopback = ((flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_CONNECT, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify auth connect IPv6 function.
 */
static void cydivert_auth_connect_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    UINT32 flags;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }
    flags = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_FLAGS);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT);
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL);

    loopback = ((flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_CONNECT, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify endpoint closure IPv4 function.
 */
static void cydivert_endpoint_closure_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_REMOTE_PORT);
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_IP_PROTOCOL);

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_CLOSE, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify endpoint closure IPv6 function.
 */
static void cydivert_endpoint_closure_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_REMOTE_PORT);
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_IP_PROTOCOL);

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_ENDPOINT_CLOSURE_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_CLOSE, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify auth listen IPv4 function.
 */
static void cydivert_auth_listen_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = 0;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = IPPROTO_TCP;

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V4_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_LISTEN, /*ipv4=*/TRUE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify auth listen IPv6 function.
 */
static void cydivert_auth_listen_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = 0;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    RtlZeroMemory(&socket_data.RemoteAddr, sizeof(socket_data.RemoteAddr));
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = 0;
    socket_data.Protocol = IPPROTO_TCP;

    loopback = ((cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_LISTEN_V6_FLAGS) &
        FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_LISTEN, /*ipv4=*/FALSE,
        /*outbound=*/TRUE, loopback, result);
}

/*
 * CyDivert classify auth recv accept IPv4 function.
 */
static void cydivert_auth_recv_accept_v4_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    UINT32 flags;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;

    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }
    flags = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_FLAGS);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    cydivert_get_ipv4_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_LOCAL_PORT);
    socket_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_PORT);
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_PROTOCOL);

    loopback = ((flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_ACCEPT, /*ipv4=*/TRUE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * CyDivert classify auth recv accept IPv6 function.
 */
static void cydivert_auth_recv_accept_v6_classify(
    IN const FWPS_INCOMING_VALUES0 *fixed_vals,
    IN const FWPS_INCOMING_METADATA_VALUES0 *meta_vals, IN OUT void *data,
    const FWPS_FILTER0 *filter, IN UINT64 flow_context,
    OUT FWPS_CLASSIFY_OUT0 *result)
{
    CYDIVERT_DATA_SOCKET socket_data;
    UINT32 flags;
    BOOL loopback;
    context_t context = (context_t)(ULONG_PTR)filter->context;
    
    UNREFERENCED_PARAMETER(data);
    UNREFERENCED_PARAMETER(flow_context);

    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) == 0)
    {
        return;
    }
    flags = cydivert_get_val32(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_FLAGS);
    if ((flags & FWP_CONDITION_FLAG_IS_REAUTHORIZE) != 0)
    {
        result->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    socket_data.EndpointId = meta_vals->transportEndpointHandle;
    socket_data.ParentEndpointId = meta_vals->parentEndpointHandle;
    socket_data.ProcessId = (UINT32)meta_vals->processId;
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_ADDRESS,
        socket_data.LocalAddr);
    cydivert_get_ipv6_addr(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS,
        socket_data.RemoteAddr);
    socket_data.LocalPort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_LOCAL_PORT);
    socket_data.RemotePort = cydivert_get_val16(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_PORT);
    socket_data.Protocol = cydivert_get_val8(fixed_vals,
        FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_PROTOCOL);

    loopback = ((flags & FWP_CONDITION_FLAG_IS_LOOPBACK) != 0);

    cydivert_socket_classify(context, &socket_data,
        /*event=*/CYDIVERT_EVENT_SOCKET_ACCEPT, /*ipv4=*/FALSE,
        /*outbound=*/FALSE, loopback, result);
}

/*
 * CyDivert socket classify function.
 */
static void cydivert_socket_classify(context_t context,
    PCYDIVERT_DATA_SOCKET socket_data, CYDIVERT_EVENT event, BOOL ipv4,
    BOOL outbound, BOOL loopback, FWPS_CLASSIFY_OUT0 *result)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    UINT64 flags;
    BOOL match, ok;
    WDFOBJECT object;
    const CYDIVERT_FILTER *filter;
    LONGLONG timestamp;

    // Get the timestamp.
    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    
    if ((result->rights & FWPS_RIGHT_ACTION_WRITE) != 0)
    {
        result->actionType = FWP_ACTION_CONTINUE;
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN ||
        context->shutdown_recv)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    filter = context->filter;
    flags = context->flags;
    object = (WDFOBJECT)context->object;
    WdfObjectReference(object);
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    match = cydivert_filter(/*buffer=*/NULL, /*layer=*/CYDIVERT_LAYER_SOCKET,
        (PVOID)socket_data, timestamp, event, ipv4, outbound, loopback,
        /*impostor=*/FALSE, /*frag_mode=*/FALSE, filter);
    if (match)
    {
        ok = cydivert_queue_work(context, /*packet=*/NULL, /*packet_len=*/0,
            /*buffers=*/NULL, /*object=*/NULL, /*layer=*/CYDIVERT_LAYER_SOCKET,
            (PVOID)socket_data, event, flags, /*priority=*/0, ipv4, outbound,
            loopback, /*impostor=*/FALSE, match, timestamp);
        if (!ok)
        {
            WdfObjectDereference(object);
            return;
        }
    }

    WdfObjectDereference(object);
    if (match && (result->rights & FWPS_RIGHT_ACTION_WRITE) != 0 &&
        event != CYDIVERT_EVENT_SOCKET_CLOSE &&
        (flags & CYDIVERT_FLAG_SNIFF) == 0)
    {
        result->actionType = FWP_ACTION_BLOCK;
        result->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
        result->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    }
}

/*
 * CyDivert work item routine for out-of-band filtering.
 */
VOID cydivert_worker(IN WDFWORKITEM item)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFFILEOBJECT object = (WDFFILEOBJECT)WdfWorkItemGetParentObject(item);
    context_t context = cydivert_context_get(object);
    PLIST_ENTRY entry;
    packet_t work;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (context->state == CYDIVERT_CONTEXT_STATE_OPEN &&
            !IsListEmpty(&context->work_queue))
    {
        entry = RemoveHeadList(&context->work_queue);
        context->work_queue_length--;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        work = CONTAINING_RECORD(entry, struct packet_s, entry);
        if (work->match)
        {
            cydivert_queue_packet(context, work);
        }
        else
        {
            cydivert_inject_packet(work);
        }

        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    cydivert_read_service(context);
}

/*
 * Queue work.
 */
static BOOL cydivert_queue_work(context_t context, PVOID packet,
    ULONG packet_len, PNET_BUFFER_LIST buffers, PVOID object,
    CYDIVERT_LAYER layer, PVOID layer_data, CYDIVERT_EVENT event,
    UINT64 flags, UINT32 priority, BOOL ipv4, BOOL outbound, BOOL loopback,
    BOOL impostor, BOOL match, LONGLONG timestamp)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PNET_BUFFER buffer;
    packet_t work;
    ULONG packet_size;
    UINT8 *data;
    PLIST_ENTRY old_entry;
    NDIS_TCP_IP_CHECKSUM_NET_BUFFER_LIST_INFO checksums;
    PCYDIVERT_DATA_NETWORK network_data;
    PCYDIVERT_DATA_FLOW flow_data;
    PCYDIVERT_DATA_SOCKET socket_data;
    PCYDIVERT_DATA_REFLECT reflect_data;
    BOOL sniffed, ip_checksum, tcp_checksum, udp_checksum;
    WDFREQUEST request = NULL;
    NTSTATUS status;

    sniffed = ((flags & CYDIVERT_FLAG_SNIFF) != 0 ||
        event == CYDIVERT_EVENT_SOCKET_CLOSE);

    if (!match && sniffed)
    {
        return TRUE;
    }
    if (match && (flags & CYDIVERT_FLAG_DROP) != 0)
    {
        return TRUE;
    }

    // Check for fast-path:
    if (match)
    {
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        if (context->state == CYDIVERT_CONTEXT_STATE_OPEN &&
            !context->shutdown_recv && IsListEmpty(&context->packet_queue) &&
            IsListEmpty(&context->work_queue))
        {
            status = WdfIoQueueRetrieveNextRequest(context->read_queue,
                &request);
            request = (!NT_SUCCESS(status)? NULL: request);
        }
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        if (request != NULL)
        {
            cydivert_fast_read_service_request(packet, packet_len, buffers,
                layer, layer_data, event, flags, ipv4, outbound, loopback,
                impostor, timestamp, request);
            return TRUE;
        }
    }

    // Copy the packet & layer data.
    switch (layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
            buffer = (PNET_BUFFER)packet;
            network_data = (PCYDIVERT_DATA_NETWORK)layer_data;
            if (packet_len > CYDIVERT_MTU_MAX)
            {
                // Cannot handle oversized packet
                return TRUE;
            }
            packet_size = CYDIVERT_PACKET_SIZE(CYDIVERT_DATA_NETWORK,
                packet_len);
            work = (packet_t)cydivert_malloc(packet_size, FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = (UINT32)packet_len;
            data = CYDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, network_data, sizeof(CYDIVERT_DATA_NETWORK));
            data = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_NETWORK, work);
            if (!cydivert_copy_data(buffer, data, packet_len))
            {
                cydivert_free(work);
                return TRUE;
            }
            checksums.Value = NET_BUFFER_LIST_INFO(buffers,
                TcpIpChecksumNetBufferListInfo);
            if (outbound)
            {
                ip_checksum = (checksums.Transmit.IpHeaderChecksum == 0);
                tcp_checksum = (checksums.Transmit.TcpChecksum == 0);
                udp_checksum = (checksums.Transmit.UdpChecksum == 0);
            }
            else
            {
                ip_checksum = (checksums.Receive.IpChecksumSucceeded == 0);
                tcp_checksum = (checksums.Receive.TcpChecksumSucceeded == 0);
                udp_checksum = (checksums.Receive.UdpChecksumSucceeded == 0);
            }
            break;

        case CYDIVERT_LAYER_FLOW:
            flow_data = (PCYDIVERT_DATA_FLOW)layer_data;
            packet_size = CYDIVERT_PACKET_SIZE(CYDIVERT_DATA_FLOW, 0);
            work = (packet_t)cydivert_malloc(packet_size, FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = 0;
            data = CYDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, flow_data, sizeof(CYDIVERT_DATA_FLOW));
            ip_checksum = tcp_checksum = udp_checksum = FALSE;
            break;
 
        case CYDIVERT_LAYER_SOCKET:
            socket_data = (PCYDIVERT_DATA_SOCKET)layer_data;
            packet_size = CYDIVERT_PACKET_SIZE(CYDIVERT_DATA_SOCKET, 0);
            work = (packet_t)cydivert_malloc(packet_size, FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = 0;
            data = CYDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, socket_data, sizeof(CYDIVERT_DATA_SOCKET));
            ip_checksum = tcp_checksum = udp_checksum = FALSE;
            break;

        case CYDIVERT_LAYER_REFLECT:
            reflect_data = (PCYDIVERT_DATA_REFLECT)layer_data;
            packet_size = CYDIVERT_PACKET_SIZE(CYDIVERT_DATA_REFLECT,
                packet_len);
            work = (packet_t)cydivert_malloc(packet_size, FALSE);
            if (work == NULL)
            {
                return TRUE;
            }
            work->packet_len = packet_len;
            data = CYDIVERT_LAYER_DATA_PTR(work);
            RtlCopyMemory(data, reflect_data, sizeof(CYDIVERT_DATA_REFLECT));
            data = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_REFLECT, work);
            RtlCopyMemory(data, packet, packet_len);
            ip_checksum = tcp_checksum = udp_checksum = FALSE;
            break;

        default:
            return TRUE;
    }

    work->layer         = layer;
    work->event         = event;
    work->sniffed       = (sniffed? 1: 0);
    work->outbound      = (outbound? 1: 0);
    work->loopback      = (loopback? 1: 0);
    work->impostor      = (impostor? 1: 0);
    work->ipv6          = (!ipv4? 1: 0);
    work->ip_checksum   = (ip_checksum? 1: 0);
    work->tcp_checksum  = (tcp_checksum? 1: 0);
    work->udp_checksum  = (udp_checksum? 1: 0);
    work->icmp_checksum = 1;
    work->match         = match;
    work->packet_size   = packet_size;
    work->priority      = priority;
    work->timestamp     = timestamp;
    work->object        = object;
    if (object != NULL)
    {
        ObfReferenceObject(object);
    }

    old_entry = NULL;
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        cydivert_free_packet(work);
        return FALSE;
    }
    if (context->shutdown_recv && context->shutdown_recv_enabled)
    {
        if ((flags & CYDIVERT_FLAG_SNIFF) != 0)
        {
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            cydivert_free_packet(work);
            return FALSE;
        }
        work->match = FALSE;
    }
    context->work_queue_length++;
    if (context->work_queue_length > CYDIVERT_WORK_QUEUE_LENGTH_MAX)
    {
        // The work queue is full; as an emergency we drop packets.
        old_entry = RemoveHeadList(&context->work_queue);
        context->work_queue_length--;
    }
    InsertTailList(&context->work_queue, &work->entry);
    WdfWorkItemEnqueue(context->worker);
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    
    if (old_entry != NULL)
    {
        work = CONTAINING_RECORD(old_entry, struct packet_s, entry);
        cydivert_free_packet(work);
    }

    return TRUE;
}

/*
 * Queue a packet.
 */
static void cydivert_queue_packet(context_t context, packet_t packet)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY old_entry;
    packet_t old_packet;
    LONGLONG timestamp;
    BOOL timeout;

    timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    while (TRUE)
    {
        if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
        {
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            cydivert_inject_packet(packet);
            return;
        }
        if (packet->packet_size > context->packet_queue_maxsize)
        {
            // (Corner case) the packet is larger than the max queue size:
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            cydivert_free_packet(packet);
            return;
        }
        timeout = CYDIVERT_TIMEOUT(context, packet->timestamp, timestamp);
        if (timeout)
        {
            // (Corner case) the packet has already expired:
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            cydivert_free_packet(packet);
            return;
        }

        if (context->packet_queue_size + packet->packet_size >
                context->packet_queue_maxsize ||
            context->packet_queue_length + 1 > context->packet_queue_maxlength)
        {
            // The queue is full; drop a packet & try again:
            old_entry = RemoveHeadList(&context->packet_queue);
            old_packet = CONTAINING_RECORD(old_entry, struct packet_s, entry);
            context->packet_queue_length--;
            context->packet_queue_size -= old_packet->packet_size;
            KeReleaseInStackQueuedSpinLock(&lock_handle);
            DEBUG("DROP: packet queue is full, dropping packet");
            cydivert_free_packet(old_packet);
            timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
            KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
            continue;
        }
        else
        {
            // Queue the packet:
            InsertTailList(&context->packet_queue, &packet->entry);
            context->packet_queue_length++;
            context->packet_queue_size += packet->packet_size;
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    DEBUG("PACKET: queued packet (packet=%p)", packet);

    return;
}

/*
 * Inject a packet.
 */
static NTSTATUS cydivert_inject_packet(packet_t packet)
{
    UINT8 *packet_data;
    UINT32 packet_len;
    UINT64 checksums;
    PCYDIVERT_DATA_NETWORK network_data;
    PMDL mdl;
    PNET_BUFFER_LIST buffers;
    HANDLE handle;
    UINT32 priority;
    NTSTATUS status;

    if (packet->layer != CYDIVERT_LAYER_NETWORK &&
        packet->layer != CYDIVERT_LAYER_NETWORK_FORWARD)
    {
        cydivert_free_packet(packet);
        return STATUS_INVALID_PARAMETER;
    }

    network_data = (PCYDIVERT_DATA_NETWORK)CYDIVERT_LAYER_DATA_PTR(packet);
    packet_data = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_NETWORK, packet);
    packet_len = packet->packet_len;

    // Fix checksums:
    checksums =
        (packet->ip_checksum == 0?   0: CYDIVERT_HELPER_NO_IP_CHECKSUM) |
        (packet->tcp_checksum == 0?  0: CYDIVERT_HELPER_NO_TCP_CHECKSUM) |
        (packet->udp_checksum == 0?  0: CYDIVERT_HELPER_NO_UDP_CHECKSUM) |
        (packet->icmp_checksum == 0? 0: CYDIVERT_HELPER_NO_ICMP_CHECKSUM |
                                        CYDIVERT_HELPER_NO_ICMPV6_CHECKSUM);
    CyDivertHelperCalcChecksums(packet_data, packet_len, NULL, checksums);

    // Decrement TTL for impostor packets:
    if (packet->impostor != 0 &&
            !CyDivertHelperDecrementTTL(packet_data, packet_len))
    {
        status = STATUS_HOPLIMIT_EXCEEDED;
        DEBUG_ERROR("failed to inject ttl-exceeded impostor packet", status);
        cydivert_free_packet(packet);
        return status;
    }

    // Inject packet:
    mdl = IoAllocateMdl(packet_data, packet_len, FALSE, FALSE, NULL);
    if (mdl == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        DEBUG_ERROR("failed to allocate MDL for injected packet", status);
        cydivert_free_packet(packet);
        return status;
    }
    MmBuildMdlForNonPagedPool(mdl);
    status = FwpsAllocateNetBufferAndNetBufferList0(nbl_pool_handle, 0, 0,
        mdl, 0, packet_len, &buffers);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create NET_BUFFER_LIST for injected packet",
            status);
        IoFreeMdl(mdl);
        cydivert_free_packet(packet);
        return status;
    }
    priority = packet->priority;
    if (packet->layer == CYDIVERT_LAYER_NETWORK_FORWARD)
    {
        handle = (packet->ipv6? injectv6_handle_forward: inject_handle_forward);
        status = FwpsInjectForwardAsync0(handle, (HANDLE)priority, 0,
            (packet->ipv6? AF_INET6: AF_INET), UNSPECIFIED_COMPARTMENT_ID,
            network_data->IfIdx, buffers, cydivert_inject_complete,
            (HANDLE)packet);
    }
    else if (packet->outbound)
    {
        handle = (packet->ipv6? injectv6_handle_out: inject_handle_out);
        status = FwpsInjectNetworkSendAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, buffers, cydivert_inject_complete,
            (HANDLE)packet);
    }
    else
    {
        handle = (packet->ipv6? injectv6_handle_in: inject_handle_in);
        status = FwpsInjectNetworkReceiveAsync0(handle, (HANDLE)priority, 0,
            UNSPECIFIED_COMPARTMENT_ID, network_data->IfIdx,
            network_data->SubIfIdx, buffers, cydivert_inject_complete,
            (HANDLE)packet);
    }

    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to inject (packet=%p)", status, packet);
        FwpsFreeNetBufferList0(buffers);
        IoFreeMdl(mdl);
        cydivert_free_packet(packet);
    }
    return status;
}

/*
 * Free a packet.
 */
static void cydivert_free_packet(packet_t packet)
{
    if (packet->object != NULL)
    {
        ObDereferenceObject(packet->object);
    }
    cydivert_free(packet);
}

/*
 * CyDivert inject complete routine.
 */
static void NTAPI cydivert_inject_complete(VOID *context,
    NET_BUFFER_LIST *buffers, BOOLEAN dispatch_level)
{
    PMDL mdl;
    PNET_BUFFER buffer;
    packet_t packet;
    UNREFERENCED_PARAMETER(dispatch_level);

    packet = (packet_t)context;
    if (buffers->Status == STATUS_INVALID_BUFFER_SIZE)
    {
        // STATUS_INVALID_BUFFER_SIZE indicates that the send failed because
        // the packet was larger than the MTU.  We generate an ICMP
        // Fragmentation Needed (for IPv4) or an ICMPV6 Packet Too Big (for
        // IPv6) message to allow for PMTU discovery.
        cydivert_inject_packet_too_big(packet);
    }

    buffer = NET_BUFFER_LIST_FIRST_NB(buffers);
    mdl = NET_BUFFER_FIRST_MDL(buffer);
    IoFreeMdl(mdl);
    FwpsFreeNetBufferList0(buffers);
    cydivert_free_packet(packet);
}

/*
 * CyDivert inject an ICMP(V6) Packet Too Big message.
 */
static void cydivert_inject_packet_too_big(packet_t packet)
{
    const UINT mtus[] =
    {
        568, 768, 1024, 1192, 1280, 1372, 1452, 1500, 4096, UINT16_MAX,
            UINT32_MAX
    };
    PCYDIVERT_IPHDR ip_header, ip_header_2;
    PCYDIVERT_IPV6HDR ipv6_header = NULL, ipv6_header_2;
    PCYDIVERT_ICMPHDR icmp_header;
    PCYDIVERT_ICMPV6HDR icmpv6_header;
    packet_t icmp;
    UINT version, packet_len, copy_len, icmp_len;
    UINT icmp_size;
    UINT i, min_mtu = /*ipv4 min MTU=*/568, mtu;
    UINT32 flowlabel;
    UINT8 *data;

    if (packet->layer != CYDIVERT_LAYER_NETWORK || !packet->outbound ||
            packet->loopback)
    {
        return;
    }
    ip_header = (PCYDIVERT_IPHDR)CYDIVERT_PACKET_DATA_PTR(
        CYDIVERT_DATA_NETWORK, packet);
    version = ip_header->Version;
    switch (version)
    {
        case 4:
            packet_len = RtlUshortByteSwap(ip_header->Length);
            copy_len = ip_header->HdrLength * sizeof(UINT32) + 8;
            copy_len = (packet_len < copy_len? packet_len: copy_len);
            icmp_len = sizeof(CYDIVERT_IPHDR) + sizeof(CYDIVERT_ICMPHDR) +
                copy_len;
            break;
        case 6:
            ipv6_header = (PCYDIVERT_IPV6HDR)ip_header;
            packet_len = RtlUshortByteSwap(ipv6_header->Length) +
                sizeof(CYDIVERT_IPV6HDR);
            min_mtu = /*ipv6 min MTU=*/1280;
            copy_len = min_mtu - sizeof(CYDIVERT_IPV6HDR) -
                sizeof(CYDIVERT_ICMPV6HDR);
            copy_len = (packet_len < copy_len? packet_len: copy_len);
            icmp_len = sizeof(CYDIVERT_IPV6HDR) +
                sizeof(CYDIVERT_ICMPV6HDR) + copy_len;
            break;
        default:
            return;
    }
    if (packet_len <= min_mtu)
    {
        return;
    }

    // We do not actually know the MTU value, so we make an educated guess.
    for (i = 0; packet_len > mtus[i]; i++)
        ;
    mtu = (i == 0? min_mtu: mtus[i-1]);
    mtu = (mtu < min_mtu? min_mtu: mtu);

    icmp_size = CYDIVERT_PACKET_SIZE(CYDIVERT_DATA_NETWORK, icmp_len);
    icmp = (packet_t)cydivert_malloc(icmp_size, FALSE);
    if (icmp == NULL)
    {
        return;
    }
    icmp->layer         = CYDIVERT_LAYER_NETWORK;
    icmp->event         = CYDIVERT_EVENT_NETWORK_PACKET;
    icmp->sniffed       = 0;        // Unused
    icmp->outbound      = 0;        // Inbound
    icmp->loopback      = 0;        // Unused
    icmp->impostor      = 0;        // Treat as non-impostor
    icmp->ipv6          = (version == 6? 1: 0);
    icmp->ip_checksum   = 0;        // IP checksum valid
    icmp->tcp_checksum  = 0;        // Unused
    icmp->udp_checksum  = 0;        // Unused
    icmp->icmp_checksum = 0;        // ICMP(V6) checksum invalid
    icmp->match         = 0;        // Unused
    icmp->packet_size   = icmp_size;
    icmp->packet_len    = icmp_len;
    icmp->priority      = packet->priority;
    icmp->timestamp     = 0;        // Unused
    icmp->object        = NULL;
    RtlCopyMemory(CYDIVERT_LAYER_DATA_PTR(icmp),
        CYDIVERT_LAYER_DATA_PTR(packet), sizeof(CYDIVERT_DATA_NETWORK));
    data = CYDIVERT_PACKET_DATA_PTR(CYDIVERT_DATA_NETWORK, icmp);
    switch (version)
    {
        case 4:
            ip_header_2 = (PCYDIVERT_IPHDR)data;
            ip_header_2->Version   = 4;
            ip_header_2->HdrLength = sizeof(CYDIVERT_IPHDR) / sizeof(UINT32);
            ip_header_2->TOS       = 0x0;
            ip_header_2->Length    = RtlUshortByteSwap(icmp_len);
            ip_header_2->Id        = 0x0;
            ip_header_2->TTL       = 64;
            ip_header_2->Protocol  = IPPROTO_ICMP;
            ip_header_2->SrcAddr   = ip_header->DstAddr;
            ip_header_2->DstAddr   = ip_header->SrcAddr;
            CYDIVERT_IPHDR_SET_FRAGOFF(ip_header_2, 0x0);
            CYDIVERT_IPHDR_SET_MF(ip_header_2, 0);
            CYDIVERT_IPHDR_SET_DF(ip_header_2, 1);
            CYDIVERT_IPHDR_SET_RESERVED(ip_header_2, 0x0);
            icmp_header = (PCYDIVERT_ICMPHDR)(ip_header_2 + 1);
            icmp_header->Type      = /*Destination Unreachable=*/3;
            icmp_header->Code      = /*Fragmentation required=*/4;
            icmp_header->Body      = ((UINT32)RtlUshortByteSwap(mtu)) << 16;
            data = (UINT8 *)(icmp_header + 1);
            RtlCopyMemory(data, ip_header, copy_len);
            break;
        case 6:
            icmp_len -= sizeof(CYDIVERT_IPV6HDR);
            ipv6_header_2 = (PCYDIVERT_IPV6HDR)data;
            ipv6_header_2->Version  = 6;
            ipv6_header_2->Length   = RtlUshortByteSwap(icmp_len);
            ipv6_header_2->NextHdr  = IPPROTO_ICMPV6;
            ipv6_header_2->HopLimit = 64;
            RtlCopyMemory(ipv6_header_2->SrcAddr, ipv6_header->DstAddr,
                sizeof(ipv6_header_2->SrcAddr));
            RtlCopyMemory(ipv6_header_2->DstAddr, ipv6_header->SrcAddr,
                sizeof(ipv6_header_2->DstAddr));
            CYDIVERT_IPV6HDR_SET_TRAFFICCLASS(ipv6_header_2, 0x0);
            flowlabel = CYDIVERT_IPV6HDR_GET_FLOWLABEL(ipv6_header);
            CYDIVERT_IPV6HDR_SET_FLOWLABEL(ipv6_header_2, flowlabel);
            icmpv6_header = (PCYDIVERT_ICMPV6HDR)(ipv6_header_2 + 1);
            icmpv6_header->Type = /*Packet Too Big=*/2;
            icmpv6_header->Code = 0;
            icmpv6_header->Body = RtlUlongByteSwap(mtu);
            data = (UINT8 *)(icmpv6_header + 1);
            RtlCopyMemory(data, ipv6_header, copy_len);
            break;
    }
    cydivert_inject_packet(icmp);
}

/*
 * Copy data from a NET_BUFFER.
 */
static BOOL cydivert_copy_data(PNET_BUFFER buffer, PVOID data, UINT size)
{
    PVOID ptr;

    ptr = NdisGetDataBuffer(buffer, size, NULL, 1, 0);
    if (ptr != NULL)
    {
        // Contiguous (common) case:
        RtlCopyMemory(data, ptr, size);
    }
    else
    {
        // Non-contigious case:
        ptr = NdisGetDataBuffer(buffer, size, data, 1, 0);
        if (ptr == NULL)
        {
            return FALSE;
        }
    }

    return TRUE;
}

/*
 * Lookup packet/payload data at given index.
 */
static BOOL cydivert_get_data(PNET_BUFFER buffer, UINT length, INT min,
    INT max, INT idx, PVOID data, UINT size)
{
    BOOL success;
    UNREFERENCED_PARAMETER(length);

    idx += (idx < 0? max: min);
    if (idx < min || idx > (max - (INT)size))
    {
        return FALSE;       // OOB
    }

    if (idx > 0)
    {
        NdisAdvanceNetBufferDataStart(buffer, idx, FALSE, NULL);
    }
    success = cydivert_copy_data(buffer, data, size);
    if (idx > 0)
    {
        (VOID)NdisRetreatNetBufferDataStart(buffer, idx, 0, NULL);
    }
    return success;
}

/*
 * Parse packet headers.
 */
static CYDIVERT_INLINE BOOL cydivert_parse_headers(PNET_BUFFER buffer,
    BOOL ipv4, BOOL *fragment_ptr, PCYDIVERT_IPHDR *ip_header_ptr,
    PCYDIVERT_IPV6HDR *ipv6_header_ptr, PCYDIVERT_ICMPHDR *icmp_header_ptr,
    PCYDIVERT_ICMPV6HDR *icmpv6_header_ptr, PCYDIVERT_TCPHDR *tcp_header_ptr,
    PCYDIVERT_UDPHDR *udp_header_ptr, UINT8 *proto_ptr, UINT *header_len_ptr,
    UINT *payload_len_ptr)
{
    UINT total_len, ip_header_len = 0;
    PCYDIVERT_IPHDR ip_header = NULL;
    PCYDIVERT_IPV6HDR ipv6_header = NULL;
    PCYDIVERT_ICMPHDR icmp_header = NULL;
    PCYDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PCYDIVERT_TCPHDR tcp_header = NULL;
    PCYDIVERT_UDPHDR udp_header = NULL;
    PCYDIVERT_IPV6FRAGHDR frag_header;
    BOOL fragment = FALSE;
    UINT8 protocol = 0;
    UINT16 frag_off = 0;
    UINT header_len = 0;
    NTSTATUS status;

    // Parse the headers:
    if (buffer == NULL)
    {
        DEBUG("FILTER: REJECT (packet is NULL)");
        return FALSE;
    }
    total_len = NET_BUFFER_DATA_LENGTH(buffer);
    if (total_len < sizeof(CYDIVERT_IPHDR))
    {
        DEBUG("FILTER: REJECT (packet length too small)");
        return FALSE;
    }

    // Get the IP header.
    if (ipv4)
    {
        // IPv4:
        if (total_len < sizeof(CYDIVERT_IPHDR))
        {
            DEBUG("FILTER: REJECT (packet length too small)");
            return FALSE;
        }
        ip_header = (PCYDIVERT_IPHDR)NdisGetDataBuffer(buffer,
            sizeof(CYDIVERT_IPHDR), NULL, 1, 0);
        if (ip_header == NULL)
        {
            DEBUG("FILTER: REJECT (failed to get IPv4 header)");
            return FALSE;
        }
        ip_header_len = ip_header->HdrLength*sizeof(UINT32);
        if (ip_header->Version != 4 ||
            RtlUshortByteSwap(ip_header->Length) != total_len ||
            ip_header->HdrLength < 5 ||
            ip_header_len > total_len)
        {
            DEBUG("FILTER: REJECT (bad IPv4 packet)");
            return FALSE;
        }
        frag_off = RtlUshortByteSwap(CYDIVERT_IPHDR_GET_FRAGOFF(ip_header));
        fragment = (frag_off != 0 || CYDIVERT_IPHDR_GET_MF(ip_header) != 0);
        protocol = ip_header->Protocol;
        NdisAdvanceNetBufferDataStart(buffer, ip_header_len, FALSE, NULL);
    }
    else
    {
        // IPv6:
        if (total_len < sizeof(CYDIVERT_IPV6HDR))
        {
            DEBUG("FILTER: REJECT (packet length too small)");
            return FALSE;
        }
        ipv6_header = (PCYDIVERT_IPV6HDR)NdisGetDataBuffer(buffer,
            sizeof(CYDIVERT_IPV6HDR), NULL, 1, 0);
        if (ipv6_header == NULL)
        {
            DEBUG("FILTER: REJECT (failed to get IPv6 header)");
            return FALSE;
        }
        ip_header_len = sizeof(CYDIVERT_IPV6HDR);
        if (ipv6_header->Version != 6 ||
            ip_header_len > total_len ||
            RtlUshortByteSwap(ipv6_header->Length) +
                sizeof(CYDIVERT_IPV6HDR) != total_len)
        {
            DEBUG("FILTER: REJECT (bad IPv6 packet)");
            return FALSE;
        }
        protocol = ipv6_header->NextHdr;
        NdisAdvanceNetBufferDataStart(buffer, ip_header_len, FALSE, NULL);

        // Skip extension headers:
        while (frag_off == 0)
        {
            UINT8 *ext_header = NULL;
            UINT ext_header_len = 0;
            BOOL is_ext_header;
            switch (protocol)
            {
                case IPPROTO_FRAGMENT:
                    frag_header = (PCYDIVERT_IPV6FRAGHDR)
                        NdisGetDataBuffer(buffer, 8, NULL, 1, 0);
                    ext_header = (UINT8 *)frag_header;
                    if (fragment || frag_header == NULL)
                    {
                        is_ext_header = FALSE;
                        break;
                    }
                    fragment = TRUE;
                    frag_off = RtlUshortByteSwap(
                        CYDIVERT_IPV6FRAGHDR_GET_FRAGOFF(frag_header));
                    ext_header_len = 8;
                    is_ext_header  = TRUE;
                    break;

                case IPPROTO_AH:
                case IPPROTO_HOPOPTS:
                case IPPROTO_DSTOPTS:
                case IPPROTO_ROUTING:
                case IPPROTO_MH:
                    ext_header = (UINT8 *)NdisGetDataBuffer(buffer, 2, NULL,
                        1, 0);
                    if (ext_header == NULL)
                    {
                        is_ext_header = FALSE;
                        break;
                    }
                    ext_header_len = (UINT)ext_header[1];
                    if (protocol == IPPROTO_AH)
                    {
                        ext_header_len += 2;
                        ext_header_len *= 4;
                    }
                    else
                    {
                        ext_header_len++;
                        ext_header_len *= 8;
                    }
                    is_ext_header = TRUE;
                    break;
                default:

                    is_ext_header = FALSE;
                    break;
            }

            if (!is_ext_header || ip_header_len + ext_header_len > total_len)
            {
                break;
            }
            protocol = ext_header[0];
            ip_header_len += ext_header_len;
            NdisAdvanceNetBufferDataStart(buffer, ext_header_len, FALSE,
                NULL);
        }
    }

    header_len = ip_header_len;
    if (frag_off == 0)
    {
        switch (protocol)
        {
            case IPPROTO_ICMP:
                if (ip_header == NULL)
                {
                    break;
                }
                icmp_header = (PCYDIVERT_ICMPHDR)NdisGetDataBuffer(buffer,
                    sizeof(CYDIVERT_ICMPHDR), NULL, 1, 0);
                header_len +=
                    (icmp_header == NULL? 0: sizeof(CYDIVERT_ICMPHDR));
                break;

            case IPPROTO_ICMPV6:
                if (ipv6_header == NULL)
                {
                    break;
                }
                icmpv6_header = (PCYDIVERT_ICMPV6HDR)NdisGetDataBuffer(buffer,
                    sizeof(CYDIVERT_ICMPV6HDR), NULL, 1, 0);
                header_len +=
                    (icmpv6_header == NULL? 0: sizeof(CYDIVERT_ICMPV6HDR));
                break;

            case IPPROTO_TCP:
                tcp_header = (PCYDIVERT_TCPHDR)NdisGetDataBuffer(buffer,
                    sizeof(CYDIVERT_TCPHDR), NULL, 1, 0);
                if (tcp_header != NULL)
                {
                    if (tcp_header->HdrLength < 5)
                    {
                        tcp_header = NULL;
                    }
                    else
                    {
                        UINT tcp_header_len =
                            tcp_header->HdrLength * sizeof(UINT32);
                        tcp_header_len =
                            (header_len + tcp_header_len > total_len?
                                total_len - header_len: tcp_header_len);
                        header_len += tcp_header_len;
                    }
                }
                break;

            case IPPROTO_UDP:
                udp_header = (PCYDIVERT_UDPHDR)NdisGetDataBuffer(buffer,
                    sizeof(CYDIVERT_UDPHDR), NULL, 1, 0);
                header_len +=
                    (udp_header == NULL? 0: sizeof(CYDIVERT_UDPHDR));
                break;
            default:
                break;
        }
    }

    status = NdisRetreatNetBufferDataStart(buffer, ip_header_len, 0, NULL);
    if (!NT_SUCCESS(status))
    {
        // Should never occur.
        DEBUG("FILTER: REJECT (failed to retreat buffer)");
        return FALSE;
    }

    *fragment_ptr      = fragment;
    *ip_header_ptr     = ip_header;
    *ipv6_header_ptr   = ipv6_header;
    *icmp_header_ptr   = icmp_header;
    *icmpv6_header_ptr = icmpv6_header;
    *tcp_header_ptr    = tcp_header;
    *udp_header_ptr    = udp_header;
    *proto_ptr         = protocol;
    *header_len_ptr    = header_len;
    *payload_len_ptr   = total_len - header_len;

    return TRUE;
}

/*
 * Checks if the given network packet is of interest.
 */
static BOOL cydivert_filter(PNET_BUFFER buffer, CYDIVERT_LAYER layer,
    const VOID *layer_data, LONGLONG timestamp, CYDIVERT_EVENT event,
    BOOL ipv4, BOOL outbound, BOOL loopback, BOOL impostor, BOOL frag_mode,
    const CYDIVERT_FILTER *filter)
{
    PCYDIVERT_IPHDR ip_header = NULL;
    PCYDIVERT_IPV6HDR ipv6_header = NULL;
    PCYDIVERT_ICMPHDR icmp_header = NULL;
    PCYDIVERT_ICMPV6HDR icmpv6_header = NULL;
    PCYDIVERT_TCPHDR tcp_header = NULL;
    PCYDIVERT_UDPHDR udp_header = NULL;
    BOOL fragment = FALSE;
    UINT8 protocol = 0;
    UINT header_len = 0, payload_len = 0;
    PCYDIVERT_DATA_NETWORK network_data = NULL;
    PCYDIVERT_DATA_FLOW flow_data = NULL;
    PCYDIVERT_DATA_SOCKET socket_data = NULL;
    PCYDIVERT_DATA_REFLECT reflect_data = NULL;
    int result;

    switch (layer)
    {
        case CYDIVERT_LAYER_NETWORK:
        case CYDIVERT_LAYER_NETWORK_FORWARD:
            if (!cydivert_parse_headers(buffer, ipv4, &fragment, &ip_header,
                    &ipv6_header, &icmp_header, &icmpv6_header, &tcp_header,
                    &udp_header, &protocol, &header_len, &payload_len))
            {
                return FALSE;
            }
            if (fragment && !frag_mode)
            {
                return FALSE;
            }
            network_data = (PCYDIVERT_DATA_NETWORK)layer_data;
            break;
        case CYDIVERT_LAYER_FLOW:
            flow_data = (PCYDIVERT_DATA_FLOW)layer_data;
            break;
        case CYDIVERT_LAYER_SOCKET:
            socket_data = (PCYDIVERT_DATA_SOCKET)layer_data;
            break;
        case CYDIVERT_LAYER_REFLECT:
            reflect_data = (PCYDIVERT_DATA_REFLECT)layer_data;
            break;
        default:
            DEBUG("FILTER: REJECT (invalid parameter)");
            return FALSE;
    }

    result = CyDivertExecuteFilter(
        filter,
        layer,
        timestamp,
        event,
        ipv4,
        outbound,
        loopback,
        impostor,
        fragment,
        network_data,
        flow_data,
        socket_data,
        reflect_data,
        ip_header,
        ipv6_header,
        icmp_header,
        icmpv6_header,
        tcp_header,
        udp_header,
        protocol,
        (const VOID *)buffer,
        header_len + payload_len,
        header_len,
        payload_len);

    return (result == 1);
}

/*
 * Compile a CyDivert filter from an IOCTL.
 */
static const CYDIVERT_FILTER *cydivert_filter_compile(
    const CYDIVERT_FILTER *ioctl_filter, size_t ioctl_filter_len,
    CYDIVERT_LAYER layer)
{
    PCYDIVERT_FILTER filter = NULL;
    CYDIVERT_EVENT event;
    BOOL neg_lb, neg_ub, neg;
    UINT32 lb[4], ub[4];
    int result;
    UINT16 i;
    size_t length;

    if (ioctl_filter_len % sizeof(CYDIVERT_FILTER) != 0)
    {
        goto cydivert_filter_compile_error;
    }
    length = ioctl_filter_len / sizeof(CYDIVERT_FILTER);
    if (length >= CYDIVERT_FILTER_MAXLEN || length == 0)
    {
        goto cydivert_filter_compile_error;
    }

    filter = (PCYDIVERT_FILTER)cydivert_malloc(
        length * sizeof(CYDIVERT_FILTER), FALSE);
    if (filter == NULL)
    {
        goto cydivert_filter_compile_error;
    }
 
    for (i = 0; i < length; i++)
    {
        if (ioctl_filter[i].field > CYDIVERT_FILTER_FIELD_MAX ||
            ioctl_filter[i].test > CYDIVERT_FILTER_TEST_MAX)
        {
            goto cydivert_filter_compile_error;
        }
        switch (ioctl_filter[i].success)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (ioctl_filter[i].success <= i ||
                    ioctl_filter[i].success >= length)
                {
                    goto cydivert_filter_compile_error;
                }
                break;
        }
        switch (ioctl_filter[i].failure)
        {
            case CYDIVERT_FILTER_RESULT_ACCEPT:
            case CYDIVERT_FILTER_RESULT_REJECT:
                break;
            default:
                if (ioctl_filter[i].failure <= i ||
                    ioctl_filter[i].failure >= length)
                {
                    goto cydivert_filter_compile_error;
                }
                break;
        }

        // Enforce layers:
        if (!CyDivertValidateField(layer, ioctl_filter[i].field))
        {
            goto cydivert_filter_compile_error;
        }

        // Enforce ranges:
        neg_lb = neg_ub = 0;
        lb[0] = lb[1] = lb[2] = lb[3] = 0;
        ub[0] = ub[1] = ub[2] = ub[3] = 0;
        switch (ioctl_filter[i].field)
        {
            case CYDIVERT_FILTER_FIELD_PACKET:
            case CYDIVERT_FILTER_FIELD_PACKET16:
            case CYDIVERT_FILTER_FIELD_PACKET32:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD32:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD32:
            {
                INT idx = (INT)ioctl_filter[i].arg[1];
                if (ioctl_filter[i].neg)
                {
                    goto cydivert_filter_compile_error;
                }
                if (idx > CYDIVERT_MTU_MAX || idx < -CYDIVERT_MTU_MAX)
                {
                    goto cydivert_filter_compile_error;
                }
                lb[1] = ub[1] = ioctl_filter[i].arg[1];
                break;
            }
            default:
                break;
        }
        switch (ioctl_filter[i].field)
        {
            case CYDIVERT_FILTER_FIELD_ZERO:
            case CYDIVERT_FILTER_FIELD_INBOUND:
            case CYDIVERT_FILTER_FIELD_OUTBOUND:
            case CYDIVERT_FILTER_FIELD_FRAGMENT:
            case CYDIVERT_FILTER_FIELD_IP:
            case CYDIVERT_FILTER_FIELD_IPV6:
            case CYDIVERT_FILTER_FIELD_ICMP:
            case CYDIVERT_FILTER_FIELD_ICMPV6:
            case CYDIVERT_FILTER_FIELD_TCP:
            case CYDIVERT_FILTER_FIELD_UDP:
            case CYDIVERT_FILTER_FIELD_IP_DF:
            case CYDIVERT_FILTER_FIELD_IP_MF:
            case CYDIVERT_FILTER_FIELD_TCP_URG:
            case CYDIVERT_FILTER_FIELD_TCP_ACK:
            case CYDIVERT_FILTER_FIELD_TCP_PSH:
            case CYDIVERT_FILTER_FIELD_TCP_RST:
            case CYDIVERT_FILTER_FIELD_TCP_SYN:
            case CYDIVERT_FILTER_FIELD_TCP_FIN:
                ub[0] = 1;
                break;
            case CYDIVERT_FILTER_FIELD_LAYER:
                ub[0] = CYDIVERT_LAYER_MAX;
                break;
            case CYDIVERT_FILTER_FIELD_PRIORITY:
                neg_lb = TRUE;
                lb[0] = ub[0] = CYDIVERT_PRIORITY_MAX;
                break;
            case CYDIVERT_FILTER_FIELD_EVENT:
                event = (CYDIVERT_EVENT)ioctl_filter[i].arg[0];
                switch (layer)
                {
                    case CYDIVERT_LAYER_NETWORK:
                    case CYDIVERT_LAYER_NETWORK_FORWARD:
                        if (event != CYDIVERT_EVENT_NETWORK_PACKET)
                        {
                            goto cydivert_filter_compile_error;
                        }
                        break;
                    case CYDIVERT_LAYER_FLOW:
                        if (event != CYDIVERT_EVENT_FLOW_ESTABLISHED &&
                            event != CYDIVERT_EVENT_FLOW_DELETED)
                        {
                            goto cydivert_filter_compile_error;
                        }
                        break;
                    case CYDIVERT_LAYER_SOCKET:
                        if (event != CYDIVERT_EVENT_SOCKET_BIND &&
                            event != CYDIVERT_EVENT_SOCKET_CONNECT &&
                            event != CYDIVERT_EVENT_SOCKET_LISTEN &&
                            event != CYDIVERT_EVENT_SOCKET_ACCEPT &&
                            event != CYDIVERT_EVENT_SOCKET_CLOSE)
                        {
                            goto cydivert_filter_compile_error;
                        }
                        break;
                    case CYDIVERT_LAYER_REFLECT:
                        if (event != CYDIVERT_EVENT_REFLECT_OPEN &&
                            event != CYDIVERT_EVENT_REFLECT_CLOSE)
                        {
                            goto cydivert_filter_compile_error;
                        }
                        break;
                    default:
                        goto cydivert_filter_compile_error;
                }
                ub[0] = CYDIVERT_EVENT_MAX;
                break;
            case CYDIVERT_FILTER_FIELD_IP_HDRLENGTH:
            case CYDIVERT_FILTER_FIELD_TCP_HDRLENGTH:
                ub[0] = 0x0F;
                break;
            case CYDIVERT_FILTER_FIELD_IP_TOS:
            case CYDIVERT_FILTER_FIELD_IP_TTL:
            case CYDIVERT_FILTER_FIELD_IP_PROTOCOL:
            case CYDIVERT_FILTER_FIELD_IPV6_TRAFFICCLASS:
            case CYDIVERT_FILTER_FIELD_IPV6_NEXTHDR:
            case CYDIVERT_FILTER_FIELD_IPV6_HOPLIMIT:
            case CYDIVERT_FILTER_FIELD_ICMP_TYPE:
            case CYDIVERT_FILTER_FIELD_ICMP_CODE:
            case CYDIVERT_FILTER_FIELD_ICMPV6_TYPE:
            case CYDIVERT_FILTER_FIELD_ICMPV6_CODE:
            case CYDIVERT_FILTER_FIELD_PROTOCOL:
            case CYDIVERT_FILTER_FIELD_PACKET:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD:
            case CYDIVERT_FILTER_FIELD_RANDOM8:
                ub[0] = 0xFF;
                break;
            case CYDIVERT_FILTER_FIELD_IP_FRAGOFF:
                ub[0] = 0x1FFF;
                break;
            case CYDIVERT_FILTER_FIELD_IP_LENGTH:
            case CYDIVERT_FILTER_FIELD_IP_ID:
            case CYDIVERT_FILTER_FIELD_IP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_IPV6_LENGTH:
            case CYDIVERT_FILTER_FIELD_ICMP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_ICMPV6_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_TCP_SRCPORT:
            case CYDIVERT_FILTER_FIELD_TCP_DSTPORT:
            case CYDIVERT_FILTER_FIELD_TCP_WINDOW:
            case CYDIVERT_FILTER_FIELD_TCP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_TCP_URGPTR:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOADLENGTH:
            case CYDIVERT_FILTER_FIELD_UDP_SRCPORT:
            case CYDIVERT_FILTER_FIELD_UDP_DSTPORT:
            case CYDIVERT_FILTER_FIELD_UDP_LENGTH:
            case CYDIVERT_FILTER_FIELD_UDP_CHECKSUM:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOADLENGTH:
            case CYDIVERT_FILTER_FIELD_LOCALPORT:
            case CYDIVERT_FILTER_FIELD_REMOTEPORT:
            case CYDIVERT_FILTER_FIELD_PACKET16:
            case CYDIVERT_FILTER_FIELD_TCP_PAYLOAD16:
            case CYDIVERT_FILTER_FIELD_UDP_PAYLOAD16:
            case CYDIVERT_FILTER_FIELD_RANDOM16:
                ub[0] = 0xFFFF;
                break;
            case CYDIVERT_FILTER_FIELD_LENGTH:
                lb[0] = sizeof(CYDIVERT_IPHDR);
                ub[0] = CYDIVERT_MTU_MAX;
                break;
            case CYDIVERT_FILTER_FIELD_IPV6_FLOWLABEL:
                ub[0] = 0x000FFFFF;
                break;
            case CYDIVERT_FILTER_FIELD_IP_SRCADDR:
            case CYDIVERT_FILTER_FIELD_IP_DSTADDR:
                ub[0] = 0xFFFFFFFF;
                ub[1] = lb[1] = 0x0000FFFF;
                break;
            case CYDIVERT_FILTER_FIELD_TIMESTAMP:
                lb[1] = 0x80000000;
                ub[0] = 0xFFFFFFFF;
                ub[1] = 0x7FFFFFFF;
                neg_lb = TRUE;
                break;
            case CYDIVERT_FILTER_FIELD_ENDPOINTID:
            case CYDIVERT_FILTER_FIELD_PARENTENDPOINTID:
                ub[0] = ub[1] = 0xFFFFFFFF;
                break;
            case CYDIVERT_FILTER_FIELD_IPV6_SRCADDR:
            case CYDIVERT_FILTER_FIELD_IPV6_DSTADDR:
            case CYDIVERT_FILTER_FIELD_LOCALADDR:
            case CYDIVERT_FILTER_FIELD_REMOTEADDR:
                ub[0] = ub[1] = ub[2] = ub[3] = 0xFFFFFFFF;
                break;
            default:
                ub[0] = 0xFFFFFFFF;
                break;
        }
        neg = (ioctl_filter[i].neg? TRUE: FALSE);
        result = CyDivertCompare128(neg, ioctl_filter[i].arg, neg_lb,
            lb, /*big=*/TRUE);
        if (result < 0)
        {
            goto cydivert_filter_compile_error;
        }
        result = CyDivertCompare128(neg, ioctl_filter[i].arg, neg_ub,
            ub, /*big=*/TRUE);
        if (result > 0)
        {
            goto cydivert_filter_compile_error;
        }

        // Disallow negative zero:
        if (neg &&
                ioctl_filter[i].arg[0] == 0 && ioctl_filter[i].arg[1] == 0 &&
                ioctl_filter[i].arg[2] == 0 && ioctl_filter[i].arg[3] == 0)
        {
            goto cydivert_filter_compile_error;
        }

        filter[i].field   = ioctl_filter[i].field;
        filter[i].test    = ioctl_filter[i].test;
        filter[i].success = ioctl_filter[i].success;
        filter[i].failure = ioctl_filter[i].failure;
        filter[i].neg     = ioctl_filter[i].neg;
        filter[i].arg[0]  = ioctl_filter[i].arg[0];
        filter[i].arg[1]  = ioctl_filter[i].arg[1];
        filter[i].arg[2]  = ioctl_filter[i].arg[2];
        filter[i].arg[3]  = ioctl_filter[i].arg[3];
    }
    
    return filter;

cydivert_filter_compile_error:

    cydivert_free((PVOID)filter);
    return NULL;
}

/****************************************************************************/
/* CYDIVERT REFLECT MANAGER IMPLEMENTATION                                 */
/****************************************************************************/

#define CYDIVERT_REFLECT_PACKET_MAX        12288

/*
 * CyDivert reflect state.
 */
static BOOL reflect_inited = FALSE;         // Reflection initialized?
static BOOL reflect_worker_queued = FALSE;  // Reflect worker queued?
static KSPIN_LOCK reflect_lock;             // Reflect lock.
static LIST_ENTRY reflect_event_queue;      // Reflect event queue.
static LIST_ENTRY reflect_contexts;         // All open (non-REFLECT) contexts.
static LIST_ENTRY reflect_waiters;          // All open REFLECT contexts.
static WDFWORKITEM reflect_worker;          // Reflect work item.
#pragma data_seg(push, stack, "PAGE")
static char reflect_packet[CYDIVERT_REFLECT_PACKET_MAX];
#pragma data_seg(pop, stack)

/*
 * Initialize the reflection layer implementation.
 */
static NTSTATUS cydivert_reflect_init(WDFOBJECT parent)
{
    WDF_WORKITEM_CONFIG item_config;
    WDF_OBJECT_ATTRIBUTES obj_attrs;
    NTSTATUS status;

    KeInitializeSpinLock(&reflect_lock);
    InitializeListHead(&reflect_event_queue);
    InitializeListHead(&reflect_contexts);
    InitializeListHead(&reflect_waiters);
    WDF_WORKITEM_CONFIG_INIT(&item_config, cydivert_reflect_worker);
    item_config.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&obj_attrs);
    obj_attrs.ParentObject = parent;
    status = WdfWorkItemCreate(&item_config, &obj_attrs, &reflect_worker);
    if (!NT_SUCCESS(status))
    {
        DEBUG_ERROR("failed to create reflection work item", status);
        return status;
    }
    reflect_inited = TRUE;
    return STATUS_SUCCESS;
}

/*
 * Cleanup the reflection layer implementation.
 */
static void cydivert_reflect_close(void)
{
    if (!reflect_inited)
    {
        return;
    }
    WdfWorkItemFlush(reflect_worker);
    WdfObjectDelete(reflect_worker);
}

/*
 * CyDivert handle reflect open event.
 */
static void cydivert_reflect_open_event(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    WDFOBJECT object;
    reflect_event_t reflect_event;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    object = (WDFOBJECT)context->object;
    // To be released on the close event.  This ensures the context object
    // remains valid until the close event has been handled.
    WdfObjectReference(object);
    context->reflect.open = TRUE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    // Queue the event:
    reflect_event = &context->reflect.open_event;
    reflect_event->context = context;
    reflect_event->event   = CYDIVERT_EVENT_REFLECT_OPEN;
    KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    InsertTailList(&reflect_event_queue, &reflect_event->entry);
    if (!reflect_worker_queued)
    {
        WdfWorkItemEnqueue(reflect_worker);
        reflect_worker_queued = TRUE;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * CyDivert handle reflect close event.
 */
static void cydivert_reflect_close_event(context_t context)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    reflect_event_t reflect_event;
    BOOL open;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    open = context->reflect.open;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    if (!open)
    {
        return;
    }

    // Queue the event:
    reflect_event = &context->reflect.close_event;
    reflect_event->context = context;
    reflect_event->event   = CYDIVERT_EVENT_REFLECT_CLOSE;
    KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    InsertTailList(&reflect_event_queue, &reflect_event->entry);
    if (!reflect_worker_queued)
    {
        WdfWorkItemEnqueue(reflect_worker);
        reflect_worker_queued = TRUE;
    }
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * Create REFLECT layer packet to pass the filter.
 */
static PVOID cydivert_reflect_packet(context_t context, ULONG *len_ptr)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    const CYDIVERT_FILTER *filter;
    UINT16 filter_len;
    CYDIVERT_STREAM stream;

    stream.data     = reflect_packet;
    stream.pos      = 0;
    stream.max      = sizeof(reflect_packet) - 1;
    stream.overflow = FALSE;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    filter = context->filter;
    filter_len = context->filter_len;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    
    CyDivertSerializeFilter(&stream, filter, (UINT8)filter_len);
    *len_ptr = stream.pos;
    return (PVOID)stream.data;
}

/*
 * Notify all REFLECT layer contexts a new event.
 */
static void cydivert_reflect_event_notify(context_t context,
    LONGLONG timestamp, CYDIVERT_EVENT event)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    context_t waiter;
    const CYDIVERT_FILTER *filter;
    PVOID packet = NULL, process;
    ULONG packet_len = 0;
    UINT64 flags;
    BOOL match;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    process = (PVOID)context->process;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    entry = reflect_waiters.Flink;
    while (entry != &reflect_waiters)
    {
        waiter = CONTAINING_RECORD(entry, struct context_s, reflect.entry);
        entry = entry->Flink;
        KeAcquireInStackQueuedSpinLock(&waiter->lock, &lock_handle);
        filter = waiter->filter;
        flags  = waiter->flags;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        match = cydivert_filter(/*buffer=*/NULL,
            /*layer=*/CYDIVERT_LAYER_REFLECT, (PVOID)&context->reflect.data,
            timestamp, event, /*ipv4=*/TRUE, /*outbound=*/FALSE,
            /*loopback=*/FALSE, /*impostor=*/FALSE, /*frag_mode=*/FALSE,
            filter);
        if (!match)
        {
            continue;
        }
        if (packet == NULL)
        {
            packet = cydivert_reflect_packet(context, &packet_len);
        }
        (VOID)cydivert_queue_work(waiter, packet, packet_len,
            /*buffers=*/NULL, process, /*layer=*/CYDIVERT_LAYER_REFLECT,
            (PVOID)&context->reflect.data, event, flags, /*priority=*/0,
            /*ipv4=*/TRUE, /*outbound=*/FALSE, /*loopback=*/FALSE,
            /*impostor=*/FALSE, /*match=*/TRUE, timestamp);
    }
}

/*
 * Notify a new REFLECT layer context of all existing open handles.
 */
static void cydivert_reflect_established_notify(context_t context,
    LONGLONG timestamp)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    BOOL match, ok;
    context_t waiter;
    const CYDIVERT_FILTER *filter;
    PVOID packet, process;
    ULONG packet_len;
    UINT64 flags;

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    filter = context->filter;
    flags = context->flags;
    KeReleaseInStackQueuedSpinLock(&lock_handle);

    entry = reflect_contexts.Flink;
    while (entry != &reflect_contexts)
    {
        waiter = CONTAINING_RECORD(entry, struct context_s, reflect.entry);
        entry = entry->Flink;
        match = cydivert_filter(/*buffer=*/NULL,
            /*layer=*/CYDIVERT_LAYER_REFLECT, (PVOID)&waiter->reflect.data,
            timestamp, /*event=*/CYDIVERT_EVENT_REFLECT_OPEN, /*ipv4=*/TRUE,
            /*outbound=*/FALSE, /*loopback=*/FALSE, /*impostor=*/FALSE,
            /*frag_mode=*/FALSE, filter);
        if (!match)
        {
            continue;
        }
        packet = cydivert_reflect_packet(waiter, &packet_len);
        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        process = (PVOID)waiter->process;
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        ok = cydivert_queue_work(context, packet, packet_len,
            /*buffers=*/NULL, process, /*layer=*/CYDIVERT_LAYER_REFLECT,
            (PVOID)&waiter->reflect.data,
            /*event=*/CYDIVERT_EVENT_REFLECT_OPEN, flags, /*priority=*/0,
            /*ipv4=*/TRUE, /*outbound=*/FALSE, /*loopback=*/FALSE,
            /*impostor=*/FALSE, /*match=*/TRUE, timestamp);
        if (!ok)
        {
            break;
        }
    }

    KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
    if (context->state != CYDIVERT_CONTEXT_STATE_OPEN)
    {
        KeReleaseInStackQueuedSpinLock(&lock_handle);
        return;
    }
    // REFLECT layer shutdown is disabled until all previously open handles
    // have been queued.
    context->shutdown_recv_enabled = TRUE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
    cydivert_read_service(context);
}

/*
 * CyDivert REFLECT worker.
 */
void cydivert_reflect_worker(IN WDFWORKITEM item)
{
    KLOCK_QUEUE_HANDLE lock_handle;
    PLIST_ENTRY entry;
    context_t context;
    LONGLONG timestamp;
    CYDIVERT_EVENT event;
    reflect_event_t reflect_event;
    WDFOBJECT object;
    CYDIVERT_LAYER layer;

    UNREFERENCED_PARAMETER(item);

    // All reflection events are serialized and handled by this worker.
    // This ensures that we are always operating on a consistent "snapshot"
    // of the CyDivert handle state.  This worker also has exclusive control 
    // over reflect_contexts/reflect_waiters, so locking is not required.

    KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    while (!IsListEmpty(&reflect_event_queue))
    {
        entry = RemoveHeadList(&reflect_event_queue);
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        reflect_event = CONTAINING_RECORD(entry, struct reflect_event_s, entry);
        context       = reflect_event->context;
        event         = reflect_event->event;

        DEBUG("REFLECT: %s event for CyDivert context (context=%p)",
            (event == CYDIVERT_EVENT_REFLECT_OPEN? "open": "close"), context);

        KeAcquireInStackQueuedSpinLock(&context->lock, &lock_handle);
        object = (WDFOBJECT)context->object;
        layer = context->layer;
        KeReleaseInStackQueuedSpinLock(&lock_handle);

        timestamp = KeQueryPerformanceCounter(NULL).QuadPart;
        switch (event)
        {
            case CYDIVERT_EVENT_REFLECT_OPEN:
                if (layer != CYDIVERT_LAYER_REFLECT)
                {
                    InsertTailList(&reflect_contexts, &context->reflect.entry);
                }
                else
                {
                    InsertTailList(&reflect_waiters, &context->reflect.entry);
                    cydivert_reflect_established_notify(context, timestamp);
                }
                break;

            case CYDIVERT_EVENT_REFLECT_CLOSE:
                RemoveEntryList(&context->reflect.entry);
                break;
        }

        if (layer != CYDIVERT_LAYER_REFLECT)
        {
            cydivert_reflect_event_notify(context, timestamp, event);
        }
        if (event == CYDIVERT_EVENT_REFLECT_CLOSE)
        {
            WdfObjectDereference(object);
        }

        KeAcquireInStackQueuedSpinLock(&reflect_lock, &lock_handle);
    }
    reflect_worker_queued = FALSE;
    KeReleaseInStackQueuedSpinLock(&lock_handle);
}

/*
 * Log a driver event.
 */
static void cydivert_log_event(PEPROCESS process, PDRIVER_OBJECT driver,
    const wchar_t *msg_str)
{
    const wchar_t cydivert_str[] = CYDIVERT_DEVICE_NAME
        CYDIVERT_VERSION_LSTR;
    wchar_t pid_str[16];
    size_t cydivert_size = sizeof(cydivert_str), msg_size, pid_size = 0, size;
    UNICODE_STRING string;
    UINT8 *str;
    PIO_ERROR_LOG_PACKET packet;
    NTSTATUS status;

    size = ERROR_LOG_MAXIMUM_SIZE - sizeof(wchar_t) -
        (sizeof(IO_ERROR_LOG_PACKET) + cydivert_size + sizeof(pid_str));
    status = RtlStringCbLengthW(msg_str, size, &msg_size);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    msg_size += sizeof(wchar_t);

    if (process != NULL)
    {
        string.Length        = 0;
        string.MaximumLength = sizeof(pid_str);
        string.Buffer        = pid_str;
        status = RtlIntegerToUnicodeString(
            (UINT32)(ULONG_PTR)PsGetProcessId(process), 10, &string);
        pid_size = string.Length + sizeof(wchar_t);
    }
    if (process == NULL || !NT_SUCCESS(status))
    {
        pid_str[0] = pid_str[1] = pid_str[2] = L'?';
        pid_str[3] = L'\0';
        pid_size = 4 * sizeof(wchar_t);
    }

    size = sizeof(IO_ERROR_LOG_PACKET) + cydivert_size + msg_size + pid_size;
    if (size > ERROR_LOG_MAXIMUM_SIZE)
    {
        return;
    }
    packet = (PIO_ERROR_LOG_PACKET)IoAllocateErrorLogEntry(driver, (UCHAR)size);
    if (packet == NULL)
    {
        return;
    }
    RtlZeroMemory(packet, size);
    packet->NumberOfStrings = 3;
    packet->StringOffset    = sizeof(IO_ERROR_LOG_PACKET);
    packet->ErrorCode       = CYDIVERT_INFO_EVENT;
    str = (UINT8 *)packet + packet->StringOffset;
    RtlCopyMemory(str, cydivert_str, cydivert_size);
    str += cydivert_size;
    RtlCopyMemory(str, msg_str, msg_size);
    str += msg_size;
    RtlCopyMemory(str, pid_str, pid_size);

    IoWriteErrorLogEntry(packet);
}