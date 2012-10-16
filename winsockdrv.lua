
local ffi = require "ffi"
local bit = require "bit"
local lshift = bit.lshift
local rshift = bit.rshift

require "win_socket"
local WSock = require "WinSock_Utils"
require "winapi"

-- From NTDDK.h, and Wdm.h
--[[
	Reference:
http://www.virtualbox.org/svn/vbox/trunk/src/VBox/Additions/WINNT/Graphics/Wine/include/winioctl.h
--]]

FILE_DEVICE_NETWORK             = 0x00000012;

METHOD_BUFFERED                 = 0;
METHOD_IN_DIRECT                = 1;
METHOD_OUT_DIRECT               = 2;
METHOD_NEITHER                  = 3;

SIO_BASE_HANDLE = 0x48000022;

-- TDI Definitions that are in the Windows DDK

TDI_RECEIVE_BROADCAST           = 0x00000004;
TDI_RECEIVE_MULTICAST           = 0x00000008;
TDI_RECEIVE_PARTIAL             = 0x00000010;
TDI_RECEIVE_NORMAL              = 0x00000020;
TDI_RECEIVE_EXPEDITED           = 0x00000040;
TDI_RECEIVE_PEEK                = 0x00000080;
TDI_RECEIVE_NO_RESPONSE_EXP     = 0x00000100;
TDI_RECEIVE_COPY_LOOKAHEAD      = 0x00000200;
TDI_RECEIVE_ENTIRE_MESSAGE      = 0x00000400;
TDI_RECEIVE_AT_DISPATCH_LEVEL   = 0x00000800;
TDI_RECEIVE_CONTROL_INFO        = 0x00001000;
TDI_RECEIVE_FORCE_INDICATION    = 0x00002000;
TDI_RECEIVE_NO_PUSH             = 0x00004000;
  
--[[
 * The "Auxiliary Function Driver" is the windows kernel-mode driver that does
 * TCP, UDP etc. Winsock is just a layer that dispatches requests to it.
 * Having these definitions allows us to bypass winsock and make an AFD kernel
 * call directly, avoiding a bug in winsock's recvfrom implementation.
--]]

AFD_NO_FAST_IO   = 0x00000001;
AFD_OVERLAPPED   = 0x00000002;
AFD_IMMEDIATE    = 0x00000004;

 AFD_POLL_RECEIVE_BIT            = 0;
 AFD_POLL_RECEIVE                (1 << AFD_POLL_RECEIVE_BIT)
 AFD_POLL_RECEIVE_EXPEDITED_BIT  = 1;
 AFD_POLL_RECEIVE_EXPEDITED      (1 << AFD_POLL_RECEIVE_EXPEDITED_BIT)
 AFD_POLL_SEND_BIT               = 2;
 AFD_POLL_SEND                   (1 << AFD_POLL_SEND_BIT)
 AFD_POLL_DISCONNECT_BIT         = 3;
 AFD_POLL_DISCONNECT             (1 << AFD_POLL_DISCONNECT_BIT)
 AFD_POLL_ABORT_BIT              = 4;
 AFD_POLL_ABORT                  (1 << AFD_POLL_ABORT_BIT)
 AFD_POLL_LOCAL_CLOSE_BIT        = 5;
 AFD_POLL_LOCAL_CLOSE            (1 << AFD_POLL_LOCAL_CLOSE_BIT)
 AFD_POLL_CONNECT_BIT            = 6;
 AFD_POLL_CONNECT                (1 << AFD_POLL_CONNECT_BIT)
 AFD_POLL_ACCEPT_BIT             = 7;
 AFD_POLL_ACCEPT                 (1 << AFD_POLL_ACCEPT_BIT)
 AFD_POLL_CONNECT_FAIL_BIT       = 8;
 AFD_POLL_CONNECT_FAIL           (1 << AFD_POLL_CONNECT_FAIL_BIT)
 AFD_POLL_QOS_BIT                = 9;
 AFD_POLL_QOS                    (1 << AFD_POLL_QOS_BIT)
 AFD_POLL_GROUP_QOS_BIT          = 10;
 AFD_POLL_GROUP_QOS              (1 << AFD_POLL_GROUP_QOS_BIT)

 AFD_NUM_POLL_EVENTS             = 11;
 AFD_POLL_ALL                    ((1 << AFD_NUM_POLL_EVENTS) - 1)

ffi.cdef[[
typedef struct _AFD_RECV_DATAGRAM_INFO {
    LPWSABUF BufferArray;
    ULONG BufferCount;
    ULONG AfdFlags;
    ULONG TdiFlags;
    struct sockaddr* Address;
    int* AddressLength;
} AFD_RECV_DATAGRAM_INFO, *PAFD_RECV_DATAGRAM_INFO;

typedef struct _AFD_RECV_INFO {
    LPWSABUF BufferArray;
    ULONG BufferCount;
    ULONG AfdFlags;
    ULONG TdiFlags;
} AFD_RECV_INFO, *PAFD_RECV_INFO;
]]


local FSCTL_AFD_BASE = FILE_DEVICE_NETWORK;

local _AFD_CONTROL_CODE = function(operation, method)
    return ((FSCTL_AFD_BASE) << 12 | (operation << 2) | method)
end


AFD_RECEIVE            = 5;
AFD_RECEIVE_DATAGRAM   = 6;
AFD_POLL               = 9;

IOCTL_AFD_RECEIVE = _AFD_CONTROL_CODE(AFD_RECEIVE, METHOD_NEITHER);
IOCTL_AFD_RECEIVE_DATAGRAM = _AFD_CONTROL_CODE(AFD_RECEIVE_DATAGRAM, METHOD_NEITHER);
IOCTL_AFD_POLL = _AFD_CONTROL_CODE(AFD_POLL, METHOD_BUFFERED);

--[[
#if defined(__MINGW32__) && !defined(__MINGW64_VERSION_MAJOR)
typedef struct _IP_ADAPTER_UNICAST_ADDRESS_XP {
  /* FIXME: __C89_NAMELESS was removed */
  /* __C89_NAMELESS */ union {
    ULONGLONG Alignment;
    /* __C89_NAMELESS */ struct {
      ULONG Length;
      DWORD Flags;
    };
  };
  struct _IP_ADAPTER_UNICAST_ADDRESS_XP *Next;
  SOCKET_ADDRESS Address;
  IP_PREFIX_ORIGIN PrefixOrigin;
  IP_SUFFIX_ORIGIN SuffixOrigin;
  IP_DAD_STATE DadState;
  ULONG ValidLifetime;
  ULONG PreferredLifetime;
  ULONG LeaseLifetime;
} IP_ADAPTER_UNICAST_ADDRESS_XP,*PIP_ADAPTER_UNICAST_ADDRESS_XP;

#endif
--]]






#include "uv.h"
#include "internal.h"


-- Whether ipv6 is supported
local uv_allow_ipv6;

-- Whether there are any non-IFS LSPs stacked on TCP
local uv_tcp_non_ifs_lsp_ipv4;
local uv_tcp_non_ifs_lsp_ipv6;


-- Ip address used to bind to any port at any interface
uv_addr_ip4_any_ = sockaddr_in();	-- struct sockaddr_in 
uv_addr_ip6_any_ = sockaddr_in6();	-- struct sockaddr_in6 


local uv_get_acceptex_function(socket) 
	local res, err = WinSock.GetExtensionFunction(socket, WSAID_ACCEPTEX);
	if not res then
		return false, err
	end
	
	return ffi.cast("LPFN_ACCEPTEX*", res);
end


local uv_get_connectex_function(socket) 
	local res, err = uv_get_extension_function(socket, WSAID_CONNECTEX);

	if not res then
		return false, err
	end

	return ffi.cast("LPFN_CONNECTEX*", res)
end


void uv_winsock_init() {
  const GUID wsaid_connectex            = WSAID_CONNECTEX;
  const GUID wsaid_acceptex             = WSAID_ACCEPTEX;
  const GUID wsaid_getacceptexsockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
  const GUID wsaid_disconnectex         = WSAID_DISCONNECTEX;
  const GUID wsaid_transmitfile         = WSAID_TRANSMITFILE;

  WSADATA wsa_data;
  int errorno;
  SOCKET dummy;
  WSAPROTOCOL_INFOW protocol_info;
  int opt_len;

  /* Initialize winsock */
  errorno = WSAStartup(MAKEWORD(2, 2), &wsa_data);
  if (errorno != 0) {
    uv_fatal_error(errorno, "WSAStartup");
  }

  /* Set implicit binding address used by connectEx */
  uv_addr_ip4_any_ = uv_ip4_addr("0.0.0.0", 0);
  uv_addr_ip6_any_ = uv_ip6_addr("::", 0);

  /* Detect non-IFS LSPs */
  dummy = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (dummy == INVALID_SOCKET) {
    uv_fatal_error(WSAGetLastError(), "socket");
  }

  opt_len = (int) sizeof protocol_info;
  if (!getsockopt(dummy,
                  SOL_SOCKET,
                  SO_PROTOCOL_INFOW,
                  (char*) &protocol_info,
                  &opt_len) == SOCKET_ERROR) {
    uv_fatal_error(WSAGetLastError(), "socket");
  }

  if (!(protocol_info.dwServiceFlags1 & XP1_IFS_HANDLES)) {
    uv_tcp_non_ifs_lsp_ipv4 = true;
  }

  if (closesocket(dummy) == SOCKET_ERROR) {
    uv_fatal_error(WSAGetLastError(), "closesocket");
  }

  /* Detect IPV6 support and non-IFS LSPs */
  dummy = socket(AF_INET6, SOCK_STREAM, IPPROTO_IP);
  if (dummy != INVALID_SOCKET) {
    uv_allow_ipv6 = true;

    opt_len = (int) sizeof protocol_info;
    if (!getsockopt(dummy,
                    SOL_SOCKET,
                    SO_PROTOCOL_INFOW,
                    (char*) &protocol_info,
                    &opt_len) == SOCKET_ERROR) {
      uv_fatal_error(WSAGetLastError(), "socket");
    }

    if (!(protocol_info.dwServiceFlags1 & XP1_IFS_HANDLES)) {
      uv_tcp_non_ifs_lsp_ipv6 = true;
    }

    if (closesocket(dummy) == SOCKET_ERROR) {
      uv_fatal_error(WSAGetLastError(), "closesocket");
    }
  }
}

local status_to_error = {
    STATUS_SUCCESS = ERROR_SUCCESS;
    STATUS_PENDING = ERROR_IO_PENDING;

    STATUS_INVALID_HANDLE = WSAENOTSOCK;
    STATUS_OBJECT_TYPE_MISMATCH = WSAENOTSOCK;

    STATUS_INSUFFICIENT_RESOURCES = WSAENOBUFS;
    STATUS_PAGEFILE_QUOTA = WSAENOBUFS;
    STATUS_COMMITMENT_LIMIT = WSAENOBUFS;
    STATUS_WORKING_SET_QUOTA = WSAENOBUFS;
    STATUS_NO_MEMORY = WSAENOBUFS;
    STATUS_CONFLICTING_ADDRESSES = WSAENOBUFS;
    STATUS_QUOTA_EXCEEDED = WSAENOBUFS;
    STATUS_TOO_MANY_PAGING_FILES = WSAENOBUFS;
    STATUS_REMOTE_RESOURCES = WSAENOBUFS;
    STATUS_TOO_MANY_ADDRESSES = WSAENOBUFS;

    STATUS_SHARING_VIOLATION = WSAEADDRINUSE;
    STATUS_ADDRESS_ALREADY_EXISTS = WSAEADDRINUSE;

    STATUS_LINK_TIMEOUT = WSAETIMEDOUT;
    STATUS_IO_TIMEOUT = WSAETIMEDOUT;
    STATUS_TIMEOUT = WSAETIMEDOUT;

    STATUS_GRACEFUL_DISCONNECT = WSAEDISCON;

    STATUS_REMOTE_DISCONNECT = WSAECONNRESET;
    STATUS_CONNECTION_RESET = WSAECONNRESET;
    STATUS_LINK_FAILED = WSAECONNRESET;
    STATUS_CONNECTION_DISCONNECTED = WSAECONNRESET;
    STATUS_PORT_UNREACHABLE = WSAECONNRESET;
    STATUS_HOPLIMIT_EXCEEDED = WSAECONNRESET;

    STATUS_LOCAL_DISCONNECT = WSAECONNABORTED;
    STATUS_TRANSACTION_ABORTED = WSAECONNABORTED;
    STATUS_CONNECTION_ABORTED = WSAECONNABORTED;

    STATUS_BAD_NETWORK_PATH = WSAENETUNREACH;
    STATUS_NETWORK_UNREACHABLE = WSAENETUNREACH;
    STATUS_PROTOCOL_UNREACHABLE = WSAENETUNREACH;

    STATUS_HOST_UNREACHABLE = WSAEHOSTUNREACH;
 
    STATUS_CANCELLED = WSAEINTR;
    STATUS_REQUEST_ABORTED = WSAEINTR;

    STATUS_BUFFER_OVERFLOW = WSAEMSGSIZE;
    STATUS_INVALID_BUFFER_SIZE = WSAEMSGSIZE;

    STATUS_BUFFER_TOO_SMALL = WSAEFAULT;
    STATUS_ACCESS_VIOLATION = WSAEFAULT;

    STATUS_DEVICE_NOT_READY = WSAEWOULDBLOCK;
    STATUS_REQUEST_NOT_ACCEPTED = WSAEWOULDBLOCK;

    STATUS_INVALID_NETWORK_RESPONSE = WSAENETDOWN;
    STATUS_NETWORK_BUSY = WSAENETDOWN;
    STATUS_NO_SUCH_DEVICE = WSAENETDOWN;
    STATUS_NO_SUCH_FILE = WSAENETDOWN;
    STATUS_OBJECT_PATH_NOT_FOUND = WSAENETDOWN;
    STATUS_OBJECT_NAME_NOT_FOUND = WSAENETDOWN;
    STATUS_UNEXPECTED_NETWORK_ERROR = WSAENETDOWN;

    STATUS_INVALID_CONNECTION = WSAENOTCONN;

    STATUS_REMOTE_NOT_LISTENING = WSAECONNREFUSED;
    STATUS_CONNECTION_REFUSED = WSAECONNREFUSED;

    STATUS_PIPE_DISCONNECTED = WSAESHUTDOWN;
      
    STATUS_INVALID_ADDRESS = WSAEADDRNOTAVAIL;
    STATUS_INVALID_ADDRESS_COMPONENT = WSAEADDRNOTAVAIL;
      
    STATUS_NOT_SUPPORTED = WSAEOPNOTSUPP;
    STATUS_NOT_IMPLEMENTED = WSAEOPNOTSUPP;
      
    STATUS_ACCESS_DENIED = WSAEACCES;
}

uv_ntstatus_to_winsock_error = function(status) 

	local err = status_to_error[status]
	if err then
		return err
	end 

    if ((status & (FACILITY_NTWIN32 << 16)) == (FACILITY_NTWIN32 << 16) and
          (status & (ERROR_SEVERITY_ERROR | ERROR_SEVERITY_WARNING))) then 
	
        -- It's a windows error that has been previously mapped to an
        -- ntstatus code.
        return (DWORD) (status & 0xffff);
    else
        -- The default fallback for unmappable ntstatus codes.
        return WSAEINVAL;
    end
end


--[[
  This function provides a workaround for a bug in the winsock implementation
  of WSARecv. The problem is that when SetFileCompletionNotificationModes is
  used to avoid IOCP notifications of completed reads, WSARecv does not
  reliably indicate whether we can expect a completion package to be posted
  when the receive buffer is smaller than the received datagram.
 
  However it is desirable to use SetFileCompletionNotificationModes because
  it yields a massive performance increase.
 
  This function provides a workaround for that bug, but it only works for the
  specific case that we need it for. E.g. it assumes that the "avoid iocp"
  bit has been set, and supports only overlapped operation. It also requires
  the user to use the default msafd driver, doesn't work when other LSPs are
  stacked on top of it.
--]]
int WSAAPI uv_wsarecv_workaround(SOCKET socket, WSABUF* buffers,
    DWORD buffer_count, DWORD* bytes, DWORD* flags, WSAOVERLAPPED *overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
  NTSTATUS status;
  void* apc_context;
  IO_STATUS_BLOCK* iosb = (IO_STATUS_BLOCK*) &overlapped->Internal;
  AFD_RECV_INFO info;
  DWORD error;

  if (overlapped == NULL || completion_routine != NULL) {
    WSASetLastError(WSAEINVAL);
    return SOCKET_ERROR;
  }

  info.BufferArray = buffers;
  info.BufferCount = buffer_count;
  info.AfdFlags = AFD_OVERLAPPED;
  info.TdiFlags = TDI_RECEIVE_NORMAL;

  if (*flags & MSG_PEEK) {
    info.TdiFlags |= TDI_RECEIVE_PEEK;
  }

  if (*flags & MSG_PARTIAL) {
    info.TdiFlags |= TDI_RECEIVE_PARTIAL;
  }

  if (!((intptr_t) overlapped->hEvent & 1)) {
    apc_context = (void*) overlapped;
  } else {
    apc_context = NULL;
  }

  iosb->Status = STATUS_PENDING;
  iosb->Pointer = 0;

  status = pNtDeviceIoControlFile((HANDLE) socket,
                                  overlapped->hEvent,
                                  NULL,
                                  apc_context,
                                  iosb,
                                  IOCTL_AFD_RECEIVE,
                                  &info,
                                  sizeof(info),
                                  NULL,
                                  0);

  *flags = 0;
  *bytes = (DWORD) iosb->Information;

  switch (status) {
    case STATUS_SUCCESS:
      error = ERROR_SUCCESS;
      break;

    case STATUS_PENDING:
      error = WSA_IO_PENDING;
      break;

    case STATUS_BUFFER_OVERFLOW:
      error = WSAEMSGSIZE;
      break;

    case STATUS_RECEIVE_EXPEDITED:
      error = ERROR_SUCCESS;
      *flags = MSG_OOB;
      break;

    case STATUS_RECEIVE_PARTIAL_EXPEDITED:
      error = ERROR_SUCCESS;
      *flags = MSG_PARTIAL | MSG_OOB;
      break;

    case STATUS_RECEIVE_PARTIAL:
      error = ERROR_SUCCESS;
      *flags = MSG_PARTIAL;
      break;

    default:
      error = uv_ntstatus_to_winsock_error(status);
      break;
  }

  WSASetLastError(error);

  if (error == ERROR_SUCCESS) {
    return 0;
  } else {
    return SOCKET_ERROR;
  }
}


--[[
 See description of uv_wsarecv_workaround.
--]]
int  uv_wsarecvfrom_workaround(SOCKET socket, WSABUF* buffers,
    DWORD buffer_count, DWORD* bytes, DWORD* flags, struct sockaddr* addr,
    int* addr_len, WSAOVERLAPPED *overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
  NTSTATUS status;
  void* apc_context;
  IO_STATUS_BLOCK* iosb = (IO_STATUS_BLOCK*) &overlapped->Internal;
  AFD_RECV_DATAGRAM_INFO info;
  DWORD error;

  if (overlapped == NULL || addr == NULL || addr_len == NULL ||
      completion_routine != NULL) {
    WSASetLastError(WSAEINVAL);
    return SOCKET_ERROR;
  }

  info.BufferArray = buffers;
  info.BufferCount = buffer_count;
  info.AfdFlags = AFD_OVERLAPPED;
  info.TdiFlags = TDI_RECEIVE_NORMAL;
  info.Address = addr;
  info.AddressLength = addr_len;

  if (*flags & MSG_PEEK) {
    info.TdiFlags |= TDI_RECEIVE_PEEK;
  }

  if (*flags & MSG_PARTIAL) {
    info.TdiFlags |= TDI_RECEIVE_PARTIAL;
  }

  if (!((intptr_t) overlapped->hEvent & 1)) {
    apc_context = (void*) overlapped;
  } else {
    apc_context = NULL;
  }

  iosb->Status = STATUS_PENDING;
  iosb->Pointer = 0;

  status = pNtDeviceIoControlFile((HANDLE) socket,
                                  overlapped->hEvent,
                                  NULL,
                                  apc_context,
                                  iosb,
                                  IOCTL_AFD_RECEIVE_DATAGRAM,
                                  &info,
                                  sizeof(info),
                                  NULL,
                                  0);

  *flags = 0;
  *bytes = (DWORD) iosb->Information;

  switch (status) {
    case STATUS_SUCCESS:
      error = ERROR_SUCCESS;
      break;

    case STATUS_PENDING:
      error = WSA_IO_PENDING;
      break;

    case STATUS_BUFFER_OVERFLOW:
      error = WSAEMSGSIZE;
      break;

    case STATUS_RECEIVE_EXPEDITED:
      error = ERROR_SUCCESS;
      *flags = MSG_OOB;
      break;

    case STATUS_RECEIVE_PARTIAL_EXPEDITED:
      error = ERROR_SUCCESS;
      *flags = MSG_PARTIAL | MSG_OOB;
      break;

    case STATUS_RECEIVE_PARTIAL:
      error = ERROR_SUCCESS;
      *flags = MSG_PARTIAL;
      break;

    default:
      error = uv_ntstatus_to_winsock_error(status);
      break;
  }

  WSASetLastError(error);

  if (error == ERROR_SUCCESS) {
    return 0;
  } else {
    return SOCKET_ERROR;
  }
}


int WSAAPI uv_msafd_poll(SOCKET socket, AFD_POLL_INFO* info,
    OVERLAPPED* overlapped) {
  IO_STATUS_BLOCK iosb;
  IO_STATUS_BLOCK* iosb_ptr;
  HANDLE event = NULL;
  void* apc_context;
  NTSTATUS status;
  DWORD error;

  if (overlapped != NULL) {
    /* Overlapped operation. */
    iosb_ptr = (IO_STATUS_BLOCK*) &overlapped->Internal;
    event = overlapped->hEvent;

    /* Do not report iocp completion if hEvent is tagged. */
    if ((uintptr_t) event & 1) {
      event = (HANDLE)((uintptr_t) event & ~(uintptr_t) 1);
      apc_context = NULL;
    } else {
      apc_context = overlapped;
    }

  } else {
    /* Blocking operation. */
    iosb_ptr = &iosb;
    event = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (event == NULL) {
      return SOCKET_ERROR;
    }
    apc_context = NULL;
  }

  iosb_ptr->Status = STATUS_PENDING;
  status = pNtDeviceIoControlFile((HANDLE) socket,
                                  event,
                                  NULL,
                                  apc_context,
                                  iosb_ptr,
                                  IOCTL_AFD_POLL,
                                  info,
                                  sizeof *info,
                                  info,
                                  sizeof *info);

  if (overlapped == NULL) {
    /* If this is a blocking operation, wait for the event to become */
    /* signaled, and then grab the real status from the io status block. */
    if (status == STATUS_PENDING) {
      DWORD r = WaitForSingleObject(event, INFINITE);

      if (r == WAIT_FAILED) {
        DWORD saved_error = GetLastError();
        CloseHandle(event);
        WSASetLastError(saved_error);
        return SOCKET_ERROR;
      }

      status = iosb.Status;
    }

    CloseHandle(event);
  }

  switch (status) {
    case STATUS_SUCCESS:
      error = ERROR_SUCCESS;
      break;

    case STATUS_PENDING:
      error = WSA_IO_PENDING;
      break;

    default:
      error = uv_ntstatus_to_winsock_error(status);
      break;
  }

  WSASetLastError(error);

  if (error == ERROR_SUCCESS) {
    return 0;
  } else {
    return SOCKET_ERROR;
  }
}

