local ffi = require "ffi"
local bit = require "bit"
local band = bit.band
local bor = bit.bor
local rshift = bit.rshift
local lshift = bit.lshift



--[[
//
// The return value of COM functions and methods is an HRESULT.
// This is not a handle to anything, but is merely a 32-bit value
// with several fields encoded in the value. The parts of an
// HRESULT are shown below.
//
// Many of the macros and functions below were orginally defined to
// operate on SCODEs. SCODEs are no longer used. The macros are
// still present for compatibility and easy porting of Win16 code.
// Newly written code should use the HRESULT macros and functions.
//

//
//  HRESULTs are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +-+-+-+-+-+---------------------+-------------------------------+
//  |S|R|C|N|r|    Facility         |               Code            |
//  +-+-+-+-+-+---------------------+-------------------------------+
//
//  where
//
//      S - Severity - indicates success/fail
//
//          0 - Success
//          1 - Fail (COERROR)
//
//      R - reserved portion of the facility code, corresponds to NT's
//              second severity bit.
//
//      C - reserved portion of the facility code, corresponds to NT's
//              C field.
//
//      N - reserved portion of the facility code. Used to indicate a
//              mapped NT status value.
//
//      r - reserved portion of the facility code. Reserved for internal
//              use. Used to indicate HRESULT values that are not status
//              values, but are instead message ids for display strings.
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
--]]

--
-- Define the facility codes
--
FACILITY_XPS                     = 82
FACILITY_WINRM                   = 51
FACILITY_WINDOWSUPDATE           = 36
FACILITY_WINDOWS_DEFENDER        = 80
FACILITY_WINDOWS_CE              = 24
FACILITY_WINDOWS                 = 8
FACILITY_USERMODE_VOLMGR         = 56
FACILITY_USERMODE_VIRTUALIZATION = 55
FACILITY_USERMODE_VHD            = 58
FACILITY_URT                     = 19
FACILITY_UMI                     = 22
FACILITY_UI                      = 42
FACILITY_TPM_SOFTWARE            = 41
FACILITY_TPM_SERVICES            = 40
FACILITY_SXS                     = 23
FACILITY_STORAGE                 = 3
FACILITY_STATE_MANAGEMENT        = 34
FACILITY_SSPI                    = 9
FACILITY_SCARD                   = 16
FACILITY_SHELL                   = 39
FACILITY_SETUPAPI                = 15
FACILITY_SECURITY                = 9
FACILITY_SDIAG                   = 60
FACILITY_RPC                     = 1
FACILITY_RAS                     = 83
FACILITY_PLA                     = 48
FACILITY_OPC                     = 81
FACILITY_WIN32                   = 7
FACILITY_CONTROL                 = 10
FACILITY_WEBSERVICES             = 61
FACILITY_NULL                    = 0
FACILITY_NDIS                    = 52
FACILITY_METADIRECTORY           = 35
FACILITY_MSMQ                    = 14
FACILITY_MEDIASERVER             = 13
FACILITY_MBN                     = 84
FACILITY_INTERNET                = 12
FACILITY_ITF                     = 4
FACILITY_USERMODE_HYPERVISOR     = 53
FACILITY_HTTP                    = 25
FACILITY_GRAPHICS                = 38
FACILITY_FWP                     = 50
FACILITY_FVE                     = 49
FACILITY_USERMODE_FILTER_MANAGER = 31
FACILITY_DPLAY                   = 21
FACILITY_DISPATCH                = 2
FACILITY_DIRECTORYSERVICE        = 37
FACILITY_CONFIGURATION           = 33
FACILITY_COMPLUS                 = 17
FACILITY_USERMODE_COMMONLOG      = 26
FACILITY_CMI                     = 54
FACILITY_CERT                    = 11
FACILITY_BCD                     = 57
FACILITY_BACKGROUNDCOPY          = 32
FACILITY_ACS                     = 20
FACILITY_AAF                     = 18


--
-- MessageId: ERROR_SUCCESS
--
-- MessageText:
--
-- The operation completed successfully.
--
ERROR_SUCCESS	= 0

NO_ERROR		= 0
SEC_E_OK		= 0x00000000

-- for KINECT

ERROR_DEVICE_NOT_CONNECTED			= 1167
ERROR_NOT_READY						= 21
ERROR_ALREADY_INITIALIZED			= 1247
ERROR_NO_MORE_ITEMS					= 259

E_POINTER							= (0x80004003)	-- Invalid pointer

--[[
#define ERROR_INVALID_FUNCTION           1L    // dderror
#define ERROR_FILE_NOT_FOUND             2L
#define ERROR_PATH_NOT_FOUND             3L
#define ERROR_TOO_MANY_OPEN_FILES        4L
#define ERROR_ACCESS_DENIED              5L
#define ERROR_INVALID_HANDLE             6L
#define ERROR_ARENA_TRASHED              7L
#define ERROR_NOT_ENOUGH_MEMORY          8L    // dderror
#define ERROR_INVALID_BLOCK              9L
#define ERROR_BAD_ENVIRONMENT            10L
#define ERROR_BAD_FORMAT                 11L
#define ERROR_INVALID_ACCESS             12L
#define ERROR_INVALID_DATA               13L
#define ERROR_OUTOFMEMORY                14L
#define ERROR_INVALID_DRIVE              15L
#define ERROR_CURRENT_DIRECTORY          16L
#define ERROR_NOT_SAME_DEVICE            17L
#define ERROR_NO_MORE_FILES              18L
#define ERROR_WRITE_PROTECT              19L
#define ERROR_BAD_UNIT                   20L
#define ERROR_NOT_READY                  21L
#define ERROR_BAD_COMMAND                22L
#define ERROR_CRC                        23L
#define ERROR_BAD_LENGTH                 24L
#define ERROR_SEEK                       25L
#define ERROR_NOT_DOS_DISK               26L
#define ERROR_SECTOR_NOT_FOUND           27L
#define ERROR_OUT_OF_PAPER               28L
#define ERROR_WRITE_FAULT                29L
#define ERROR_READ_FAULT                 30L
#define ERROR_GEN_FAILURE                31L
#define ERROR_SHARING_VIOLATION          32L
#define ERROR_LOCK_VIOLATION             33L
#define ERROR_WRONG_DISK                 34L
#define ERROR_SHARING_BUFFER_EXCEEDED    36L
#define ERROR_HANDLE_EOF                 38L
#define ERROR_HANDLE_DISK_FULL           39L
#define ERROR_NOT_SUPPORTED              50L
#define ERROR_REM_NOT_LIST               51L
#define ERROR_DUP_NAME                   52L
#define ERROR_BAD_NETPATH                53L
#define ERROR_NETWORK_BUSY               54L
#define ERROR_DEV_NOT_EXIST              55L    // dderror
#define ERROR_TOO_MANY_CMDS              56L
#define ERROR_ADAP_HDW_ERR               57L
#define ERROR_BAD_NET_RESP               58L
#define ERROR_UNEXP_NET_ERR              59L
#define ERROR_BAD_REM_ADAP               60L
#define ERROR_PRINTQ_FULL                61L
#define ERROR_NO_SPOOL_SPACE             62L
#define ERROR_PRINT_CANCELLED            63L
#define ERROR_NETNAME_DELETED            64L
#define ERROR_NETWORK_ACCESS_DENIED      65L
#define ERROR_BAD_DEV_TYPE               66L
#define ERROR_BAD_NET_NAME               67L
#define ERROR_TOO_MANY_NAMES             68L
#define ERROR_TOO_MANY_SESS              69L
#define ERROR_SHARING_PAUSED             70L
#define ERROR_REQ_NOT_ACCEP              71L
#define ERROR_REDIR_PAUSED               72L
#define ERROR_FILE_EXISTS                80L
#define ERROR_CANNOT_MAKE                82L
#define ERROR_FAIL_I24                   83L
#define ERROR_OUT_OF_STRUCTURES          84L
#define ERROR_ALREADY_ASSIGNED           85L
#define ERROR_INVALID_PASSWORD           86L
#define ERROR_INVALID_PARAMETER          87L    // dderror
#define ERROR_NET_WRITE_FAULT            88L
#define ERROR_NO_PROC_SLOTS              89L
#define ERROR_TOO_MANY_SEMAPHORES        100L
#define ERROR_EXCL_SEM_ALREADY_OWNED     101L
--]]















--
-- Severity values
--

SEVERITY_SUCCESS    = 0
SEVERITY_ERROR      = 1

--
-- Generic test for success on any status value (non-negative numbers
-- indicate success).
--

function SUCCEEDED(hr)
	return hr >= 0
end

--
-- and the inverse
--

function FAILED(hr)
	return hr < 0
end


--
-- Generic test for error on any status value.
--

function IS_ERROR(Status)
	return rshift(Status, 31) == SEVERITY_ERROR
end

--
-- Return the code
--

function HRESULT_CODE(hr)
	return band(hr, 0xFFFF)
end

--
--  Return the facility
--

function HRESULT_FACILITY(hr)
	return band(rshift(hr, 16), 0x1fff)
end

--
--  Return the severity
--

function HRESULT_SEVERITY(hr)
	return band(rshift(hr, 31), 0x1)
end

function HRESULT_PARTS(hr)
	return HRESULT_SEVERITY(hr), HRESULT_FACILITY(hr), HRESULT_CODE(hr)
end

--
-- Create an HRESULT value from component pieces
--

function MAKE_HRESULT(severity,facility,code)
    return bor(lshift(severity,31) , lshift(facility,16) , code)
end


--
-- HRESULT_FROM_WIN32(x) used to be a macro, however we now run it as an inline function
-- to prevent double evaluation of 'x'. If you still need the macro, you can use __HRESULT_FROM_WIN32(x)
--
function __HRESULT_FROM_WIN32(x)
	if x <= 0 then
		return x
	end

	return bor(band(x, 0x0000FFFF), lshift(FACILITY_WIN32, 16), 0x80000000)
end

