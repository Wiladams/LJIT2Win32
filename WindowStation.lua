
local ffi = require ("ffi");
require ("WTypes");

ffi.cdef[[
BOOL WINAPI CloseWindowStation(
  _In_  HWINSTA hWinSta
);

HWINSTA WINAPI CreateWindowStation(
  _In_opt_  LPCTSTR lpwinsta,
  DWORD dwFlags,
  _In_      ACCESS_MASK dwDesiredAccess,
  _In_opt_  LPSECURITY_ATTRIBUTES lpsa
);

BOOL WINAPI EnumWindowStations(
  _In_  WINSTAENUMPROC lpEnumFunc,
  _In_  LPARAM lParam
);

HWINSTA WINAPI GetProcessWindowStation(void);

BOOL WINAPI GetUserObjectInformation(
  _In_       HANDLE hObj,
  _In_       int nIndex,
  _Out_opt_  PVOID pvInfo,
  _In_       DWORD nLength,
  _Out_opt_  LPDWORD lpnLengthNeeded
);

BOOL WINAPI GetUserObjectSecurity(
  _In_         HANDLE hObj,
  _In_         PSECURITY_INFORMATION pSIRequested,
  _Inout_opt_  PSECURITY_DESCRIPTOR pSD,
  _In_         DWORD nLength,
  _Out_        LPDWORD lpnLengthNeeded
);

HWINSTA WINAPI OpenWindowStation(
  _In_  LPTSTR lpszWinSta,
  _In_  BOOL fInherit,
  _In_  ACCESS_MASK dwDesiredAccess
);

BOOL WINAPI SetProcessWindowStation(
  _In_  HWINSTA hWinSta
);

BOOL WINAPI SetUserObjectInformation(
  _In_  HANDLE hObj,
  _In_  int nIndex,
  _In_  PVOID pvInfo,
  _In_  DWORD nLength
);

BOOL WINAPI SetUserObjectSecurity(
  _In_  HANDLE hObj,
  _In_  PSECURITY_INFORMATION pSIRequested,
  _In_  PSECURITY_DESCRIPTOR pSID
);
]]


