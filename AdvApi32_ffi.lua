
local ffi = require ("ffi");
require ("WTypes");

ffi.cdef[[
typedef struct _SID_IDENTIFIER_AUTHORITY {
  BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;
]]

ffi.cdef[[
BOOL  AllocateAndInitializeSid(
     PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
     BYTE nSubAuthorityCount,
     DWORD dwSubAuthority0,
     DWORD dwSubAuthority1,
     DWORD dwSubAuthority2,
     DWORD dwSubAuthority3,
     DWORD dwSubAuthority4,
     DWORD dwSubAuthority5,
     DWORD dwSubAuthority6,
     DWORD dwSubAuthority7,
   PSID *pSid
);

BOOL ConvertSidToStringSid(PSID Sid, LPTSTR *StringSid);

BOOL  ConvertStringSidToSid(LPCTSTR StringSid, PSID *Sid);

BOOL  CopySid(DWORD nDestinationSidLength, PSID pDestinationSid, PSID pSourceSid);

BOOL  EqualSid(PSID pSid1, PSID pSid2);

PVOID  FreeSid(PSID pSid);

DWORD  GetLengthSid(PSID pSid);

PSID_IDENTIFIER_AUTHORITY  GetSidIdentifierAuthority(PSID pSid);

DWORD  GetSidLengthRequired(UCHAR nSubAuthorityCount);

PDWORD  GetSidSubAuthority(PSID pSid, DWORD nSubAuthority);

PUCHAR  GetSidSubAuthorityCount(PSID pSid);

BOOL  InitializeSid(PSID Sid, PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority, BYTE nSubAuthorityCount);

BOOL  IsValidSid(PSID pSid);

BOOL  LookupAccountName(LPCTSTR lpSystemName,
    LPCTSTR lpAccountName,
    PSID Sid,
    LPDWORD cbSid,
    LPTSTR ReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse);

BOOL  LookupAccountSid(LPCTSTR lpSystemName,
    PSID lpSid,
    LPTSTR lpName,
    LPDWORD cchName,
    LPTSTR lpReferencedDomainName,
    LPDWORD cchReferencedDomainName,
    PSID_NAME_USE peUse);
]]
