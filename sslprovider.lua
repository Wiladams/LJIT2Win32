

--#include <wincrypt.h>

local ffi = require "ffi"
local bit = require "bit"
local band = bit.band

local k32 = require "Kernel32"
require "ncrypt"
require "WinCrypt"

local L = k32.AnsiToUnicode16

local NCLib = ffi.load("ncrypt.dll")


-- Microsoft built-in providers.

SSL = {
	Lib = NCLib;

MS_SCHANNEL_PROVIDER           = L"Microsoft SSL Protocol Provider";


NCRYPT_SSL_CLIENT_FLAG  = 0x00000001;
NCRYPT_SSL_SERVER_FLAG  = 0x00000002;



-- SSL Protocols and Cipher Suites

-- Protocols
SSL2_PROTOCOL_VERSION       = 0x0002;
SSL3_PROTOCOL_VERSION       = 0x0300;
TLS1_PROTOCOL_VERSION       = 0x0301;

TLS1_0_PROTOCOL_VERSION     = 0x0301;
TLS1_1_PROTOCOL_VERSION     = 0x0302;
TLS1_2_PROTOCOL_VERSION     = 0x0303;

-- Cipher suites
TLS_RSA_WITH_NULL_MD5                       = 0x0001;
TLS_RSA_WITH_NULL_SHA                       = 0x0002;
TLS_RSA_EXPORT_WITH_RC4_40_MD5              = 0x0003;
TLS_RSA_WITH_RC4_128_MD5                    = 0x0004;
TLS_RSA_WITH_RC4_128_SHA                    = 0x0005;
TLS_RSA_WITH_DES_CBC_SHA                    = 0x0009;
TLS_RSA_WITH_3DES_EDE_CBC_SHA               = 0x000A;
TLS_DHE_DSS_WITH_DES_CBC_SHA                = 0x0012;
TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA           = 0x0013;
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA           = 0x0016;
TLS_RSA_WITH_AES_128_CBC_SHA                = 0x002F;
TLS_DHE_DSS_WITH_AES_128_CBC_SHA            = 0x0032;
TLS_DHE_RSA_WITH_AES_128_CBC_SHA            = 0x0033;
TLS_RSA_WITH_AES_256_CBC_SHA                = 0x0035;
TLS_DHE_DSS_WITH_AES_256_CBC_SHA            = 0x0038;
TLS_DHE_RSA_WITH_AES_256_CBC_SHA            = 0x0039;
TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA         = 0x0062;
TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA     = 0x0063;
TLS_RSA_EXPORT1024_WITH_RC4_56_SHA          = 0x0064;

-- Following were added for TLS 1.2
TLS_RSA_WITH_NULL_SHA256                    = 0x003B;
TLS_RSA_WITH_AES_128_CBC_SHA256             = 0x003C;
TLS_RSA_WITH_AES_256_CBC_SHA256             = 0x003D;
TLS_DHE_DSS_WITH_AES_128_CBC_SHA256         = 0x0040;
TLS_DHE_DSS_WITH_AES_256_CBC_SHA256         = 0x006A;


-- PSK cipher suites
TLS_PSK_WITH_3DES_EDE_CBC_SHA               = 0x008B;
TLS_PSK_WITH_AES_128_CBC_SHA                = 0x008C;
TLS_PSK_WITH_AES_256_CBC_SHA                = 0x008D;
TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA           = 0x0093;
TLS_RSA_PSK_WITH_AES_128_CBC_SHA            = 0x0094;
TLS_RSA_PSK_WITH_AES_256_CBC_SHA            = 0x0095;


TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA        = 0xc009;
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA          = 0xc013;
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA        = 0xc00a;
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA          = 0xc014;

-- Following were added for TLS 1.2
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256     = 0xC023;
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384     = 0xC024;
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256     = 0xC02B;
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384     = 0xC02C;
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256       = 0xC027;
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384       = 0xC028;


-- SSL2 cipher suites
SSL_CK_RC4_128_WITH_MD5                     = 0x010080;
SSL_CK_RC4_128_EXPORT40_WITH_MD5            = 0x020080;
SSL_CK_RC2_128_CBC_WITH_MD5                 = 0x030080;
SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5        = 0x040080;
SSL_CK_IDEA_128_CBC_WITH_MD5                = 0x050080;
SSL_CK_DES_64_CBC_WITH_MD5                  = 0x060040;
SSL_CK_DES_192_EDE3_CBC_WITH_MD5            = 0x0700C0;

-- Key Types
-- ECC curve types
TLS_ECC_P256_CURVE_KEY_TYPE                = 23;
TLS_ECC_P384_CURVE_KEY_TYPE                = 24;
TLS_ECC_P521_CURVE_KEY_TYPE                = 25;

-- definition for algorithms used by ssl provider
SSL_ECDSA_ALGORITHM                   = L"ECDSA";

-- definition for szExchange field for PSK cipher suites
TLS_PSK_EXCHANGE                      = L"PSK";
TLS_RSA_PSK_EXCHANGE                  = L"RSA_PSK";


NCRYPT_SSL_CIPHER_LENGTHS_BLOCK_PADDING = 0x00000001;


--  SslComputeEapKeyBlock flags

NCRYPT_SSL_EAP_PRF_FIELD    = 0x000000ff;
NCRYPT_SSL_EAP_ID           = 0x00000000;
NCRYPT_SSL_EAP_TTLSV0_ID    = 0x00000001;
NCRYPT_SSL_EAP_TTLSV0_CHLNG_ID = 0x00000002;
NCRYPT_SSL_EAP_FAST_ID      = 0x00000003;

-- SSL provider property names.
SSL_KEY_TYPE_PROPERTY               = L"KEYTYPE";

--
-- The following flag is set to include the hash OID in an RSASSA-PKCS1-v1_5
-- signature according to the TLS 1.2 RFC. The null-terminated
-- Unicode string that identifies the cryptographic algorithm to use to create
-- the BCRYPT PKCS1 padding is passed at the start of the pbHashValue
-- parameter. The hash bytes immediately follow the Unicode NULL terminator
-- character (L'\0'). The cbHashValue includes the byte length of this
-- Unicode string.
--
-- This flag is only applicable to TLS 1.2 RSA signatures and MUST NOT be set
-- for other protocols, such as, TLS 1.0 or other signature types like
-- DSA or ECDSA.
--

NCRYPT_SSL_SIGN_INCLUDE_HASHOID = 0x00000001;

}

ffi.cdef[[
	typedef uint32_t	SECURITY_STATUS;
	typedef SECURITY_STATUS *PSECURITY_STATUS;


]]

ffi.cdef[[

static const int	NCRYPT_SSL_MAX_NAME_SIZE = 64;

typedef struct _NCRYPT_SSL_CIPHER_SUITE
{
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    DWORD dwBaseCipherSuite;
    WCHAR szCipherSuite[NCRYPT_SSL_MAX_NAME_SIZE];
    WCHAR szCipher[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwCipherLen;
    DWORD dwCipherBlockLen;    // in bytes
    WCHAR szHash[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwHashLen;
    WCHAR szExchange[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    WCHAR szCertificate[NCRYPT_SSL_MAX_NAME_SIZE];
    DWORD dwKeyType;
} NCRYPT_SSL_CIPHER_SUITE;


typedef struct _NCRYPT_SSL_CIPHER_LENGTHS
{
    DWORD cbLength;
    DWORD dwHeaderLen;
    DWORD dwFixedTrailerLen;
    DWORD dwMaxVariableTrailerLen;
    DWORD dwFlags;
} NCRYPT_SSL_CIPHER_LENGTHS;
]]


ffi.cdef[[
//+-------------------------------------------------------------------------
// SslChangeNotify
//
// This function is used to register for changes to the SSL protocol
// provider configuration settings.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslChangeNotify(HANDLE   hEvent, DWORD    dwFlags);


//+-------------------------------------------------------------------------
// SslComputeClientAuthHash
//
// Computes the hashes that are sent in the CertificateVerify handshake
// message.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslComputeClientAuthHash(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_KEY_HANDLE hMasterKey,
	NCRYPT_HASH_HANDLE hHandshakeHash,
	LPCWSTR pszAlgId,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslComputeClientAuthHashFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hMasterKey,
        NCRYPT_HASH_HANDLE hHandshakeHash,
        LPCWSTR pszAlgId,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        DWORD   dwFlags);

//+-------------------------------------------------------------------------
// SslComputeEapKeyBlock
//
// Computes the key block used by EAP
//     pbRandoms must be client_random + server_random (client random
//     concatenated with the server random).
//--------------------------------------------------------------------------
SECURITY_STATUS

SslComputeEapKeyBlock(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_KEY_HANDLE hMasterKey,
    PBYTE pbRandoms,
	DWORD   cbRandoms,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslComputeEapKeyBlockFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hMasterKey,
    PBYTE pbRandoms,
        DWORD   cbRandoms,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        DWORD   dwFlags);
]]




ffi.cdef[[
//+-------------------------------------------------------------------------
// SslComputeFinishedHash
//
// Computes the hashes that are sent in the Finished handshake message.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslComputeFinishedHash(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_KEY_HANDLE hMasterKey,
	NCRYPT_HASH_HANDLE hHandshakeHash,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslComputeFinishedHashFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hMasterKey,
        NCRYPT_HASH_HANDLE hHandshakeHash,
    PBYTE pbOutput,
        DWORD   cbOutput,
        DWORD   dwFlags);

//+-------------------------------------------------------------------------
// SslCreateEphemeralKey
//
// Creates an ephemeral key.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslCreateEphemeralKey(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_KEY_HANDLE *phEphemeralKey,
	DWORD   dwProtocol,
	DWORD   dwCipherSuite,
	DWORD   dwKeyType,
	DWORD   dwKeyBitLen,
    PBYTE pbParams,
	DWORD   cbParams,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslCreateEphemeralKeyFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
       NCRYPT_KEY_HANDLE *phEphemeralKey,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        DWORD   dwKeyType,
        DWORD   dwKeyBitLen,
    PBYTE pbParams,
        DWORD   cbParams,
        DWORD   dwFlags);


//+-------------------------------------------------------------------------
// SslCreateHandshakeHash
//
// Creates a compound hash object used to hash handshake messages.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslCreateHandshakeHash(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_HASH_HANDLE *phHandshakeHash,
	DWORD   dwProtocol,
	DWORD   dwCipherSuite,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslCreateHandshakeHashFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
       NCRYPT_HASH_HANDLE *phHandshakeHash,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        DWORD   dwFlags);
]]



ffi.cdef[[
//+-------------------------------------------------------------------------
// SslDecryptPacket
//
// Decrypts a single SSL packet.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslDecryptPacket(
	NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
	DWORD   cbInput,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	ULONGLONG SequenceNumber,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslDecryptPacketFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
        DWORD   cbInput,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        ULONGLONG SequenceNumber,
        DWORD   dwFlags);


//+-------------------------------------------------------------------------
// SslEncryptPacket
//
// Encrypts a single SSL packet.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslEncryptPacket(
    NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
	DWORD   cbInput,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	ULONGLONG SequenceNumber,
	DWORD   dwContentType,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslEncryptPacketFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
        DWORD   cbInput,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        ULONGLONG SequenceNumber,
        DWORD   dwContentType,
        DWORD   dwFlags);
]]


ffi.cdef[[
//+-------------------------------------------------------------------------
// SslEnumCipherSuites
//
// This function is used to enumerate the list of cipher suites supported
// by an SSL protocol provider. If a private key handle is specified, then
// this function will only return cipher suites that are compatible with
// the private key.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslEnumCipherSuites(
    NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hPrivateKey,
    NCRYPT_SSL_CIPHER_SUITE **ppCipherSuite,
    PVOID * ppEnumState,
    DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslEnumCipherSuitesFn)(
    NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hPrivateKey,
    NCRYPT_SSL_CIPHER_SUITE **ppCipherSuite,
    PVOID * ppEnumState,
    DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslEnumProtocolProviders
//
// Returns a list of all the SSL protocol providers that are currently
// installed on the system.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslEnumProtocolProviders(
	DWORD * pdwProviderCount,
    NCryptProviderName **ppProviderList,
	DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslExportKey
//
// Exports an SSL session key into a serialized blob.
//--------------------------------------------------------------------------
SECURITY_STATUS

SslExportKey(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hKey,
        LPCWSTR pszBlobType,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslExportKeyFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hKey,
        LPCWSTR pszBlobType,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        DWORD   dwFlags);
]]


ffi.cdef[[
//+-------------------------------------------------------------------------
// SslFreeBuffer
//
// Frees a memory buffer that was allocated by one of the other SSL protocol
// provider functions.
//--------------------------------------------------------------------------
SECURITY_STATUS SslFreeBuffer(PVOID   pvInput);

typedef SECURITY_STATUS ( * SslFreeBufferFn)(PVOID   pvInput);


//+-------------------------------------------------------------------------
// SslFreeObject
//
// Frees a key, hash, or provider object that was created using one of the
// other SSL protocol provider functions.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslFreeObject(NCRYPT_HANDLE hObject, DWORD   dwFlags);

typedef SECURITY_STATUS ( * SslFreeObjectFn)(NCRYPT_HANDLE hObject, DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslGenerateMasterKey
//
// Perform an SSL key exchange operations. This function computes the SSL
// master secret, and returns a handle to this object to the caller. This
// master key can then be used to derive the SSL session keys and finish
// the SSL handshake.
//
// When RSA key exchange is being performed, the client-side of schannel
// calls SslGenerateMasterKey and the server-side of schannel calls
// SslImportMasterKey. When DH key exchange is being performed, schannel
// calls SslGenerateMasterKey on both the client-side and the server-side.
//--------------------------------------------------------------------------
SECURITY_STATUS

SslGenerateMasterKey(
        NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hPrivateKey,
        NCRYPT_KEY_HANDLE hPublicKey,
       NCRYPT_KEY_HANDLE *phMasterKey,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        PNCryptBufferDesc pParameterList,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslGenerateMasterKeyFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_KEY_HANDLE hPrivateKey,
        NCRYPT_KEY_HANDLE hPublicKey,
       NCRYPT_KEY_HANDLE *phMasterKey,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        PNCryptBufferDesc pParameterList,
    PBYTE pbOutput,
        DWORD   cbOutput,
       DWORD * pcbResult,
        DWORD   dwFlags);


//+-------------------------------------------------------------------------
// SslGenerateSessionKeys
//
// Generates a set of session keys, based on a supplied master secret and
// one or more additional parameters.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslGenerateSessionKeys(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hMasterKey,
       NCRYPT_KEY_HANDLE *phReadKey,
       NCRYPT_KEY_HANDLE *phWriteKey,
        PNCryptBufferDesc pParameterList,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslGenerateSessionKeysFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hMasterKey,
       NCRYPT_KEY_HANDLE *phReadKey,
       NCRYPT_KEY_HANDLE *phWriteKey,
        PNCryptBufferDesc pParameterList,
        DWORD   dwFlags);
]]


ffi.cdef[[
//+-------------------------------------------------------------------------
// SslGetKeyProperty
//
// Queries information from the key.
//--------------------------------------------------------------------------
SECURITY_STATUS

SslGetKeyProperty(
        NCRYPT_KEY_HANDLE hKey,
        LPCWSTR pszProperty,
    PBYTE *ppbOutput,
       DWORD * pcbOutput,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslGetKeyPropertyFn)(
        NCRYPT_KEY_HANDLE hKey,
        LPCWSTR pszProperty,
    PBYTE *ppbOutput,
       DWORD * pcbOutput,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslGetProviderProperty
//
// Queries information from the protocol provider.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslGetProviderProperty(
        NCRYPT_PROV_HANDLE hSslProvider,
        LPCWSTR pszProperty,
    PBYTE *ppbOutput,
       DWORD * pcbOutput,
    PVOID *ppEnumState,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslGetProviderPropertyFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        LPCWSTR pszProperty,
    PBYTE *ppbOutput,
       DWORD * pcbOutput,
    PVOID *ppEnumState,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslHashHandshake
//
// Adds a handshake message to the cumulative handshake hash object. This
// handshake hash is used when generating or processing Finished and
// CertificateVerify messages.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslHashHandshake(NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_HASH_HANDLE hHandshakeHash,
    PBYTE pbInput,
        DWORD   cbInput,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslHashHandshakeFn)(
    NCRYPT_PROV_HANDLE hSslProvider,
    NCRYPT_HASH_HANDLE hHandshakeHash,
    PBYTE pbInput,
        DWORD   cbInput,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslImportKey
//
// Imports a public key into the protocol provider, as part of a key
// exchange operation. This function is also used to import session keys,
// when transferring them from one process to another.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslImportKey(
        NCRYPT_PROV_HANDLE hSslProvider,
       NCRYPT_KEY_HANDLE *phKey,
        LPCWSTR pszBlobType,
    PBYTE pbKeyBlob,
        DWORD   cbKeyBlob,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslImportKeyFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
       NCRYPT_KEY_HANDLE *phKey,
        LPCWSTR pszBlobType,
    PBYTE pbKeyBlob,
        DWORD   cbKeyBlob,
        DWORD   dwFlags);


//+-------------------------------------------------------------------------
// SslImportMasterKey
//
// This function is used when performing a server-side SSL key exchange
// operation. This function decrypts the pre-master secret, computes the
// SSL master secret, and returns a handle to this object to the caller.
// This master key can then be used to derive the SSL session keys, and
// finish the SSL handshake.
//
// Note that this function is only used when the RSA key exchange algorithm
// is being used. When DH is used, then the server-side of schannel calls
// SslGenerateMasterKey instead.
//--------------------------------------------------------------------------
SECURITY_STATUS

SslImportMasterKey(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hPrivateKey,
       NCRYPT_KEY_HANDLE *phMasterKey,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        NCryptBufferDesc *pParameterList,
    PBYTE pbEncryptedKey,
        DWORD   cbEncryptedKey,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslImportMasterKeyFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hPrivateKey,
       NCRYPT_KEY_HANDLE *phMasterKey,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        NCryptBufferDesc *pParameterList,
    PBYTE pbEncryptedKey,
        DWORD   cbEncryptedKey,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslLookupCipherSuiteInfo
//
// Looks up cipher suite information given the suite number and a key type.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslLookupCipherSuiteInfo(
        NCRYPT_PROV_HANDLE hSslProvider,
        DWORD dwProtocol,
        DWORD dwCipherSuite,
        DWORD dwKeyType,
       NCRYPT_SSL_CIPHER_SUITE *pCipherSuite,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslLookupCipherSuiteInfoFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        DWORD dwProtocol,
        DWORD dwCipherSuite,
        DWORD dwKeyType,
       NCRYPT_SSL_CIPHER_SUITE *pCipherSuite,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslOpenPrivateKey
//
// This function is used to obtain a handle to the private key that
// corresponds to the passed in server certificate. This handle will be used
// by the server-side of Schannel when performing key exchange operations.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslOpenPrivateKey(
       NCRYPT_PROV_HANDLE hSslProvider,
      NCRYPT_KEY_HANDLE *phPrivateKey,
       PCCERT_CONTEXT pCertContext,
       DWORD dwFlags);

typedef SECURITY_STATUS
( * SslOpenPrivateKeyFn)(
       NCRYPT_PROV_HANDLE hSslProvider,
      NCRYPT_KEY_HANDLE *phPrivateKey,
       PCCERT_CONTEXT pCertContext,
       DWORD dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslOpenProvider
//
// Returns a handle to the specified protocol provider.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslOpenProvider(
	NCRYPT_PROV_HANDLE *phSslProvider,
	LPCWSTR pszProviderName,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslOpenProviderFn)(
       NCRYPT_PROV_HANDLE *phSslProvider,
        LPCWSTR pszProviderName,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslSignHash
//
// Signs the passed in hash with the private key specified by the passed
// in key handle.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslSignHash(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hPrivateKey,
    PBYTE pbHashValue,
        DWORD   cbHashValue,
    PBYTE pbSignature,
        DWORD   cbSignature,
       DWORD * pcbResult,
        DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslSignHashFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hPrivateKey,
    PBYTE pbHashValue,
        DWORD   cbHashValue,
    PBYTE pbSignature,
        DWORD   cbSignature,
       DWORD * pcbResult,
        DWORD   dwFlags);
]]



ffi.cdef[[
//+-------------------------------------------------------------------------
// SslVerifySignature
//
// Verifies the passed in signature with the passed in hash and the
// passed in public key.
//--------------------------------------------------------------------------
SECURITY_STATUS
SslVerifySignature(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_KEY_HANDLE hPublicKey,
    PBYTE pbHashValue,
	DWORD   cbHashValue,
    PBYTE pbSignature,
	DWORD   cbSignature,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslVerifySignatureFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        NCRYPT_KEY_HANDLE hPublicKey,
    PBYTE pbHashValue,
        DWORD   cbHashValue,
    PBYTE pbSignature,
        DWORD   cbSignature,
        DWORD   dwFlags);
]]

ffi.cdef[[
//+-------------------------------------------------------------------------
// SslCreateClientAuthHash
//
// Creates the hash object used to hash TLS 1.2 handshake messages for
// client authentication
//--------------------------------------------------------------------------
SECURITY_STATUS
SslLookupCipherLengths(
	NCRYPT_PROV_HANDLE hSslProvider,
	DWORD dwProtocol,
	DWORD dwCipherSuite,
	DWORD dwKeyType,
    NCRYPT_SSL_CIPHER_LENGTHS *pCipherLengths,
	DWORD cbCipherLengths,
	DWORD dwFlags);

typedef SECURITY_STATUS
( * SslLookupCipherLengthsFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        DWORD dwProtocol,
        DWORD dwCipherSuite,
        DWORD dwKeyType,
    NCRYPT_SSL_CIPHER_LENGTHS *pCipherLengths,
        DWORD cbCipherLengths,
        DWORD dwFlags);
]]

ffi.cdef[[
SECURITY_STATUS
SslCreateClientAuthHash(
	NCRYPT_PROV_HANDLE hSslProvider,
	NCRYPT_HASH_HANDLE *phHandshakeHash,
	DWORD   dwProtocol,
	DWORD   dwCipherSuite,
	LPCWSTR pszHashAlgId,
	DWORD   dwFlags);

typedef SECURITY_STATUS
( * SslCreateClientAuthHashFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
       NCRYPT_HASH_HANDLE *phHandshakeHash,
        DWORD   dwProtocol,
        DWORD   dwCipherSuite,
        LPCWSTR pszHashAlgId,
        DWORD   dwFlags);

SECURITY_STATUS
SslGetCipherSuitePRFHashAlgorithm(
	NCRYPT_PROV_HANDLE hSslProvider,
	DWORD dwProtocol,
	DWORD dwCipherSuite,
	DWORD dwKeyType,
	WCHAR szPRFHash[NCRYPT_SSL_MAX_NAME_SIZE],
	DWORD dwFlags);

typedef SECURITY_STATUS
( * SslGetCipherSuitePRFHashAlgorithmFn)(
        NCRYPT_PROV_HANDLE hSslProvider,
        DWORD dwProtocol,
        DWORD dwCipherSuite,
        DWORD dwKeyType,
        WCHAR szPRFHash[NCRYPT_SSL_MAX_NAME_SIZE],
        DWORD dwFlags);
]]

--#define NCRYPT_SSL_INTERFACE_VERSION_1  BCRYPT_MAKE_INTERFACE_VERSION(1,0)
--#define NCRYPT_SSL_INTERFACE_VERSION_2  BCRYPT_MAKE_INTERFACE_VERSION(2,0)
--#define NCRYPT_SSL_INTERFACE_VERSION    NCRYPT_SSL_INTERFACE_VERSION_1


ffi.cdef[[
//+-------------------------------------------------------------------------
// SslInitializeInterface
//
// This function is implemented by the SSL protocol provider, and provides
// the protocol router with a dispatch table of functions implemented by
// the provider.
//--------------------------------------------------------------------------

typedef struct _NCRYPT_SSL_FUNCTION_TABLE
{
    BCRYPT_INTERFACE_VERSION    Version;
    SslComputeClientAuthHashFn  ComputeClientAuthHash;
    SslComputeEapKeyBlockFn     ComputeEapKeyBlock;
    SslComputeFinishedHashFn    ComputeFinishedHash;
    SslCreateEphemeralKeyFn     CreateEphemeralKey;
    SslCreateHandshakeHashFn    CreateHandshakeHash;
    SslDecryptPacketFn          DecryptPacket;
    SslEncryptPacketFn          EncryptPacket;
    SslEnumCipherSuitesFn       EnumCipherSuites;
    SslExportKeyFn              ExportKey;
    SslFreeBufferFn             FreeBuffer;
    SslFreeObjectFn             FreeObject;
    SslGenerateMasterKeyFn      GenerateMasterKey;
    SslGenerateSessionKeysFn    GenerateSessionKeys;
    SslGetKeyPropertyFn         GetKeyProperty;
    SslGetProviderPropertyFn    GetProviderProperty;
    SslHashHandshakeFn          HashHandshake;
    SslImportMasterKeyFn        ImportMasterKey;
    SslImportKeyFn              ImportKey;
    SslLookupCipherSuiteInfoFn  LookupCipherSuiteInfo;
    SslOpenPrivateKeyFn         OpenPrivateKey;
    SslOpenProviderFn           OpenProvider;
    SslSignHashFn               SignHash;
    SslVerifySignatureFn        VerifySignature;
// End of entries in NCRYPT_SSL_INTERFACE_VERSION_1

    SslLookupCipherLengthsFn    LookupCipherLengths;
    SslCreateClientAuthHashFn   CreateClientAuthHash;
    SslGetCipherSuitePRFHashAlgorithmFn GetCipherSuitePRFHashAlgorithm;
// End of entries in NCRYPT_SSL_INTERFACE_VERSION_2
} NCRYPT_SSL_FUNCTION_TABLE, *PNCRYPT_SSL_FUNCTION_TABLE;

NTSTATUS GetSChannelInterface(
	LPCWSTR pszProviderName,
	NCRYPT_SSL_FUNCTION_TABLE **ppFunctionTable,
	DWORD dwFlags);

typedef NTSTATUS
( * GetSChannelInterfaceFn)(
        LPCWSTR pszProviderName,
       NCRYPT_SSL_FUNCTION_TABLE **ppFunctionTable,
        ULONG dwFlags);


SECURITY_STATUS
SslInitializeInterface(
    LPCWSTR pszProviderName,
    NCRYPT_SSL_FUNCTION_TABLE *pFunctionTable,
    DWORD    dwFlags);

typedef SECURITY_STATUS
( * SslInitializeInterfaceFn)(
    LPCWSTR pszProviderName,
    NCRYPT_SSL_FUNCTION_TABLE *pFunctionTable,
    DWORD    dwFlags);


SECURITY_STATUS SslIncrementProviderReferenceCount(NCRYPT_PROV_HANDLE hSslProvider);

SECURITY_STATUS SslDecrementProviderReferenceCount(NCRYPT_PROV_HANDLE hSslProvider);
]]


ffi.cdef[[
typedef struct _SSLProvider {
	NCRYPT_SSL_FUNCTION_TABLE	*FunctionTable;
	NCRYPT_PROV_HANDLE	Handle;
} SSLProvider;
]]

ffi.cdef[[
typedef struct _SSLHandshakeHash {
	NCRYPT_HASH_HANDLE	Handle;
	SSLProvider			Provider;
} SSLHandshakeHash;
]]

ffi.cdef[[
typedef struct __SSLKey {
	NCRYPT_KEY_HANDLE	Handle;
	SSLProvider			Provider;
} SSLKey;
]]

SSLKey = ffi.typeof("SSLKey");
SSLKey_mt = {
	__gc = function(self)
		self.Provider.FunctionTable.FreeObject(self.Handle, 0);
	end,

	__index = {
	},
}
SSLKey = ffi.metatype(SSLKey, SSLKey_mt);


SSLProvider = ffi.typeof("SSLProvider");
SSLProvider_mt = {
	__gc = function(self)
		self.FunctionTable.FreeObject(self.Handle, 0);
	end,

	__new = function(ct, fTable)
		-- get a provider handle
		local phSslProvider = ffi.new("NCRYPT_PROV_HANDLE[1]");
		local dwFlags = 0;

		local status = fTable.OpenProvider(phSslProvider, nil, dwFlags);

		-- if not, then return error
		if status ~= 0 then
			return nil, status
		end

		-- create the provider instance
		local provider = ffi.new("SSLProvider", fTable, phSslProvider[0])

		return provider;
	end,

	__index = {
--[[
    BCRYPT_INTERFACE_VERSION    Version;
    SslEnumCipherSuitesFn       EnumCipherSuites;
    SslGetProviderPropertyFn    GetProviderProperty;
    SslLookupCipherSuiteInfoFn  LookupCipherSuiteInfo;
    SslLookupCipherLengthsFn    LookupCipherLengths;
    SslGetCipherSuitePRFHashAlgorithmFn GetCipherSuitePRFHashAlgorithm;


    SslComputeClientAuthHashFn  ComputeClientAuthHash;
    SslComputeFinishedHashFn    ComputeFinishedHash;
    SslCreateHandshakeHashFn    CreateHandshakeHash;
    SslHashHandshakeFn          HashHandshake;
    SslSignHashFn               SignHash;
    SslCreateClientAuthHashFn   CreateClientAuthHash;
    SslVerifySignatureFn        VerifySignature;


    SslDecryptPacketFn          DecryptPacket;
    SslEncryptPacketFn          EncryptPacket;


    SslFreeBufferFn             FreeBuffer;
    SslFreeObjectFn             FreeObject;
--]]

--[[
    SslComputeEapKeyBlockFn     ComputeEapKeyBlock;
    SslCreateEphemeralKeyFn     CreateEphemeralKey;
    SslExportKeyFn              ExportKey;
    SslGenerateMasterKeyFn      GenerateMasterKey;
    SslGenerateSessionKeysFn    GenerateSessionKeys;
    SslGetKeyPropertyFn         GetKeyProperty;
    SslImportMasterKeyFn        ImportMasterKey;
    SslImportKeyFn              ImportKey;
    SslOpenPrivateKeyFn         OpenPrivateKey;
--]]
	OpenPrivateKey = function(self, certContext)
		local phPrivateKey = ffi.new("NCRYPT_KEY_HANDLE[1]")
		local status = self.FunctionTable.OpenPrivateKey(self.Handle,
			phPrivateKey,
			pCertContext,
			0);

		if status ~= 0 then
			return nil, status
		end

		return SSLKey(phPrivateKey[0], self)
	end,



	}
}
SSLProvider = ffi.metatype(SSLProvider, SSLProvider_mt);





SSLHandshakeHash = ffi.typeof("SSLHandshakeHash");
SSLHandshakeHash_mt = {
	__gc = function(self)
	end,

	__new = function(ct, ...)
		return ffi.new(ct,...);
	end,

	__index = {
		HashMore = function(chunk, chunkSize)
			local status = self.Provider:HashHandshake(self.Handle,
				chunk, chunkSize, 0);

			return status == 0 or nil, status
		end,

		Finish = function(self, pbOutput, cbOutput)
			local status = self.Provider:ComputeFinishedHash(masterkey, self.Handle,
				pbOutput, cbOutput, 0);

			return status == 0 or nil, status
		end,

	},
}
SSLHandshakeHash = ffi.metatype(SSLHandshakeHash, SSLHandshakeHash_mt);

return SSL

--[[
/*++

Copyright (c) 2004  Microsoft Corporation

Module Name:

    sslprovider.h

Abstract:

    SSL protocol provider API prototypes and definitions

Author:

    John Banes (jbanes)     October 6, 2004

Revision History:

--*/
--]]
