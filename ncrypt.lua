local ffi = require "ffi"
require "WTypes"

local k32 = require "Kernel32"

local L = k32.AnsiToUnicode16

ffi.cdef[[
typedef LONG SECURITY_STATUS;
]]

local BCrypt = require "bcrypt"

local NCrypt = {
MS_KEY_STORAGE_PROVIDER       =  L"Microsoft Software Key Storage Provider";
MS_SMART_CARD_KEY_STORAGE_PROVIDER = L"Microsoft Smart Card Key Storage Provider";

--
-- Common algorithm identifiers.
--

NCRYPT_RSA_ALGORITHM           = BCrypt.BCRYPT_RSA_ALGORITHM;
NCRYPT_RSA_SIGN_ALGORITHM      = BCrypt.BCRYPT_RSA_SIGN_ALGORITHM;
NCRYPT_DH_ALGORITHM            = BCrypt.BCRYPT_DH_ALGORITHM;
NCRYPT_DSA_ALGORITHM           = BCrypt.BCRYPT_DSA_ALGORITHM;
NCRYPT_MD2_ALGORITHM           = BCrypt.BCRYPT_MD2_ALGORITHM;
NCRYPT_MD4_ALGORITHM           = BCrypt.BCRYPT_MD4_ALGORITHM;
NCRYPT_MD5_ALGORITHM           = BCrypt.BCRYPT_MD5_ALGORITHM;
NCRYPT_SHA1_ALGORITHM          = BCrypt.BCRYPT_SHA1_ALGORITHM;
NCRYPT_SHA256_ALGORITHM        = BCrypt.BCRYPT_SHA256_ALGORITHM;
NCRYPT_SHA384_ALGORITHM        = BCrypt.BCRYPT_SHA384_ALGORITHM;
NCRYPT_SHA512_ALGORITHM        = BCrypt.BCRYPT_SHA512_ALGORITHM;
NCRYPT_ECDSA_P256_ALGORITHM    = BCrypt.BCRYPT_ECDSA_P256_ALGORITHM;
NCRYPT_ECDSA_P384_ALGORITHM    = BCrypt.BCRYPT_ECDSA_P384_ALGORITHM;
NCRYPT_ECDSA_P521_ALGORITHM    = BCrypt.BCRYPT_ECDSA_P521_ALGORITHM;
NCRYPT_ECDH_P256_ALGORITHM     = BCrypt.BCRYPT_ECDH_P256_ALGORITHM;
NCRYPT_ECDH_P384_ALGORITHM     = BCrypt.BCRYPT_ECDH_P384_ALGORITHM;
NCRYPT_ECDH_P521_ALGORITHM     = BCrypt.BCRYPT_ECDH_P521_ALGORITHM;

NCRYPT_KEY_STORAGE_ALGORITHM   = L"KEY_STORAGE";


--
-- Interfaces
--

NCRYPT_HASH_INTERFACE                  = BCrypt.BCRYPT_HASH_INTERFACE;
NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE = BCrypt.BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;

NCRYPT_SECRET_AGREEMENT_INTERFACE      = BCrypt.BCRYPT_SECRET_AGREEMENT_INTERFACE;

NCRYPT_SIGNATURE_INTERFACE             = BCrypt.BCRYPT_SIGNATURE_INTERFACE;

NCRYPT_KEY_STORAGE_INTERFACE           = 0x00010001;
NCRYPT_SCHANNEL_INTERFACE              = 0x00010002;
NCRYPT_SCHANNEL_SIGNATURE_INTERFACE    = 0x00010003;

--
-- algorithm groups.
--

--NCRYPT_RSA_ALGORITHM_GROUP      = NCRYPT_RSA_ALGORITHM;
--NCRYPT_DH_ALGORITHM_GROUP       = NCRYPT_DH_ALGORITHM;
--NCRYPT_DSA_ALGORITHM_GROUP      = NCRYPT_DSA_ALGORITHM;
NCRYPT_ECDSA_ALGORITHM_GROUP    = L"ECDSA";
NCRYPT_ECDH_ALGORITHM_GROUP     = L"ECDH";


-- NCrypt generic memory descriptors


NCRYPTBUFFER_VERSION               = 0;

NCRYPTBUFFER_EMPTY                 = 0;
NCRYPTBUFFER_DATA                  = 1;
NCRYPTBUFFER_SSL_CLIENT_RANDOM     = 20;
NCRYPTBUFFER_SSL_SERVER_RANDOM     = 21;
NCRYPTBUFFER_SSL_HIGHEST_VERSION   = 22;
NCRYPTBUFFER_SSL_CLEAR_KEY         = 23;
NCRYPTBUFFER_SSL_KEY_ARG_DATA      = 24;

NCRYPTBUFFER_PKCS_OID              = 40;
NCRYPTBUFFER_PKCS_ALG_OID          = 41;
NCRYPTBUFFER_PKCS_ALG_PARAM        = 42;
NCRYPTBUFFER_PKCS_ALG_ID           = 43;
NCRYPTBUFFER_PKCS_ATTRS            = 44;
NCRYPTBUFFER_PKCS_KEY_NAME         = 45;
NCRYPTBUFFER_PKCS_SECRET           = 46;

NCRYPTBUFFER_CERT_BLOB             = 47;

--
-- NCrypt API Flags
--

NCRYPT_NO_PADDING_FLAG      = BCrypt.BCRYPT_PAD_NONE;
NCRYPT_PAD_PKCS1_FLAG       = BCrypt.BCRYPT_PAD_PKCS1;  -- NCryptEncrypt/Decrypt NCryptSignHash/VerifySignature
NCRYPT_PAD_OAEP_FLAG        = BCrypt.BCRYPT_PAD_OAEP;   -- BCryptEncrypt/Decrypt
NCRYPT_PAD_PSS_FLAG         = BCrypt.BCRYPT_PAD_PSS;    -- BCryptSignHash/VerifySignature
NCRYPT_NO_KEY_VALIDATION    = BCrypt.BCRYPT_NO_KEY_VALIDATION;
NCRYPT_MACHINE_KEY_FLAG                 = 0x00000020;  -- same as CAPI CRYPT_MACHINE_KEYSET
NCRYPT_SILENT_FLAG                      = 0x00000040;  -- same as CAPI CRYPT_SILENT
NCRYPT_OVERWRITE_KEY_FLAG               = 0x00000080;
NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG   = 0x00000200;
NCRYPT_DO_NOT_FINALIZE_FLAG             = 0x00000400;
NCRYPT_PERSIST_ONLY_FLAG                = 0x40000000;
NCRYPT_PERSIST_FLAG                     = 0x80000000;
NCRYPT_REGISTER_NOTIFY_FLAG             = 0x00000001;
NCRYPT_UNREGISTER_NOTIFY_FLAG           = 0x00000002;

-- AlgOperations flags for use with NCryptEnumAlgorithms()
NCRYPT_CIPHER_OPERATION                = BCrypt.BCRYPT_CIPHER_OPERATION;
NCRYPT_HASH_OPERATION                  = BCrypt.BCRYPT_HASH_OPERATION;
NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = BCrypt.BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION;
NCRYPT_SECRET_AGREEMENT_OPERATION      = BCrypt.BCRYPT_SECRET_AGREEMENT_OPERATION;
NCRYPT_SIGNATURE_OPERATION             = BCrypt.BCRYPT_SIGNATURE_OPERATION;
NCRYPT_RNG_OPERATION                   = BCrypt.BCRYPT_RNG_OPERATION;

-- NCryptEnumKeys flags
NCRYPT_MACHINE_KEY_FLAG         = 0x00000020;

-- NCryptOpenKey flags
NCRYPT_MACHINE_KEY_FLAG         = 0x00000020;
NCRYPT_SILENT_FLAG              = 0x00000040;

-- NCryptCreatePersistedKey flags
NCRYPT_MACHINE_KEY_FLAG         = 0x00000020;
NCRYPT_OVERWRITE_KEY_FLAG       = 0x00000080;

-- Standard property names.
NCRYPT_NAME_PROPERTY                   = L"Name";
NCRYPT_UNIQUE_NAME_PROPERTY            = L"Unique Name";
NCRYPT_ALGORITHM_PROPERTY              = L"Algorithm Name";
NCRYPT_LENGTH_PROPERTY                 = L"Length";
NCRYPT_LENGTHS_PROPERTY                = L"Lengths";
NCRYPT_BLOCK_LENGTH_PROPERTY           = L"Block Length";
NCRYPT_UI_POLICY_PROPERTY              = L"UI Policy";
NCRYPT_EXPORT_POLICY_PROPERTY          = L"Export Policy";
NCRYPT_WINDOW_HANDLE_PROPERTY          = L"HWND Handle";
NCRYPT_USE_CONTEXT_PROPERTY            = L"Use Context";
NCRYPT_IMPL_TYPE_PROPERTY              = L"Impl Type";
NCRYPT_KEY_USAGE_PROPERTY              = L"Key Usage";
NCRYPT_KEY_TYPE_PROPERTY               = L"Key Type";
NCRYPT_VERSION_PROPERTY                = L"Version";
NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY = L"Security Descr Support";
NCRYPT_SECURITY_DESCR_PROPERTY         = L"Security Descr";
NCRYPT_USE_COUNT_ENABLED_PROPERTY      = L"Enabled Use Count";
NCRYPT_USE_COUNT_PROPERTY              = L"Use Count";
NCRYPT_LAST_MODIFIED_PROPERTY          = L"Modified";
NCRYPT_MAX_NAME_LENGTH_PROPERTY        = L"Max Name Length";
NCRYPT_ALGORITHM_GROUP_PROPERTY        = L"Algorithm Group";
NCRYPT_DH_PARAMETERS_PROPERTY          = BCrypt.BCRYPT_DH_PARAMETERS;
NCRYPT_PROVIDER_HANDLE_PROPERTY        = L"Provider Handle";
NCRYPT_PIN_PROPERTY                    = L"SmartCardPin";
NCRYPT_READER_PROPERTY                 = L"SmartCardReader";
NCRYPT_SMARTCARD_GUID_PROPERTY         = L"SmartCardGuid";
NCRYPT_CERTIFICATE_PROPERTY            = L"SmartCardKeyCertificate";
NCRYPT_PIN_PROMPT_PROPERTY             = L"SmartCardPinPrompt";
NCRYPT_USER_CERTSTORE_PROPERTY         = L"SmartCardUserCertStore";
NCRYPT_ROOT_CERTSTORE_PROPERTY         = L"SmartcardRootCertStore";
NCRYPT_SECURE_PIN_PROPERTY             = L"SmartCardSecurePin";
NCRYPT_ASSOCIATED_ECDH_KEY             = L"SmartCardAssociatedECDHKey";
NCRYPT_SCARD_PIN_ID                    = L"SmartCardPinId";
NCRYPT_SCARD_PIN_INFO                  = L"SmartCardPinInfo";

-- Maximum length of property name (in characters)
NCRYPT_MAX_PROPERTY_NAME       = 64;

-- Maximum length of property data (in bytes)
NCRYPT_MAX_PROPERTY_DATA        = 0x100000;

-- NCRYPT_EXPORT_POLICY_PROPERTY property flags.
NCRYPT_ALLOW_EXPORT_FLAG                = 0x00000001;
NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG      = 0x00000002;
NCRYPT_ALLOW_ARCHIVING_FLAG             = 0x00000004;
NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG   = 0x00000008;

-- NCRYPT_IMPL_TYPE_PROPERTY property flags.
NCRYPT_IMPL_HARDWARE_FLAG               = 0x00000001;
NCRYPT_IMPL_SOFTWARE_FLAG               = 0x00000002;
NCRYPT_IMPL_REMOVABLE_FLAG              = 0x00000008;
NCRYPT_IMPL_HARDWARE_RNG_FLAG           = 0x00000010;

-- NCRYPT_KEY_USAGE_PROPERTY property flags.
NCRYPT_ALLOW_DECRYPT_FLAG               = 0x00000001;
NCRYPT_ALLOW_SIGNING_FLAG               = 0x00000002;
NCRYPT_ALLOW_KEY_AGREEMENT_FLAG         = 0x00000004;
NCRYPT_ALLOW_ALL_USAGES                 = 0x00ffffff;

-- NCRYPT_UI_POLICY_PROPERTY property flags and structure
NCRYPT_UI_PROTECT_KEY_FLAG              = 0x00000001;
NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG    = 0x00000002;


-- NCryptGetProperty flags
NCRYPT_PERSIST_ONLY_FLAG        = 0x40000000;

-- NCryptSetProperty flags
NCRYPT_PERSIST_FLAG             = 0x80000000;
NCRYPT_PERSIST_ONLY_FLAG        = 0x40000000;

NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG   = 0x00000200;

NCRYPT_PKCS7_ENVELOPE_BLOB      = L"PKCS7_ENVELOPE";
NCRYPT_PKCS8_PRIVATE_KEY_BLOB   = L"PKCS8_PRIVATEKEY";
NCRYPT_OPAQUETRANSPORT_BLOB     = L"OpaqueTransport";

NCRYPT_MACHINE_KEY_FLAG         = 0x00000020;
NCRYPT_DO_NOT_FINALIZE_FLAG     = 0x00000400;
NCRYPT_EXPORT_LEGACY_FLAG       = 0x00000800;

-- NCryptNotifyChangeKey flags
NCRYPT_REGISTER_NOTIFY_FLAG     = 0x00000001;
NCRYPT_UNREGISTER_NOTIFY_FLAG   = 0x00000002;
NCRYPT_MACHINE_KEY_FLAG         = 0x00000020;

-- NCRYPT_KEY_STORAGE_INTERFACE_VERSION = BCrypt.BCRYPT_MAKE_INTERFACE_VERSION(1,0);

}


ffi.cdef[[
// NCRYPT shares the same BCRYPT definitions
typedef BCryptBuffer     NCryptBuffer;
typedef BCryptBuffer*    PNCryptBuffer;
typedef BCryptBufferDesc NCryptBufferDesc;
typedef BCryptBufferDesc* PNCryptBufferDesc;
]]


ffi.cdef[[
	typedef HANDLE		HCRYPTPROV;
	typedef HANDLE		HCRYPTKEY;

	typedef ULONG_PTR NCRYPT_HANDLE;
	typedef ULONG_PTR NCRYPT_PROV_HANDLE;
	typedef ULONG_PTR NCRYPT_KEY_HANDLE;
	typedef ULONG_PTR NCRYPT_HASH_HANDLE;
	typedef ULONG_PTR NCRYPT_SECRET_HANDLE;
]]

ffi.cdef[[
// USE EXTREME CAUTION: editing comments that contain "certenrolls_*" tokens
// could break building CertEnroll idl files:
// certenrolls_begin -- NCryptAlgorithmName
typedef struct _NCryptAlgorithmName
{
    LPWSTR  pszName;
    DWORD   dwClass;            // the CNG interface that supports this algorithm
    DWORD   dwAlgOperations;    // the types of operations supported by this algorithm
    DWORD   dwFlags;
} NCryptAlgorithmName, *PNCryptAlgorithmName;
// certenrolls_end
]]

ffi.cdef[[
typedef struct NCryptKeyName
{
    LPWSTR  pszName;
    LPWSTR  pszAlgid;
    DWORD   dwLegacyKeySpec;
    DWORD   dwFlags;
} NCryptKeyName, *PNCryptKeyName;
]]


ffi.cdef[[
typedef struct NCryptProviderName
{
    LPWSTR  pszName;
    LPWSTR  pszComment;
} NCryptProviderName, *PNCryptProviderName;
]]

ffi.cdef[[
typedef struct __NCRYPT_UI_POLICY_BLOB
{
    DWORD   dwVersion;
    DWORD   dwFlags;
    DWORD   cbCreationTitle;
    DWORD   cbFriendlyName;
    DWORD   cbDescription;
    // creation title string
    // friendly name string
    // description string
} NCRYPT_UI_POLICY_BLOB;

typedef struct __NCRYPT_UI_POLICY
{
    DWORD   dwVersion;
    DWORD   dwFlags;
    LPCWSTR pszCreationTitle;
    LPCWSTR pszFriendlyName;
    LPCWSTR pszDescription;
} NCRYPT_UI_POLICY;


// NCRYPT_LENGTHS_PROPERTY property structure.
typedef struct __NCRYPT_SUPPORTED_LENGTHS
{
    DWORD   dwMinLength;
    DWORD   dwMaxLength;
    DWORD   dwIncrement;
    DWORD   dwDefaultLength;
} NCRYPT_SUPPORTED_LENGTHS;
]]

ffi.cdef[[
//
// Functions used to manage persisted keys.
//

SECURITY_STATUS
NCryptOpenStorageProvider(
	NCRYPT_PROV_HANDLE *phProvider,
	LPCWSTR pszProviderName,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS

NCryptEnumAlgorithms(
	NCRYPT_PROV_HANDLE hProvider,
	DWORD   dwAlgOperations,
	DWORD * pdwAlgCount,
    NCryptAlgorithmName **ppAlgList,
	DWORD   dwFlags);

SECURITY_STATUS
NCryptIsAlgSupported(
	NCRYPT_PROV_HANDLE hProvider,
	LPCWSTR pszAlgId,
	DWORD   dwFlags);
]]


ffi.cdef[[

SECURITY_STATUS
NCryptEnumKeys(
	NCRYPT_PROV_HANDLE hProvider,
	LPCWSTR pszScope,
    NCryptKeyName **ppKeyName,
	PVOID * ppEnumState,
	DWORD   dwFlags);
]]


ffi.cdef[[

SECURITY_STATUS
NCryptEnumStorageProviders(DWORD * pdwProviderCount,
    NCryptProviderName **ppProviderList,
	DWORD   dwFlags);
]]


ffi.cdef[[
SECURITY_STATUS NCryptFreeBuffer(PVOID   pvInput);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptOpenKey(
	NCRYPT_PROV_HANDLE hProvider,
	NCRYPT_KEY_HANDLE *phKey,
	LPCWSTR pszKeyName,
	DWORD  dwLegacyKeySpec,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptCreatePersistedKey(
	NCRYPT_PROV_HANDLE hProvider,
	NCRYPT_KEY_HANDLE *phKey,
	LPCWSTR pszAlgId,
	LPCWSTR pszKeyName,
	DWORD   dwLegacyKeySpec,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptGetProperty(
	NCRYPT_HANDLE hObject,
	LPCWSTR pszProperty,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptSetProperty(
	NCRYPT_HANDLE hObject,
	LPCWSTR pszProperty,
    PBYTE pbInput,
	DWORD   cbInput,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS NCryptFinalizeKey(NCRYPT_KEY_HANDLE hKey, DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptEncrypt(
	NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
	DWORD   cbInput,
	void *pPaddingInfo,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	DWORD   dwFlags);


SECURITY_STATUS
NCryptDecrypt(
	NCRYPT_KEY_HANDLE hKey,
    PBYTE pbInput,
	DWORD   cbInput,
	void *pPaddingInfo,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptImportKey(
	NCRYPT_PROV_HANDLE hProvider,
	NCRYPT_KEY_HANDLE hImportKey,
	LPCWSTR pszBlobType,
	NCryptBufferDesc *pParameterList,
	NCRYPT_KEY_HANDLE *phKey,
    PBYTE pbData,
	DWORD   cbData,
	DWORD   dwFlags);




SECURITY_STATUS
NCryptExportKey(
	NCRYPT_KEY_HANDLE hKey,
	NCRYPT_KEY_HANDLE hExportKey,
	LPCWSTR pszBlobType,
	NCryptBufferDesc *pParameterList,
    PBYTE pbOutput,
	DWORD   cbOutput,
	DWORD * pcbResult,
	DWORD   dwFlags);
]]


ffi.cdef[[

SECURITY_STATUS
NCryptSignHash(
	NCRYPT_KEY_HANDLE hKey,
	void *pPaddingInfo,
    PBYTE pbHashValue,
	DWORD   cbHashValue,
    PBYTE pbSignature,
	DWORD   cbSignature,
	DWORD * pcbResult,
	DWORD   dwFlags);

SECURITY_STATUS
NCryptVerifySignature(
	NCRYPT_KEY_HANDLE hKey,
	void *pPaddingInfo,
    PBYTE pbHashValue,
	DWORD   cbHashValue,
    PBYTE pbSignature,
	DWORD   cbSignature,
	DWORD   dwFlags);
]]

ffi.cdef[[
SECURITY_STATUS
NCryptDeleteKey(NCRYPT_KEY_HANDLE hKey, DWORD   dwFlags);

SECURITY_STATUS NCryptFreeObject(NCRYPT_HANDLE hObject);

BOOL NCryptIsKeyHandle(NCRYPT_KEY_HANDLE hKey);

SECURITY_STATUS NCryptTranslateHandle(
	NCRYPT_PROV_HANDLE *phProvider,
	NCRYPT_KEY_HANDLE *phKey,
	HCRYPTPROV hLegacyProv,
	HCRYPTKEY hLegacyKey,
	DWORD  dwLegacyKeySpec,
	DWORD   dwFlags);
]]

ffi.cdef[[

SECURITY_STATUS
NCryptNotifyChangeKey(
	NCRYPT_PROV_HANDLE hProvider,
	HANDLE *phEvent,
	DWORD   dwFlags);

SECURITY_STATUS
NCryptSecretAgreement(
	NCRYPT_KEY_HANDLE hPrivKey,
	NCRYPT_KEY_HANDLE hPubKey,
	NCRYPT_SECRET_HANDLE *phAgreedSecret,
	DWORD   dwFlags);

SECURITY_STATUS
NCryptDeriveKey(
	NCRYPT_SECRET_HANDLE hSharedSecret,
	LPCWSTR              pwszKDF,
	NCryptBufferDesc     *pParameterList,
    PBYTE pbDerivedKey,
	DWORD                cbDerivedKey,
	DWORD                *pcbResult,
	ULONG                dwFlags);
]]

return NCrypt
