local ffi = require "ffi"
local bit = require "bit"
local bor = bit.bor

local WinError = require "WinError"

local NCrypt = require "ncrypt"
local NCLib = ffi.load("ncrypt")
local k32 = require "Kernel32"

local L = k32.AnsiToUnicode16
local A = k32.Unicode16ToAnsi

NCryptKeyName = ffi.typeof("NCryptKeyName");
NCryptKeyName_mt = {
	__gc = function(self)
		NCLib.NCryptFreeBuffer(self);
	end,

}
NCryptKeyName = ffi.metatype(NCryptKeyName, NCryptKeyName_mt);

ffi.cdef[[
typedef struct {
	NCRYPT_PROV_HANDLE	Handle;
} NCryptStorageProvider;
]]

NCryptStorageProvider = ffi.typeof("NCryptStorageProvider")
NCryptStorageProvider_mt = {
	__gc = function(self)
		NCLib.NCryptFreeObject(self.Handle);
	end,

	__new = function(ct, pszProviderName)
		local phProvider = ffi.new("NCRYPT_PROV_HANDLE[1]");
		local pszProviderName = nil;

		local status = NCLib.NCryptOpenStorageProvider(phProvider,
			pszProviderName, 0);

		if status ~= 0 then
			return nil, status
		end

		local obj = ffi.new("NCryptStorageProvider", phProvider[0]);

		return obj;
	end,

	__index = {
		EnumerateAlgorithms = function(self, whichones)
			whichones = whichones or bor(
				NCrypt.NCRYPT_CIPHER_OPERATION,
				NCrypt.NCRYPT_HASH_OPERATION,
				NCrypt.NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION,
				NCrypt.NCRYPT_SECRET_AGREEMENT_OPERATION,
				NCrypt.NCRYPT_SIGNATURE_OPERATION);

			local pdwAlgCount = ffi.new("uint32_t[1]");
			local ppAlgList = ffi.new("PNCryptAlgorithmName[1]");

			local status = NCLib.NCryptEnumAlgorithms(self.Handle,
				whichones,
				pdwAlgCount,
				ppAlgList,
				0);

			if status ~= 0 then
				return nil, status
			end

			-- Create a list with the algoritm
			-- names in it
			local res = {}
			local AlgList = ppAlgList[0];
			for i=0,pdwAlgCount[0]-1 do
				local entry = {
					name = A(AlgList[i].pszName),
					class = AlgList[i].dwClass,
					operations = AlgList[i].dwAlgOperations,
				}
				table.insert(res, entry);
			end
			return res
		end,

		IsAlgorithmSupported = function(self, algoname)
		end,

		GetAllKeys = function(self, flags)
			flags = flags or 0

			local res = {}
			local ppKeyName = ffi.new("PNCryptKeyName[1]");
			local ppEnumState = ffi.new("PVOID[1]");
			local status
			local dwFlags = flags;

			repeat
				local pszScope = nil
				status = NCLib.NCryptEnumKeys(self.Handle,
					pszScope,ppKeyName,ppEnumState,dwFlags);

				if status == 0 then
					local pKeyName = ppKeyName[0]
					local entry = {
						name = A(pKeyName.pszName),
						algoid = A(pKeyName.pszAlgid),
					}

					table.insert(res, entry);
				end
			until status ~= 0

			print(string.format("0x%x", status))
			print(string.format("Status: 0x%x  0x%x   0x%x", HRESULT_PARTS(status)))

			return res;
		end,

	},

}
NCryptStorageProvider = ffi.metatype(NCryptStorageProvider, NCryptStorageProvider_mt);



return {
	NCryptStorageProvider = NCryptStorageProvider,
}
