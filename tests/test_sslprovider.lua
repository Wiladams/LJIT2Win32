package.path = package.path..";../?.lua"

local ffi = require "ffi"

local SSL = require "sslprovider"
local k32 = require "Kernel32"

A = k32.Unicode16ToAnsi

function test_SslEnumProtocolProviders()
	local pdwProviderCount = ffi.new("uint32_t[1]");
	local ppProviderList = ffi.new("PNCryptProviderName[1]");
	local dwFlags = 0;

	local status = SSL.Lib.SslEnumProtocolProviders(pdwProviderCount, ppProviderList, dwFlags);

	if status ~= 0 then
		print("FAIL: ", status)
		return
	end

	local count = pdwProviderCount[0];

	print("Provider Count: ", count);


	for i=0,count-1 do
		local pName = ppProviderList[i];
		local name = A(pName.pszName);
		local comment = A(pName.pszComment);

		print("Protocol Provider: ", name, comment);
	end

end

SSLFactory = {}
SSLFactory_mt = {
	__index = SSLFactory,
}

SSLFactory.GetInterface = function(providerName)
	providerName = providerName or SSL.MS_SCHANNEL_PROVIDER
	local ppFunctionTable = ffi.new("PNCRYPT_SSL_FUNCTION_TABLE[1]");
	local dwFlags = 0;

	local status = SSL.Lib.GetSChannelInterface(SSL.MS_SCHANNEL_PROVIDER, ppFunctionTable, dwFlags);

	if status ~= 0 then
		return nil
	end

	local functionTable = ppFunctionTable[0]

	local obj = {
		VTable = functionTable;
		ProviderName = providerName
	}
	setmetatable(obj, SSLFactory_mt);

	return obj
end

function SSLFactory:OpenProvider()
	local phSslProvider = ffi.new("NCRYPT_PROV_HANDLE[1]");
	local dwFlags = 0;

	local status = self.VTable.SslOpenProvider(phSslProvider, self.ProviderName, dwFlags);

	if status ~= 0 then
		return nil, status
	end

	return SSLProvider(phSslProvider[0])
end


function test_GetInterface()
	local sslI = SSLFactory.GetInterface()

	if not sslI then
		print("FAIL");
		return
	end

	local provider, err = sslI:OpenProvider()

	if not provider then
		print("FAIL");
	end


end

--test_SslEnumProtocolProviders();

test_GetInterface();
