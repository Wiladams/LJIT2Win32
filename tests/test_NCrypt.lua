package.path = package.path..";../?.lua"

local ncr = require "ncrypt"
local NCrypt = require "NCryptUtils"

local provider = NCryptStorageProvider();
print(provider);

function test_EnumAlgorithms(provider)
	local algos = provider:EnumerateAlgorithms();

	for i, algo in ipairs(algos) do
		print(algo.name, algo.class);
	end
end

function test_GetAllKeys(provider)
	local keys = provider:GetAllKeys(ncr.NCRYPT_MACHINE_KEY_FLAG);
--	local keys = provider:GetAllKeys();

	print(keys, #keys);

	for i,key in ipairs(keys) do
		print(key.name, key.algoid);
	end
end

--test_EnumAlgorithms(provider);

test_GetAllKeys(provider);
