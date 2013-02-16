package.path = package.path..";../?.lua"

local ffi = require "ffi"

local BCrypt = require "BCryptUtils"


function test_RngAlgorithm()
	local rngalgo = BCrypt.BCryptAlgorithm(BCrypt.BCRYPT_RNG_ALGORITHM)

	print("Algo: ",rngalgo);
end


function test_RandomBytes()
	for j=1,5 do
		local rngBuff, err = BCrypt.GetRandomBytes()

		print("Status: ", rngBuff, status);

		local buffLen = ffi.sizeof(rngBuff)

		for i=0,buffLen do
			print(rngBuff[i])
		end
		print("--");
	end
end



function test_digests()

	local content = "Take this as the first input to be hashed"

	print("SHA1: ", BCrypt.SHA1(content));
	print("SHA256: ", BCrypt.SHA256(content));
	print("SHA384: ", BCrypt.SHA384(content));
	print("SHA512: ", BCrypt.SHA512(content));

	print("MD2: ", BCrypt.MD2(content));
	print("MD4: ", BCrypt.MD4(content));
	print("MD5: ", BCrypt.MD5(content));

end


--test_RandomBytes();

test_digests();
