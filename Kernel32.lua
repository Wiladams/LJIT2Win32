

local kernel32_ffi = require"kernel32_ffi"
local Lib = ffi.load("kernel32")

local ffi = require "ffi"
local C = ffi.C

function GetPerformanceFrequency()
	local anum = ffi.new("__int64[1]")
	local success = ffi.C.QueryPerformanceFrequency(anum)
	if success == 0 then
		return nil
	end

	return tonumber(anum[0])
end

function GetPerformanceCounter()
	local anum = ffi.new("__int64[1]")
	local success = ffi.C.QueryPerformanceCounter(anum)
	if success == 0 then
		return nil
	end

	return tonumber(anum[0])
end

function GetCurrentTickTime()
	local frequency = 1/GetPerformanceFrequency();
	local currentCount = GetPerformanceCounter();
	local seconds = currentCount * frequency;

	return seconds;
end


function GetProcAddress(library, funcname)
	ffi.load(library)
	local paddr = ffi.C.GetProcAddress(C.GetModuleHandleA(library), funcname)

	return paddr
end

function GetCurrentDirectory()
	local buffsize = 1024;
	local buff = ffi.new("char[1024]");
	local err = kernel32.GetCurrentDirectoryA(buffsize, buff);

	if err == 0 then
		return nil
	end

	return ffi.string(buff);
end

local CP_ACP 		= 0		-- default to ANSI code page
local CP_OEMCP		= 1		-- default to OEM code page
local CP_MACCP		= 2		-- default to MAC code page
local CP_THREAD_ACP	= 3		-- current thread's ANSI code page
local CP_SYMBOL		= 42	-- SYMBOL translations


local function AnsiToUnicode16L(in_Src)
	local nsrcBytes = #in_Src

	-- find out how many characters needed
	local charsneeded = kernel32.MultiByteToWideChar(CP_ACP, 0, in_Src, nsrcBytes, nil, 0);
--print("charsneeded: ", nsrcBytes, charsneeded);

	if charsneeded < 0 then
		return nil;
	end


	local buff = ffi.new("uint16_t[?]", charsneeded+1)

	local charswritten = kernel32.MultiByteToWideChar(CP_ACP, 0, in_Src, nsrcBytes, buff, charsneeded)
	buff[charswritten] = 0

--print("charswritten: ", charswritten)

	return ffi.string(buff, (charswritten*2)+1);
end

local function AnsiToUnicode16L(in_Src, nsrcBytes)
	nsrcBytes = nsrcBytes or #in_Src

	-- find out how many characters needed
	local charsneeded = kernel32.MultiByteToWideChar(CP_ACP, 0, in_Src, nsrcBytes, nil, 0);
--print("charsneeded: ", nsrcBytes, charsneeded);

	if charsneeded < 0 then
		return nil;
	end


	local buff = ffi.new("uint16_t[?]", charsneeded+1)

	local charswritten = kernel32.MultiByteToWideChar(CP_ACP, 0, in_Src, nsrcBytes, buff, charsneeded)
	buff[charswritten] = 0

--print("charswritten: ", charswritten)

	return buff;
end

local function Unicode16ToAnsi(in_Src, nsrcBytes)
	nsrcBytes = nsrcBytes
	local srcShorts = ffi.cast("const uint16_t *", in_Src)

	-- find out how many characters needed
	local bytesneeded = kernel32.WideCharToMultiByte(CP_ACP, 0, srcShorts, -1, nil, 0, nil, nil);
print("bytesneeded: ", bytesneeded);

	if bytesneeded <= 0 then
		return nil;
	end

	local buff = ffi.new("uint8_t[?]", bytesneeded+1)
	local byteswritten = kernel32.WideCharToMultiByte(CP_ACP, 0, srcShorts, -1, buff, bytesneeded, nil, nil);
	buff[byteswritten] = 0

--print("charswritten: ", byteswritten)

	return ffi.string(buff, byteswritten-1);
end



return {
	NativeCall = Lib,
	GetPerformanceFrequency = GetPerformanceFrequency,
	GetPerformanceCounter = GetPerformanceCounter,
	GetCurrentTickTime = GetCurrentTickTime,
	GetProcAddress = GetProcAddress,
	GetCurrentDirectory = GetCurrentDirectoryA,
	
	AnsiToUnicode16 = AnsiToUnicode16L,
	Unicode16ToAnsi = Unicode16ToAnsi,

}
