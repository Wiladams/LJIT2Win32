
local ffi = require "ffi"
require "WTypes"
require "WinBase"
local Kernel32 = require "Kernel32"

ffi.cdef[[
struct IODevice {
	HANDLE Handle;
};
]]

local IODevice = ffi.typeof("struct IODevice")
local IODevice_mt = {
	__gc = function(self)
		
	end,
	
	__index = {
		CancelIo = function(self)
		end,
		
		Lock = function(self)
		end,
		
	},
}
ffi.metatype(IODevice, IODevice_mt);

local modes = {
	["r"] = GENERIC_READ,
	["r+"] = bor(GENERIC_READ, GENERIC_WRITE),
	["w"] = GENERIC_WRITE,
	["w+"] = bor(GENERIC_WRITE, GENERIC_READ),
	["a"] = bor(APPEND, CREAT, GENERIC_WRITE),
	["a+"] = APPEND
}

local function string_to_access(mode) 
	return modes[mode] or bor(GENERIC_READ, GENERIC_WRITE);
--[[
	if (strcmp(string, "w") == 0) 
		return O_CREAT | O_TRUNC | O_WRONLY;  
	if (strcmp(string, "w+") == 0) 
		return O_CREAT | O_TRUNC | O_RDWR;  
	if (strcmp(string, "a") == 0) 
		return O_APPEND | O_CREAT | O_WRONLY;  
	if (strcmp(string, "a+") == 0) 
		return O_APPEND | O_CREAT | O_RDWR;
#ifndef _WIN32  
	if (strcmp(string, "rs") == 0) 
		return O_RDONLY | O_SYNC;  
	if (strcmp(string, "rs+") == 0) 
		return O_RDWR | O_SYNC;
#endif  
--]]
end


local FileSystem = {
	CopyFile = function(src, dest, progress)
	end,
	
	CreateFile = function(filename, access)
		local access, mode = string_to_access(access)

		local handle, err = Kernel32.CreateFile(filename,
  _In_      DWORD dwDesiredAccess,
  _In_      DWORD dwShareMode,
  _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  _In_      DWORD dwCreationDisposition,
  _In_      DWORD dwFlagsAndAttributes,
  _In_opt_  HANDLE hTemplateFile
);
	end,
	
}

-- mode_t

function open()
end

function close()
end

function read()
end

function write()
end



int luv_fs_mkdir(lua_State* L);
int luv_fs_rmdir(lua_State* L);
int luv_fs_readdir(lua_State* L);

int luv_fs_stat(lua_State* L);
int luv_fs_fstat(lua_State* L);
int luv_fs_lstat(lua_State* L);

int luv_fs_rename(lua_State* L);
int luv_fs_fsync(lua_State* L);
int luv_fs_fdatasync(lua_State* L);
int luv_fs_ftruncate(lua_State* L);
int luv_fs_sendfile(lua_State* L);

int luv_fs_chmod(lua_State* L);
int luv_fs_fchmod(lua_State* L);

int luv_fs_utime(lua_State* L);
int luv_fs_futime(lua_State* L);

int luv_fs_symlink(lua_State* L);
int luv_fs_readlink(lua_State* L);
int luv_fs_chown(lua_State* L);
int luv_fs_fchown(lua_State* L);

int luv_fs_link(lua_State* L);
int luv_fs_unlink(lua_State* L);
