package.path = package.path..";../?.lua"

local ffi = require "ffi"
--require "kernel32_ffi"

ffi.C.Sleep(3000);
