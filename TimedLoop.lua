local bit = require "bit"
local bor = bit.bor

local ffi = require "ffi"
local C = ffi.C

local U32 = require "User32"

require "kernel32"
require "StopWatch"


jit.off(Loop)
function TimedLoop(callback, frequency, params)
	local timerEvent = C.CreateEventA(nil, false, false, nil)
	-- If the timer event was not created
	-- just return
	if timerEvent == nil then
		error("unable to create timer")
		return
	end

	local handleCount = 1
	local handles = ffi.new('void*[1]', {timerEvent})

	local sw = StopWatch.new()
	local tickCount = 1
	local timeleft = 0
	local lastTime = sw:Milliseconds()
	local interval = 1/frequency;
	local nextTime = lastTime + interval * 1000

	local dwFlags = bor(U32.FFI.MWMO_ALERTABLE,U32.FFI.MWMO_INPUTAVAILABLE)

	while (true) do
		timeleft = nextTime - sw:Milliseconds();
		if (timeleft <= 0.001) then
			callback(tickCount, params);
			tickCount = tickCount + 1
			nextTime = nextTime + interval * 1000
			timeleft = nextTime - sw:Milliseconds();
		end

		if timeleft < 0 then 
			timeleft = 0 
		end

		-- use an alertable wait
		C.MsgWaitForMultipleObjectsEx(handleCount, handles, timeleft, U32.FFI.QS_ALLEVENTS, dwFlags)
	end
end

return TimedLoop;
