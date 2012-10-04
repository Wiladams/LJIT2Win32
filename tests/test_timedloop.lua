package.path = package.path..";..\\?.lua;..\\core\\?.lua";

local TimedLoop = require "TimedLoop"
require "StopWatch"

local sw = StopWatch.new()

function callback(tickCount, params)
	print("callback: ", tickCount, tickCount/sw:Seconds())
	
	--[[
	local msg = ffi.new("MSG")

	while (user32.PeekMessageA(msg, nil, 0, 0, C.PM_REMOVE) ~= 0) do
		user32.TranslateMessage(msg)
		user32.DispatchMessageA(msg)

		if msg.message == C.WM_QUIT then
			return win:OnQuit()
		end
	end
--]]
end


local fps = arg[1] or 1


local looper = TimedLoop(callback, fps);
