local ffi = require"ffi"
local Kernel32 = require "Kernel32"



StopWatch = {}
StopWatch_mt = {
	__index = StopWatch;
}

StopWatch.new = function()
	local obj = {
		Frequency = 0;
		StartCount = 0;
	}

	setmetatable(obj, StopWatch_mt);

	StopWatch.Reset(obj);

	return obj
end

function StopWatch:__tostring()
	return string.format("Frequency: %d  Count: %d", self.Frequency, self.StartCount)
end



--[[
/// <summary>
/// Reset the startCount, which is the current tick count.
/// This will reset the elapsed time because elapsed time is the
/// difference between the current tick count, and the one that
/// was set here in the Reset() call.
/// </summary>
--]]

function StopWatch:Reset()
	self.Frequency = 1/Kernel32.GetPerformanceFrequency();
	self.StartCount = Kernel32.GetPerformanceCounter();
end

-- <summary>
-- Return the number of seconds that elapsed since Reset() was called.
-- </summary>
-- <returns>The number of elapsed seconds.</returns>

function StopWatch:Seconds()
	local ellapsed = Kernel32.GetPerformanceCounter() - self.StartCount
	local seconds = ellapsed * self.Frequency;

	return seconds
end

function StopWatch:Milliseconds()
	return self:Seconds() * 1000
end


