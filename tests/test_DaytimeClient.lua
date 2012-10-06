package.path = package.path..";..\\?.lua";

local DaytimeClient = require "DaytimeClient"

for i=1, 500 do
	local dtc = DaytimeClient.new("localhost")
	dtc:Run()
end
