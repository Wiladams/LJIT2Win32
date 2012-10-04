package.path = package.path..";..\\Bhut\\?.lua;..\\Bhut\\core\\?.lua";

local DaytimeClient = require "DaytimeClient"

for i=1, 50 do
	local dtc = DaytimeClient.new("localhost")
	dtc:Run()
end
