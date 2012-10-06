package.path = package.path..";..\\?.lua;..\\core\\?.lua";

local port = 9091

server = require "TcpServer"

local cnt = 1

local acceptcallback = function(acceptedsock)	
	acceptedsock.id = cnt
	cnt = cnt + 1
	acceptedsock:Send(os.date("%c"));
	acceptedsock:Send("\r\n");
			
	acceptedsock:CloseDown()
end

local idlecnt = 1;
local idlecallback = function()
	-- call the GC for every 500 connections
	if cnt >= 500 then
		print("Calling GC: ", idlecnt);
		collectgarbage();
		cnt = 0
	end
	idlecnt = idlecnt + 1
end

server.Startup({port = 9091, nonblocking=true, nodelay=false}, acceptcallback, idlecallback);
