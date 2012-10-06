local ffi = require "ffi"

local NativeSocket = require "NativeSocket"
local SocketUtils = require "SocketUtils"

local daytimeport = 9091

DaytimeClient = {}
DaytimeClient_mt = {
	__index = DaytimeClient,
}

function DaytimeClient.new(hostname, port)
    hostname = hostname or "localhost";
    port = port or daytimeport;

	local self = {}
    self.Socket, err = CreateTcpClientSocket(hostname, port);
	
	if not self.Socket then
		print("DaytimeClient.new(), error: ", err);
		return false, err;
	end
	
	self.Socket:SetNonBlocking(false);
	setmetatable(self, DaytimeClient_mt)
	
	return self;
end

function DaytimeClient:Run()
    local bufflen = 256
    local buff = ffi.new("char [256]")

	print("client about to receive");
    n, err = self.Socket:Receive(buff, bufflen)
	print("client received: ", n);
    while (n > 0) do
        buff[n] = 0		-- null terminated
        print(ffi.string(buff))

        n = self.Socket:Receive(buff, bufflen)
    end
end

return DaytimeClient
