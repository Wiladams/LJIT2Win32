
local SocketUtils = require "SocketUtils"


local function Run(config, acceptcallback, idlecallback)
	local nonblocking = config.nonblocking
	local nodelay = config.nodelay
	
	local ServerSocket, err = SocketUtils.CreateTcpServerSocket({port = config.port or 80, backlog = config.backlock or 15, nonblocking=nonblocking, nodelay = nodelay});
	
	if not ServerSocket or not acceptcallback then 
		return false, err
	end
	
	print("Server Running")
	local acceptedsock = nil
	while (true) do
		acceptedsock, err = ServerSocket:Accept()

		if acceptedsock then
			acceptcallback(acceptedsock)
		elseif idlecallback then
			idlecallback();
		end
	end
end

return {
	Startup = Run,
}
