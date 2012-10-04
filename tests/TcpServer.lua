
local SocketUtils = require "SocketUtils"


local function Run(config, acceptcallback)
	local port = config.port or 13
	local ServerSocket, err = SocketUtils.CreateTcpServerSocket({port = port, backlog = 15, nonblocking=false, nodelay = false});
	
	if not ServerSocket or not acceptcallback then 
		return false, err
	end
	
	print("Daytime Server Running")
	local acceptedsock = nil
	while (true) do
		acceptedsock, err = ServerSocket:Accept()

		if acceptedsock then
			acceptcallback(acceptedsock)
		end
	end
end

return {
	Startup = Run,
}
