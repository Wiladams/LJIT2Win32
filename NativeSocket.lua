
local ffi = require "ffi"

local WinSock = require "WinSock_Utils"
local wsock = require "win_socket"
local SocketType = wsock.SocketType
local Protocol = wsock.Protocol

ffi.cdef[[
typedef struct {
	SOCKET				Handle;
	int					id;
} Socket_Win32;
]]


local NativeSocket = ffi.typeof("Socket_Win32");
local NativeSocket_mt = {
	__gc = function(self)
		-- Force close on socket
		-- To ensure it's really closed
		print("GC: NativeSocket: ", self.id);
		self:ForceClose();
	end,
	
	__new = function(ct, handle, family, socktype, protocol, flags)
		family = family or AF_INET;
		socktype = socktype or SocketType.SOCK_STREAM;
		protocol = protocol or 0;
		flags = flags or WSA_FLAG_OVERLAPPED;
		
		if not handle then
			handle, err = WinSock.WSASocket(family, socktype, protocol, nil, 0, WSA_FLAG_OVERLAPPED);
			if not handle then
				return nil, err
			end
		end
				
		return ffi.new(ct, handle);
	end,
	
	__index = {
		--[[
			Setting various options
		--]]
		SetKeepAlive = function(self, keepalive, delay)
			local oneint = ffi.new("int[1]");
			if keepalive then
				oneint[0] = 1
			end

			local success, err =  WinSock.setsockopt(self.Handle, SOL_SOCKET, SO_KEEPALIVE, oneint, ffi.sizeof(oneint))
			if not success then 
				return false, err
			end

			if keepalive and delay then
				oneint[0] = delay
				success, err = WinSock.setsockopt(self.Handle, Protocol.IPPROTO_TCP, TCP_KEEPALIVE, oneint, ffi.sizeof(oneint))
			end

			return success, err
		end,

		SetNoDelay = function(self, nodelay)
			local oneint = ffi.new("int[1]");
			if nodelay then
				oneint[0] = 1
			end

			return WinSock.setsockopt(self.Handle, Protocol.IPPROTO_TCP, TCP_NODELAY, oneint, ffi.sizeof(oneint))
		end,
		
		SetNonBlocking = function(self, nonblocking)
			local oneint = ffi.new("int[1]");
			if nonblocking then
				oneint[0] = 1
			end

			return WinSock.ioctlsocket(self.Handle, FIONBIO, oneint);
		end,
		
		SetReuseAddress = function(self, reuse)
			local oneint = ffi.new("int[1]");
			if reuse then
				oneint[0] = 1
			end

			return WinSock.setsockopt(self.Handle, SOL_SOCKET, SO_REUSEADDR, oneint, ffi.sizeof(oneint))
		end,
		

		
		--[[
			Connection Management
		--]]
		CloseDown = function(self)
			local success, err = WinSock.shutdown(self.Handle, SD_SEND)
			if not success then
				return false, err
			end

			return WinSock.closesocket(self.Handle);
		end,

		ForceClose = function(self)
			return WinSock.closesocket(self.Handle);
		end,
		
		Shutdown = function(self, how)
			how = how or SD_SEND
			
			return WinSock.shutdown(self.Handle, how)
		end,
		
		ShutdownReceive = function(self)
			return WinSock.shutdown(self.Handle, SD_RECEIVE)
		end,

		ShutdownSend = function(self)
			return WinSock.shutdown(self.Handle, SD_SEND)
		end,

		--[[
			Client Socket Routines
		--]]
		ConnectTo = function(self, address)
			local name = ffi.cast("const struct sockaddr *", address)
			local namelen = ffi.sizeof(address)
			return WinSock.connect(self.Handle, name, namelen);
		end,

		--[[
			Server socket routines
		--]]
		MakePassive = function(self, backlog)
			backlog = backlog or 5
			return WinSock.listen(self.Handle, backlog)
		end,

		Accept = function(self)
			local handle, err =  WinSock.accept(self.Handle, nil, nil);

			if not handle then
				return false, err
			end
			
			return NativeSocket(handle)
		end,
		
		Bind = function(self, addr, addrlen)
			return WinSock.bind(self.Handle, addr, addrlen)
		end,
		
		--[[
			Data Transport
		--]]
		CanReadWithoutBlocking = function(self)
			local fdarray = WSAPOLLFD()
			fdarray.fd = self.Handle;
			fdarray.events = POLLRDNORM;

			-- wait up to 15 milliseconds to see if there's
			-- anything waiting
			local success, err = WinSock.WSAPoll(fdarray, 1, 15);
			
			if not success then
				return false, err
			end
			
			if success > 0 then
				return true;
			end

			return false, "wouldblock";
		end,
		
		CanWriteWithoutBlocking = function(self)
			local fdarray = WSAPOLLFD()
			fdarray.fd = self.Handle;
			fdarray.events = POLLWRNORM;

			local success, err = WinSock.WSAPoll(fdarray, 1, 15);
			if not success then
				return false, err
			end

			if ret == 0 then
				return false, "wouldblock"
			end

			return true
		end,

		Send = function(self, buff, bufflen)
			bufflen = bufflen or #buff

			return WinSock.send(self.Handle, buff, bufflen);
		end,

		Receive = function(self, buff, bufflen)
			return WinSock.recv(self.Handle, buff, bufflen);
		end,
	},
}
NativeSocket = ffi.metatype(NativeSocket, NativeSocket_mt);


return NativeSocket;