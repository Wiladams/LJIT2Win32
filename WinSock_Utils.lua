
local ffi = require "ffi"

local wsock = require "win_socket"
local SocketType = wsock.SocketType
local Protocol = wsock.Protocol
local Family = wsock.Family

-- Startup windows sockets
local SocketLib = ffi.load("ws2_32")

--[[
	Casual Macros
--]]

function IN4_CLASSA(i)
	return (band(i, 0x00000080) == 0)
end

function IN4_CLASSB(i)
	return (band(i, 0x000000c0) == 0x00000080)
end

function IN4_CLASSC(i)
	return (band(i, 0x000000e0) == 0x000000c0)
end

function IN4_CLASSD(i)
	return (band(i, 0x000000f0) == 0x000000e0)
end

IN4_MULTICAST = IN4_CLASSD


--[[
	Data Structures
--]]

IN_ADDR = ffi.typeof("struct in_addr");
IN_ADDR_mt = {
	__gc = function (self)
		print("-- IN_ADDR: GC");
	end,

	__tostring = function(self)
		local res = SocketLib.inet_ntoa(self)
		if res then
			return ffi.string(res)
		end

		return nil
	end,

	__index = {
		Assign = function(self, rhs)
		--print("IN_ADDR Assign: ", rhs.s_addr)
			self.S_addr = rhs.S_addr
			return self
		end,

		Clone = function(self)
			local obj = IN_ADDR(self.S_addr)
			return obj
		end,

--[[
		SetFromString = function(self, src)
			local tmpptr = ffi.new("struct in_addr[1]")
			wsock.inet_pton(AF_INET, src, tmpptr);
			self:Assign(tmpptr[0])

			return self
		end,
--]]
	},
}
IN_ADDR = ffi.metatype(IN_ADDR, IN_ADDR_mt)


local families = {
	[Family.AF_INET] = "AF_INET",
	[Family.AF_INET6] = "AF_INET6",
}

local socktypes = {
	[SocketType.SOCK_STREAM] = "SOCK_STREAM",
	[SocketType.SOCK_DGRAM] = "SOCK_DGRAM",
}

local protocols = {
	[Protocol.IPPROTO_IP]  = "IPPROTO_IP",
	[Protocol.IPPROTO_TCP] = "IPPROTO_TCP",
	[Protocol.IPPROTO_UDP] = "IPPROTO_UDP",
}


sockaddr_in = ffi.typeof("struct sockaddr_in")
sockaddr_in_mt = {
	__gc = function (self)
		--print("GC: sockaddr_in");
	end,

	__new = function(ct, port, family)
		port = port or 80
		family = family or Family.AF_INET;
		
		local obj = ffi.new(ct)
		obj.sin_family = family;
		obj.sin_addr.S_addr = SocketLib.htonl(INADDR_ANY);
		obj.sin_port = SocketLib.htons(port);
		
		return obj
	end,
	
	__tostring = function(self)
		return string.format("Family: %s  Port: %d Address: %s",
			families[self.sin_family], SocketLib.ntohs(self.sin_port), tostring(self.sin_addr));
	end,

	__index = {
		SetPort = function(self, port)
			self.sin_port = SocketLib.htons(port);
		end,
	},
}
sockaddr_in = ffi.metatype(sockaddr_in, sockaddr_in_mt);

sockaddr_in6 = ffi.typeof("struct sockaddr_in6")
sockaddr_in6_mt = {
	__gc = function (self)
		print("-- sockaddr_in6: GC");
	end,

	__tostring = function(self)
		return string.format("Family: %s  Port: %d Address: %s",
			families[self.sin6_family], self.sin6_port, tostring(self.sin6_addr));
	end,

	__index = {
		SetPort = function(self, port)
			self.sin6_port = SocketLib.htons(port);
		end,
	},
}
sockaddr_in6 = ffi.metatype(sockaddr_in6, sockaddr_in6_mt);


sockaddr = ffi.typeof("struct sockaddr")
sockaddr_mt = {
	__index = {
	}
}
sockaddr = ffi.metatype(sockaddr, sockaddr_mt);


addrinfo = nil
addrinfo_mt = {
	__tostring = function(self)
		local family = families[self.ai_family]
		local socktype = socktypes[self.ai_socktype]
		local protocol = protocols[self.ai_protocol]

		--local family = self.ai_family
		local socktype = self.ai_socktype
		local protocol = self.ai_protocol


		local str = string.format("Socket Type: %s, Protocol: %s, %s", socktype, protocol, tostring(self.ai_addr));

		return str
	end,

	__index = {
		Print = function(self)
			print("-- AddrInfo ==")
			print("Flags: ", self.ai_flags);
			print("Family: ", families[self.ai_family])
			print("Sock Type: ", socktypes[self.ai_socktype]);
			print("Protocol: ", protocols[self.ai_protocol]);
			print("Canon Name: ", self.ai_canonname);
			--print("Addr Len: ", self.ai_addrlen);
			--print("Address: ", self.ai_addr);
			--print("Address Family: ", self.ai_addr.sa_family);
			local addr
			if self.ai_addr.sa_family == Family.AF_INET then
				addr = ffi.cast("struct sockaddr_in *", self.ai_addr)
			elseif self.ai_addr.sa_family == Family.AF_INET6 then
				addr = ffi.cast("struct sockaddr_in6 *", self.ai_addr)
			end
			print(addr);

			if self.ai_next ~= nil then
				self.ai_next:Print();
			end
		end,
	},
}
addrinfo = ffi.metatype("struct addrinfo", addrinfo_mt)




--[[
	BSD Style functions
--]]
local accept = function(s, addr, addrlen)
	local socket = SocketLib.accept(s,addr,addrlen);
	if socket == INVALID_SOCKET then
		return false, SocketLib.WSAGetLastError();
	end
	
	return socket;
end

local bind = function(s, name, namelen)
	if 0 == SocketLib.bind(s, ffi.cast("const struct sockaddr *",name), namelen) then
		return true;
	end
	
	return false, WinSock.WSAGetLastError();
end

local connect = function(s, name, namelen)
	if 0 == SocketLib.connect(s, ffi.cast("const struct sockaddr *", name), namelen) then
		return true
	end
	
	return false, SocketLib.WSAGetLastError();
end

local closesocket = function(s)
	if 0 == SocketLib.closesocket(s) then
		return true
	end
	
	return false, SocketLib.WSAGetLastError();
end

local ioctlsocket = function(s, cmd, argp)
	if 0 == SocketLib.ioctlsocket(s, cmd, argp) then
		return true
	end
	
	return false, SocketLib.WSAGetLastError();
end

local listen = function(s, backlog)
	if 0 == SocketLib.listen(s, backlog) then
		return true
	end
	
	return false, SocketLib.WSAGetLastError();
end

local recv = function(s, buf, len, flags)
	len = len or #buf;
	flags = flags or 0;
	
	local bytesreceived = SocketLib.recv(s, ffi.cast("char*", buf), len, flags);

	if bytesreceived == SOCKET_ERROR then
		return false, SocketLib.WSAGetLastError();
	end
	
	return bytesreceived;
end

local send = function(s, buf, len, flags)
	len = len or #buf;
	flags = flags or 0;
	
	local bytessent = SocketLib.send(s, ffi.cast("const char*", buf), len, flags);

	if bytessent == SOCKET_ERROR then
		return false, SocketLib.WSAGetLastError();
	end
	
	return bytessent;
end

local setsockopt = function(s, optlevel, optname, optval, optlen)
	if 0 == SocketLib.setsockopt(s, optlevel, optname, ffi.cast("const uint8_t *", optval), optlen) then
		return true
	end
	
	return false, SocketLib.WSAGetLastError();
end

local shutdown = function(s, how)
	how = how or SD_BOTH
	
	if 0 == SocketLib.shutdown(s, how) then
		return true
	end
	
	return false, SocketLib.WSAGetLastError();
end

local socket = function(af, socktype, protocol)
	af = af or Family.AF_INET
	socktype = socktype or SocketType.SOCK_STREAM
	protocol = protocol or Protocol.IPPROTO_TCP
	
	local sock = SocketLib.socket(af, socktype, protocol);
	if sock == INVALID_SOCKET then
		return false, SocketLib.WSAGetLastError();
	end
	
	return sock;
end

--[[
	Windows Specific Socket routines
--]]
local WSAIoctl = function(s,dwIoControlCode,lpvInBuffer,cbInBuffer,lpvOutBuffer,cbOutBuffer,lpcbBytesReturned,
							lpOverlapped,lpCompletionRoutine)
	
	local res = SocketLib.WSAIoctl(s, dwIoControlCode,
		lpvInBuffer, cbInBuffer,
		lpvOutBuffer, cbOutBuffer,
		lpcbBytesReturned,
		lpOverlapped, lpCompletionRoutine);
	
	if res ~= 0 then
		return false, SocketLib.WSAGetLastError();
	end
	
	return res
end

local WSAPoll = function(fdArray, fds, timeout)
	local res = SocketLib.WSAPoll(fdArray, fds, timeout)
	
	if SOCKET_ERROR == res then
		return false, SocketLib.WSAGetLastError();
	end
	
	return res
end

local WSASocket = function(af, socktype, protocol, lpProtocolInfo, g, dwFlags)
	af = af or Family.AF_INET;
	socktype = ocktype or SocketType.SOCK_STREAM;
	protocol = protocol or 0;
	lpProtocolInfo = lpProtocolInfo or nil;
	g = g or 0;
	dwFlags = dwFlags or WSA_FLAG_OVERLAPPED;

	local socket = SocketLib.WSASocketA(af, socktype, protocol, lpProtocolInfo, g, dwFlags);
	
	if socket == INVALID_SOCKET then
		return false, SocketLib.WSAGetLastError();
	end

	return socket;
end

--[[
	Retrieves the pointer to a winsock extension function.
--]]

local GetExtensionFunction = function(sock, gwid) 
	local target = ffi.new("void *[1]");
	local pbytes = ffi.new("int32_t[1]");

	local result, err = WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    gwid,
                    ffi.sizeof(gwid),
                    target,
                    ffi.sizeof(target[0]),
                    pbytes,
                    nil,
                    nil);
					
	
	if not result then
		return false, err
	end
	
	local bytes = pbytes[0];

end


--[[
	Real convenience functions
--]]

local SocketErrors = {
	[0]					= {0, "SUCCESS",},
	[WSAEFAULT]			= {10014, "WSAEFAULT", "Bad Address"},
	[WSAEINVAL]			= {10022, "WSAEINVAL", },
	[WSAEWOULDBLOCK]	= {10035, "WSAEWOULDBLOCK", },
	[WSAEINPROGRES]		= {10036, "WSAEINPROGRES", },
	[WSAEALREADY]		= {10037, "WSAEALREADY", },
	[WSAENOTSOCK]		= {10038, "WSAENOTSOCK", },
	[WSAEAFNOSUPPORT]	= {10047, "WSAEAFNOSUPPORT", },
	[WSAECONNABORTED]	= {10053, "WSAECONNABORTED", },
	[WSAECONNRESET] 	= {10054, "WSAECONNRESET", },
	[WSAENOBUFS] 		= {10055, "WSAENOBUFS", },
	[WSAEISCONN]		= {10056, "WSAEISCONN", },
	[WSAENOTCONN]		= {10057, "WSAENOTCONN", },
	[WSAESHUTDOWN]		= {10058, "WSAESHUTDOWN", },
	[WSAETOOMANYREFS]	= {10059, "WSAETOOMANYREFS", },
	[WSAETIMEDOUT]		= {10060, "WSAETIMEDOUT", },
	[WSAECONNREFUSED]	= {10061, "WSAECONNREFUSED", },
	[WSAHOST_NOT_FOUND]	= {11001, "WSAHOST_NOT_FOUND", },
}

function GetSocketErrorString(err)
	if SocketErrors[err] then
		return SocketErrors[err][2];
	end
	return tostring(err)
end


local function GetLocalHostName()
	local name = ffi.new("char[255]")
	local err = SocketLib.gethostname(name, 255);

	return ffi.string(name)
end

--[[
	This startup routine must be called before any other functions
	within the library are utilized.
--]]

function WinsockStartup()
	local wVersionRequested = MAKEWORD( 2, 2 );

	local dataarrayname = string.format("%s[1]", wsock.wsadata_typename)
	local wsadata = ffi.new(dataarrayname)
    local retValue = SocketLib.WSAStartup(wVersionRequested, wsadata);
	wsadata = wsadata[0]

	return retValue, wsadata
end

local err, wsadata = WinsockStartup()




return {
	WSAData = wsadata,

	Lib = SocketLib,
	FFI = wsock,

	-- Data Structures
	IN_ADDR = IN_ADDR,
	sockaddr = sockaddr,
	sockaddr_in = sockaddr_in,
	sockaddr_in6 = sockaddr_in6,
	addrinfo = addrinfo,
	
	-- Library Functions
	accept = accept,
	bind = bind,
	connect = connect,
	closesocket = closesocket,
	ioctlsocket = ioctlsocket,
	listen = listen,
	recv = recv,
	send = send,
	setsockopt = setsockopt,
	shutdown = shutdown,
	socket = socket,
	
	WSAIoctl = WSAIoctl,
	WSAPoll = WSAPoll,
	WSASocket = WSASocket,
	
	-- Helper functions
	GetLocalHostName = GetLocalHostName,
	GetSocketErrorString = GetSocketErrorString,
	GetExtensionFunction = GetExtensionFunction,
}



--[[
	BONE YARD
--]]

--[[
SOCKADDR_STORAGE = nil
SOCKADDR_STORAGE_mt = {
	__tostring = function(self)
		if self.ss_family == Family.AF_INET then
			return string.format("AF_INET, %s,  %d", self:GetAddressString(), self:GetPort())
		end

		if self.ss_family == AF_INET6 then
			return string.format("AF_INET6, %s, %d", self:GetAddressString(), self:GetPort())
		end

		return ""
	end,

	__index={
		Assign = function(self, rhs)
			if rhs.ss_family == Family.AF_INET then
				local selfptr = ffi.cast("struct sockaddr_in *", self)
				local rhsptr = ffi.cast("struct sockaddr_in *", rhs)
				local len = ffi.sizeof("struct sockaddr_in")

				memcpy(selfptr, rhs, len)
				return self
			elseif rhs.ss_family == Family.AF_INET6 then
				local selfptr = ffi.cast("struct sockaddr_in6 *", self)
				local rhsptr = ffi.cast("struct sockaddr_in6 *", rhs)
				local len = ffi.sizeof("struct sockaddr_in6")

				memcpy(selfptr, rhs, len)
				return self
			end

			return self
		end,

		Family = function(self)
			return self.ss_family, families[self.ss_family]
		end,

		Size = function(self)
			if self.ss_family == Family.AF_INET then
				local len = ffi.sizeof("struct sockaddr_in")
				return len
			elseif self.ss_family == Family.AF_INET6 then
				local len = ffi.sizeof("struct sockaddr_in6")
				return len
			end

			return 0
		end,

		Clone = function(self)
			local newone = SOCKADDR_STORAGE()
			memcpy(newone, self, ffi.sizeof("SOCKADDR_STORAGE"))

			return newone
		end,

		Equal = function(self, rhs)
			if self.ss_family ~= rhs.ss_family then return false end

			if self.sa_family == Family.AF_INET then
				local len = ffi.sizeof("struct sockaddr_in")
				return memcmp(self, rhs, len)
			else
				local len = ffi.sizeof("struct sockaddr_in6")
				return memcmp(self, rhs, len)
			end

			return false
		end,

		GetAddressString = function(self)
			if self.ss_family == Family.AF_INET then
				local selfptr = ffi.cast("struct sockaddr_in *", self)
				return selfptr.sin_addr:GetAsString()
			elseif self.ss_family == AF_INET6 then
				local selfptr = ffi.cast("struct sockaddr_in6 *", self)
				local addroffset = ffi.offsetof("struct sockaddr_in6", "sin6_addr")
				local in_addr6ptr = selfptr+addroffset

				local buf = ffi.new("char[?]", (INET6_ADDRSTRLEN+1))
				local bufptr = ffi.cast("intptr_t", buf)

				SocketLib.inet_ntop(AF_INET6, in_addr6ptr, bufptr, (INET6_ADDRSTRLEN));
				local ipstr =  ffi.string(buf)
--print(ipstr)
				return ipstr
			end

			return nil
		end,

		SetAddressFromString = function(self, src)
			if self.ss_family == AF_INET then
				local selfptr = ffi.cast("struct sockaddr_in *", self)
				selfptr.sin_addr:SetFromString(src)

				return self
			elseif self.ss_family == AF_INET6 then
				local selfptr = ffi.cast("struct sockaddr_in6 *", self)
				local addroffset = ffi.offsetof("struct sockaddr_in6", "sin6_addr")
				local in_addrptr = selfptr+addroffset

				wsock.inet_pton(AF_INET6, src, in_addrptr);

				return self
			end

			return nil
		end,

		EqualPort = function(self, rhs)
			return self:GetPort() == rhs:GetPort()
		end,

		GetPort = function(self)
			if self.ss_family == AF_INET then
				local selfptr = ffi.cast("struct sockaddr_in *", self)
				return wsock.ntohs(selfptr.sin_port)
			elseif self.ss_family == AF_INET6 then
				local selfptr = ffi.cast("struct sockaddr_in6 *", self)
				return wsock.ntohs(selfptr.sin6_port)
			end

			return nil
		end,

		SetPort = function(self, port)
			port = tonumber(port)
			if self.ss_family == AF_INET then
				local selfptr = ffi.cast("struct sockaddr_in *", self)
				selfptr.sin_port = wsock.htons(port);
				return self
			elseif self.ss_family == AF_INET6 then
				local selfptr = ffi.cast("struct sockaddr_in6 *", self)
				selfptr.sin6_port = wsock.htons(port);
				return self
			end

			return nil
		end,


	},
}
SOCKADDR_STORAGE = ffi.metatype("SOCKADDR_STORAGE", SOCKADDR_STORAGE_mt)
--]]


