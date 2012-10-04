
local ffi = require "ffi"
local bit = require "bit"
local band = bit.band

local WinSock = require "WinSock_Utils"
local SocketType = WinSock.FFI.SocketType;

local NativeSocket = require "NativeSocket"

-- pass in a sockaddr
-- get out a more specific sockaddr_in or sockaddr_in6
function newSocketAddress(name, namelen)
	local sockaddrptr = ffi.cast("struct sockaddr *", name)
	local newone

	if sockaddrptr.sa_family == AF_INET then
		newone = sockaddr_in()
	elseif sockaddrptr.sa_family == AF_INET6 then
		newone = sockaddr_in6()
	end
	ffi.copy(newone, sockaddrptr, namelen)

	return newone
end


local function host_serv(hostname, servicename, family, sockttype, isnumericstring)
	hostname = hostname or "localhost"
	family = family or AF_UNSPEC;
	socktype = socktype or SocketType.SOCK_STREAM;

	local err;
	local hints = WinSock.addrinfo();
	local res = ffi.new("PADDRINFOA[1]")

	--hints.ai_flags = AI_CANONNAME;	-- return canonical name
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	if isnumericstring then
		hints.ai_flags = AI_NUMERICHOST
	end

	err = WinSock.Lib.getaddrinfo(hostname, servicename, hints, res)
--print("host_serv, err: ", err);
	if err ~= 0 then
		-- error condition
		return nil, err
	end

	return res[0]
end


function CreateIPV4WildcardAddress(family, port)
	local inetaddr = sockaddr_in()
	inetaddr.sin_family = family;
	inetaddr.sin_addr.S_addr = WinSock.Lib.htonl(INADDR_ANY);
	inetaddr.sin_port = WinSock.Lib.htons(port);

	return inetaddr
end

function CreateSocketAddress(hostname, port, family, socktype)
	family = family or AF_INET
	socktype = socktype or SOCK_STREAM

--print("CreateSocketAddress(): ", hostname, port);

	local hostportoffset = hostname:find(':')
	if hostportoffset then
		port = tonumber(hostname:sub(hostportoffset+1))
		hostname = hostname:sub(1,hostportoffset-1)
		print("CreateSocketAddress() - Modified: ", hostname, port)
	end

	local addressinfo, err = host_serv(hostname, nil, family, socktype)

	if not addressinfo then
		return nil, err
	end

	-- clone one of the addresses
	local oneaddress = newSocketAddress(addressinfo.ai_addr, addressinfo.ai_addrlen)
	oneaddress:SetPort(port)

	-- free the addrinfos structure
	err = WinSock.Lib.freeaddrinfo(addressinfo)

	return oneaddress;
end

local function ReadChunk(sock, buff, size)
	local nread, err = sock:Receive(buff, size)

	return nread, err
end

local function ReadN(sock, buff, size)
	local nleft = size;
	local nread = 0;
	local err
	local ptr = buff

	while nleft > 0 do
		nread, err = sock:Receive(ptr, nleft)
		--coroutine.yield();
		if nread then
			if nread == 0 then
				break
			end

			nleft = nleft - nread
			ptr = ptr + nread
		elseif err and err ~= WSAEWOULDBLOCK then
			break
		end
	end

	local bytesread = size - nleft

	if bytesread == 0 then
		return nil, "eof"
	end

	return bytesread
end

local function WriteN(sock, buff, size)
	local nleft = size;
	local nwritten = 0;
	local err
	local ptr = ffi.cast("const uint8_t *", buff)

	while nleft > 0 do
		nwritten, err = sock:Send(ptr, nleft)
		if not nwritten then
			if err ~= WSAEWOULDBLOCK then
				return nil, err
			end
			err = nil
		else
			if nwritten == 0 then
				break
			end
			nleft = nleft - nwritten
			ptr = ptr + nwritten
		end
	end

	return size - nleft
end


local CR = string.byte("\r")
local LF = string.byte("\n")

local function ReadLine(sock, buff, maxlen)
	--print("ReadLine(), Begin: ", maxlen)

	assert(buff)

	local nchars = 0;
	local ptr = buff
	local err
	local bytesread

	for n=1, maxlen do
		bytesread, err = ReadN(sock, ptr, 1)
		if not bytesread then
			--print("-- ReadLine(), Error: ", err);
			if err ~= "wouldblock" then
				break
			end
		end

		if ptr[0] == LF then
			break
		elseif ptr[0] ~= CR then
			ptr = ptr + 1
			nchars = nchars+1
		end
	end

	if err and err ~= "eof" then
		return nil, err
	end

	if nchars == 0 then
		return nil, "eof"
	end

	return nchars
end


--[[
	Helper Functions
--]]

function CreateTcpServerSocket(params)
	params = params or {port = 80, backlog = 15, nonblocking=false, nodelay = false}
	params.backlog = params.backlog or 15
	params.port = params.port or 80

	local sock, err = NativeSocket()
	if not sock then
		return nil, err
	end

	local success
	success, err = sock:SetNoDelay(params.nodelay)
	success, err = sock:SetReuseAddress(true);

	local addr = WinSock.sockaddr_in(params.port);
	local addrlen = ffi.sizeof("struct sockaddr_in")

	success, err = sock:Bind(addr,addrlen)
	if not success then
		return nil, err
	end

	success, err = sock:MakePassive(params.backlog)
	if not success then
		return nil, err
	end

	success, err = sock:SetNonBlocking(params.nonblocking);

	return sock
end

function CreateTcpClientSocket(hostname, port)
	--print("CreateTcpClientSocket: ", hostname, port)

	local addr, err = CreateSocketAddress(hostname, port)

	if not addr then
		print("-- CreateTcpClientSocket() - could not create address: ", hostname, port)
		return nil, err
	end

	--print("CreateTcpClientSocket(): ", addr);

	local sock
	sock, err	= NativeSocket();

	if not sock then
		return nil, err
	end

	-- Disable delay by default on all sockets
	err = sock:SetNoDelay(true)

	-- Connect to the host
	local success
	success, err = sock:ConnectTo(addr)
	if not success then 
		return nil, err
	end

	return sock
end


return {
	ReadByte = ReadByte,
	ReadLine = ReadLine,
	ReadN = ReadN,
	WriteN = WriteN,
	host_serv = host_serv,

	CreateTcpServerSocket = CreateTcpServerSocket,
	CreateTcpClientSocket = CreateTcpClientSocket,
}
