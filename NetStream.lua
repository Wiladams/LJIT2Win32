
local ffi = require "ffi"
local Stream = require "stream"

local MemoryStream = require "MemoryStream"

local NativeSocket = require "NativeSocket"
local SocketUtils = require "SocketUtils"

local StopWatch = require "StopWatch"

local strutils = require "stringzutils"
local typeutils = require "typeutils"

local NetStream = {}
local NetStream_mt = {
	__index = NetStream,
}

local activityTimeout = 60 * 5	-- 5 minutes

function NetStream.new(socket)
	if not socket then
		return nil
	end

	local obj = {
		Socket = socket,
		CanSeek = false,

		ReadTimer = StopWatch.new(),
		ReadTimeout = nil,

		WriteTimer = StopWatch.new(),
		WriteTimeout = nil,
	}

	setmetatable(obj, NetStream_mt)

	return obj;
end

function NetStream.Open(hostname, port)
	local socket, err = CreateTcpClientSocket(hostname, port)

	if not socket then
		return nil, err
	end

	return NetStream.new(socket)
end



--[[
	IsIdle()
	When called, this routine will compare the last
	read and write activity times.  If the time is beyond
	the respective timeout periods, then it will return 'true'.

	All other cases will return false.
--]]
function NetStream:IsIdle()
	--print("NetStream: IsIdle()");

	-- First condition of expiration
	-- both timeouts exist
	if self.ReadTimeout and self.WriteTimeout then
		if self.ReadTimer:Seconds() > self.ReadTimeout and
			self.WriteTimer:Seconds() > self.WriteTimeout then

			return true;
		end
	elseif self.ReadTimeout then
		if self.ReadTimer:Seconds() > self.ReadTimeout then
			return true;
		end
	elseif self.WriteTimeout then
		if self.WriteTimer:Seconds() > self.WriteTimeout then
			return true;
		end
	end

	return false
end

--[[
	Cycle()
	Can be called at any time.  If the stream
	is idle, then force a close.
--]]

function NetStream:Cycle()
	--print("NetStream: Cycle");

	if self:IsIdle() then
		self:CloseDown();
		--self:ForceClose();
	end
end

-- Set the timeout for inactivity
-- After the specified amount of time off
-- inactivity, timeout, and forcefully close the stream
function NetStream:SetIdleInterval(seconds)
	self:SetReadTimeout(seconds);
	self:SetWriteTimeout(seconds);
end

function NetStream:SetReadTimeout(seconds)
	self.ReadTimeout = seconds
end

function NetStream:SetWriteTimeout(seconds)
	self.WriteTimeout = seconds;
end

function NetStream:ForceClose()
	self.Socket:ForceClose();
end


-- Controlled shutdown
function NetStream:ShutdownReceive()
	return self.Socket:ShutdownReceive()
end

function NetStream:ShutdownSend()
	return self.Socket:ShutdownSend()
end

function NetStream:CloseDown()
	self.Socket:CloseDown();
end

function NetStream:GetLength()
	return 0	-- or math.huge
end

function NetStream:GetPosition()
	return self.Consumed  -- or number of bytes consumed so far
end

function NetStream:IsConnected()
	return self.Socket:IsCurrentlyConnected()
end

function NetStream:SetNonBlocking(nonblocking)
	return self.Socket:SetNonBlocking(nonblocking)
end

--[[
	READING
--]]
function NetStream:CanRead()
	return self.Socket:CanReadWithoutBlocking();
end

--[=[
function NetStream:HasBytesReadyToRead()
--[[
	-- There are bytes in the ReadingBuffer
	local bytesready = self.ReadingBuffer:BytesReadyToBeRead()
	if bytesready > 0 then
		return bytesready
	end
--]]
	-- If the socket is no longer connected, then
	-- return nil, and 'disconnected'
	if not self:IsConnected() then
		return nil, "disconnected"
	end

	-- If there are bytes sitting in the socket's queue
	-- then return true
	local pending, err = self.Socket:GetBytesPendingReceive()
	--print("NS:HBRTR - ",pending, err)

	return pending, err
end


function NetStream:BytesReadyToBeRead()
	local pending, err = self.Socket:GetBytesPendingReceive()

	if pending then
		return pending
	end

	if err == WSAEWOULDBLOCK then
		return nil, "wouldblock"
	end

	return nil, err
end
--]=]


--[[
function NetStream:RefillReadingBuffer()
	print("NetStream:RefillReadingBuffer()");

	-- Use the buffer of the memory stream to
	-- read in a bunch of bytes
	local err
	local bytesread

	repeat
		bytesread, err = self.Socket:Receive(self.ReadingBuffer.Buffer, self.ReadingBuffer.Length)

		-- if we already got bytes, then return them immediately
		if bytesread then
			print("-- LOADED BYTES: ", bytesread);

			if bytesread == 0 then
				return nil, "eof"
			end

			self.ReadingBuffer:Reset()
			self.ReadingBuffer.BytesWritten = bytesread
			return bytesread, nil
		end

		if err ~= WSAEWOULDBLOCK then
			print("-- NetStream:RefillReadingBuffer(), ERROR: ", err)
			return nil, err
		end

		print("REPEAT");
	until bytesread

	return bytesread
end
--]]

--[[
	Read a byte.
	Return the single byte read, or nil
--]]
local rb_onebyte = typeutils.uint8_tv(1)

function NetStream:ReadByte()
	local abyte
	local err
	local res

	self.ReadTimer:Reset();

	--print("ReadByte Available: ", self.Socket:GetBytesPendingReceive())

	repeat
		abyte, err = self.Socket:Receive(rb_onebyte, 1)
		--print(abyte, err)
		if abyte then
			if abyte == 0 then
				return nil, "eof"
			end

			return rb_onebyte[0]
		end

		if err ~= WSAEWOULDBLOCK then
			print("-- NetStream:ReadByte() - Err: ", err);
			return nil, err
		end
	until abyte

	return abyte

--[[
	-- First see if we can get a byte out of the
	-- Reading buffer
	abyte,err = self.ReadingBuffer:ReadByte()

	if abyte then
		return abyte
	end

	repeat
		-- If we did not get a byte out of the reading buffer
		-- try refilling the buffer, and try again
		local bytesread, err = self:RefillReadingBuffer()

		if bytesread then
			abyte, err = self.ReadingBuffer:ReadByte()
			return abyte, err
		else
			-- If there was an error
			-- then return that error immediately
			print("-- NetStream:ReadByte, ERROR: ", err)
			return nil, err
		end
	until false
--]]
end


-- The Bytes() function acs as an iterator on bytes
-- from the stream.  In the case of a nonblocking stream
-- this will in fact block, waiting for a character,
-- only returning when a character is found, or there is an
-- error other than WOULDBLOCK
--[[
function NetStream:Bytes(maxbytes)
	maxbytes = maxbytes or math.huge
	local bytesleft = maxbytes

	--print("NetStream:Bytes() BYTES LEFT: ", bytesleft);

	local function f()
		--print("-- NetStream:Bytes(), REMAINING: ", bytesleft)
		-- if we've read the maximum number of bytes
		-- then just return nil to indicate finished
		if bytesleft == 0 then
			return
		end

		local abyte
		local err
		local res

		while (true) do
			-- try to read a byte
			-- if we're a blocking socket, we'll just wait
			-- here forever, or until a system specified timeout
			local abyte, err = self:ReadByte()

			-- The return of Socket:Read() is the number of
			-- bytes read if successful, nil on failure
			if abyte then
				bytesleft = bytesleft-1
				return abyte
			end

			-- If there was an error other than wouldblock
			-- then return that error immediately
			if err ~= WSAEWOULDBLOCK then
				bytesleft = 0
				--print("-- NetStream:Bytes ERROR: ", err)
				return nil, err
			end
		end
	end

	return f
end
--]]

function NetStream:ReadBytes(buffer, len, offset)
	offset = offset or 0
--print("NetStream:ReadBytes()", buffer, len, offset);

	-- Reset the stopwatch
	self.ReadTimer:Reset();

	assert(buffer, "NetStream:ReadBytes(), buffer is NULL");

	local bytesread, err = SocketUtils.ReadN(self.Socket, buffer, len)

	return bytesread, err
--[[
	local bytesread, err = self.Socket:Receive(buffer, len, offset)

	if bytesread then
		if bytesread == 0 then
			return nil, "eof"
		end

		return bytesread
	end


	if err == WSAEWOULDBLOCK then
		return nil, "wouldblock"
	end

	return nil, err
--]]
end

local array = ffi.typeof("uint8_t[?]")

function NetStream:ReadString(bufflen)
	bufflen = bufflen or 8192

	--print(string.format("-- NetStream:ReadString(), count: 0x%x", bufflen));

	local buff = array(bufflen);
	assert(buff, "NetStream:ReadString() - buffer not allocated")

	self.ReadTimer:Reset();

	local bytesread, err = SocketUtils.ReadN(self.Socket, buff, bufflen);
	--local bytesread, err = self:ReadBytes(buff, bufflen, 0)
--print("NetStream:ReadString() - Bytes Read: ", bytesread, err)

	if bytesread and bytesread > 0 then
		return ffi.string(buff, bytesread)
	end

	return nil, err
end

-- Read characters from a stream until the specified
-- ending is found, or until the stream runs out of bytes
local CR = string.byte("\r")
local LF = string.byte("\n")

function NetStream:ReadLine(maxbytes)
	maxbytes = maxbytes or 1024
	local buff = array(maxbytes)

	assert(buff,"NetStream:ReadLine(), buffer not allocated")

	self.ReadTimer:Reset();

	local bytesread, err = SocketUtils.ReadLine(self.Socket, buff, maxbytes)

--	print("-- NetStream:ReadLine() - bytesread, err:", bytesread, err);

	if bytesread then
		return ffi.string(buff, bytesread)
	end

	return nil, err

--[[
	-- use the stream's byte iterator
	local haveCR = false
	for abyte, err in self:Bytes(maxbytes) do
		if abyte == CR then
			haveCR = true
		elseif abyte == LF then
			break
		else
			table.insert(chartable, string.char(abyte))
		end
	end

	local str = table.concat(chartable)

	return str
--]]
end

--[[
	WRITING
--]]

function NetStream:CanWrite()
	return self.Socket:CanWriteWithoutBlocking();
end

function NetStream:WriteByte(value)
	local wb_buff = array(1, value)
	local byteswritten, err

	byteswritten, err = WriteN(self.Socket, wb_buff, 1);

	self.WriteTimer:Reset();

	return byteswritten, err
end

function NetStream:WriteBytes(buffer, len, offset)
	len = len or 0
	offset = offset or 0
	local ptr = buffer;

	if type(buffer) == "string" then
		ptr = ffi.cast("const uint8_t *", buffer)
		len = len or #buffer
	end

	local byteswritten, err
	local totalwritten = 0
	local idx = 0

--print("NetStream:WriteBytes(), BEGIN")

	byteswritten, err = SocketUtils.WriteN(self.Socket, ptr, len)

	-- reset the write timer
	self.WriteTimer:Reset();

	--print("NetStream:WriteBytes(), END: ", byteswritten, err)

	return byteswritten, err
end

function NetStream:WriteString(str, count, offset)
	count = count or #str
	offset = offset or 0

--print("NetStream:WriteString(): ", str);

	local byteswritten, err =  self:WriteBytes(str, count, offset)

	return byteswritten, err
end

local lineEnd = "\r\n"
local lineEnding = strdup(lineEnd)

function NetStream:WriteLine(line)
--print("-- NetStream:WriteLine(): ",line)

	local status, err
	if line then
		status, err = self:WriteString(line)
--print("-- NetStream:WriteLine(), Line:", status, err)
		if err then
			return nil, err
		end
	end

	-- write the terminator
	status, err = self:WriteString(lineEnd);
	--status, err = self:WriteBytes(lineEnding, 2, 0)

--print("--   Terminator: ", status, err);

	return status, err
end

function NetStream:WriteStream(stream, size)
	local count = 0
	local abyte = stream:ReadByte()
	while abyte and count < size do
		self:WriteByte(abyte)
		count = count + 1
		abyte = stream:ReadByte()
	end

	return count
end

return NetStream;
