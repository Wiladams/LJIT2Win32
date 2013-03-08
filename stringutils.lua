local function bintohex(bytes, len)
	local str = ffi.string(bytes, len)

	return (str:gsub('(.)', function(c)
		return string.format('%02x', string.byte(c))
	end))
end
