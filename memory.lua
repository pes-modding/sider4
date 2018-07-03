-- memory library for Win64

local ffi = require('ffi')
local C = ffi.C

ffi.cdef [[
bool VirtualProtect(void *p, size_t len, uint32_t newprot, uint32_t *oldprot);
int memcmp(void *dst, void *src, size_t len);
void sprintf(char *dst, char *fmt, ...);
]]

local m = {}

local PAGE_EXECUTE_READWRITE = 0x40

function m.search(s, from, to)
    local p = ffi.cast('char*', from)
    local q = ffi.cast('char*', to)
    local cs = ffi.cast('char*', s)
    local range = to - from
    local slen = #s
    local oldprot = ffi.new('uint32_t[1]',{});
    if not C.VirtualProtect(p, range, PAGE_EXECUTE_READWRITE, oldprot) then
        return error(string.format('VirtualProtect failed for %s - %s memory range', from, to))
    end
    while p < q do
        if C.memcmp(p, cs, slen) == 0 then
            return p
        end
        p = p+1
    end
end

function m.read(addr, len)
    local p = ffi.cast('char*', addr)
    local oldprot = ffi.new('uint32_t[1]',{});
    if not C.VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, oldprot) then
        return error(string.format('VirtualProtect failed for %s - %s memory range', addr, addr+len))
    end
    return ffi.string(p, len)
end

function m.write(addr, s)
    local p = ffi.cast('char*', addr)
    local oldprot = ffi.new('uint32_t[1]',{});
    local len = #s
    if not C.VirtualProtect(p, len, PAGE_EXECUTE_READWRITE, oldprot) then
        return error(string.format('VirtualProtect failed for %s - %s memory range', addr, addr+len))
    end
    ffi.copy(p, s, len)
end

local format_sizes = {
    i64 = 8, u64 = 8,
    i32 = 4, u32 = 4, i = 4, ui = 4,
    i16 = 2, u16 = 2, s = 2, us = 2,
    f = 4, d = 8,
}

function m.pack(fmt, value)
    local len = format_sizes[fmt]
    if len == nil then
        return error(string.format('Unsupported pack format: %s', fmt))
    end
    local arr
    if fmt == 'f' then
        arr = ffi.new('float[1]',{ffi.cast('float', value)})
    elseif fmt == 'd' then
        arr = ffi.new('double[1]',{ffi.cast('double', value)})
    else
        arr = ffi.new('char*[1]',{ffi.cast('char*', value)})
    end
    return ffi.string(ffi.cast('char*', arr), len)
end

function m.unpack(fmt, s)
    if fmt == 'i64' then
        return ffi.cast('int64_t*', s)[0]
    elseif fmt == 'u64' then
        return ffi.cast('uint64_t*', s)[0]
    elseif fmt == 'i32' or fmt == 'i' then
        return tonumber(ffi.cast('int32_t*', s)[0])
    elseif fmt == 'u32' or fmt == 'ui' then
        return tonumber(ffi.cast('uint32_t*', s)[0])
    elseif fmt == 'i16' or fmt == 's' then
        return tonumber(ffi.cast('int16_t*', s)[0])
    elseif fmt == 'u16' or fmt == 'us' then
        return tonumber(ffi.cast('uint16_t*', s)[0])
    elseif fmt == 'f' then
        return tonumber(ffi.cast('float*', s)[0])
    elseif fmt == 'd' then
        return tonumber(ffi.cast('double*', s)[0])
    end
    return error(string.format('Unsupported unpack format: %s', fmt))
end

function m.hex(s)
    local v, count = string.gsub(s, '.', function(c)
        return string.format('%02x', string.byte(c))
    end)
    return v
end

function m.tohexstring(value)
    if type(value) == 'cdata' then
        local buf = ffi.new('char[32]',{});
        C.sprintf(buf, ffi.cast('char*', '0x%llx'), ffi.cast('uint64_t',value));
        return ffi.string(buf)
    else
        return string.format('0x%x', value)
    end
end

return m

