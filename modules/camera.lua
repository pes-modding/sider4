--[[
=========================

camera module
Game research by: nesa24
Requires: sider.dll 4.2.0+ (4.2.0+ for gamepad support)

=========================
--]]

local m = {}
m.version = "1.0"
local hex = memory.hex
local settings

local RESTORE_KEY = 0x38
local PREV_PROP_KEY = 0x39
local NEXT_PROP_KEY = 0x30
local PREV_VALUE_KEY = 0xbd
local NEXT_VALUE_KEY = 0xbb

local delta = 0
local frame_count = 0

local overlay_curr = 1
local overlay_states = {
    { ui = "camera zoom range: %0.2f", prop = "camera_range_zoom", decr = -0.1, incr = 0.1, def = 28.69 },
    { ui = "camera height range: %0.2f", prop = "camera_range_height", decr = -0.05, incr = 0.05, def = 0.3 },
    { ui = "camera angle range: %0.2f", prop = "camera_range_angle", decr = -1, incr = 1, def = 1.29 },
    { ui = "replays: %s", prop = "replays", def = "on",
        nextf = function(v)
            return (v == "on") and "off" or "on"
        end,
        prevf = function(v)
            return (v == "on") and "off" or "on"
        end,
    },
    --[[
    { ui = "ball cursor: %s", prop = "ball_cursor", def = "on",
        nextf = function(v)
            return (v == "on") and "off" or "on"
        end,
        prevf = function(v)
            return (v == "on") and "off" or "on"
        end,
    },
    --]]
}
local ui_lines = {}

local bases = {
    camera = nil,
    replays = nil,
}
local game_info = {
    camera_range_zoom   = { "camera", 0x2D8, "f", 4},   --> default: 28.69
    camera_range_height = { "camera", 0x2C0, "f", 4},   --> default: 0.3
    camera_range_angle  = { "camera", 0x20, "f", 4},   --> default: 1.35
    replays = { "replays", 0x04, "", 1, {on='\x04', off='\x06'}},
    --ball_cursor = { "ball", 0x00, "", 7,
       -- {on='\x0f\x29\x8d\xc0\xff\xff\xff', off='\x90\x90\x90\x90\x90\x90\x90'}},
}

local function load_ini(ctx, filename)
    local t = {}
    for line in io.lines(ctx.sider_dir .. "\\" .. filename) do
        local name, value = string.match(line, "^([%w_]+)%s*=%s*([-%w%d.]+)")
        if name and value then
            value = tonumber(value) or value
            t[name] = value
            log(string.format("Using setting: %s = %s", name, value))
        end
    end
    return t
end

local function save_ini(ctx, filename)
    local f,err = io.open(ctx.sider_dir .. "\\" .. filename, "wt")
    if not f then
        log(string.format("PROBLEM saving settings: %s", tostring(err)))
        return
    end
    f:write(string.format("# Camera settings. Written by camera.lua " .. m.version .. "\n\n"))
    f:write(string.format("camera_range_zoom = %0.2f\n", settings.camera_range_zoom))
    f:write(string.format("camera_range_height = %0.2f\n", settings.camera_range_height))
    f:write(string.format("camera_range_angle = %0.2f\n", settings.camera_range_angle))
    f:write(string.format("replays = %s\n", settings.replays))
   -- f:write(string.format("ball_cursor = %s\n", settings.ball_cursor))
    f:write("\n")
    f:close()
end

local function apply_settings(ctx, log_it, save_it)
    for name,value in pairs(settings) do
        local entry = game_info[name]
        if entry then
            local base_name, offset, format, len, value_mapping = unpack(entry)
            local base = bases[base_name]
            if base then
                if value_mapping then
                    value = value_mapping[value]
                end
                local addr = base + offset
                local old_value, new_value
                if format ~= "" then
                    old_value = memory.unpack(format, memory.read(addr, len))
                    memory.write(addr, memory.pack(format, value))
                    new_value = memory.unpack(format, memory.read(addr, len))
                    if log_it then
                        log(string.format("%s: changed at %s: %s --> %s",
                            name, hex(addr), old_value, new_value))
                    end
                else
                    old_value = memory.read(addr, len)
                    memory.write(addr, value)
                    new_value = memory.read(addr, len)
                    if log_it then
                        log(string.format("%s: changed at %s: %s --> %s",
                            name, hex(addr), hex(old_value), hex(new_value)))
                    end
                end
            end
        end
    end
    if (save_it) then
        save_ini(ctx, "camera.ini")
    end
end

function m.set_teams(ctx, home, away)
    apply_settings(ctx, true)
end

local function repeat_change(ctx, after_num_frames, change)
    if change ~= 0 then
        frame_count = frame_count + 1
        if frame_count >= after_num_frames then
            local s = overlay_states[overlay_curr]
            settings[s.prop] = settings[s.prop] + change
            apply_settings(ctx, false, false) -- apply
        end
    end
end

function m.overlay_on(ctx)
    -- repeat change from gamepad, if delta exists
    repeat_change(ctx, 30, delta)
    -- construct ui text
    for i,v in ipairs(overlay_states) do
        local s = overlay_states[i]
        local setting = string.format(s.ui, settings[s.prop])
        if i == overlay_curr then
            ui_lines[i] = string.format("\n---> %s <---", setting)
        else
            ui_lines[i] = string.format("\n     %s", setting)
        end
    end
    return string.format([[version %s
Keys: [9][0] - choose setting, [-][+] - modify value, [8] - restore defaults
Gamepad: RS up/down - choose setting, RS left/right - modify value
%s]], m.version, table.concat(ui_lines))
end

function m.key_down(ctx, vkey)
    if vkey == NEXT_PROP_KEY then
        if overlay_curr < #overlay_states then
            overlay_curr = overlay_curr + 1
        end
    elseif vkey == PREV_PROP_KEY then
        if overlay_curr > 1 then
            overlay_curr = overlay_curr - 1
        end
    elseif vkey == NEXT_VALUE_KEY then
        local s = overlay_states[overlay_curr]
        if s.incr ~= nil then
            settings[s.prop] = settings[s.prop] + s.incr
        elseif s.nextf ~= nil then
            settings[s.prop] = s.nextf(settings[s.prop])
        end
        apply_settings(ctx, false, true)
    elseif vkey == PREV_VALUE_KEY then
        local s = overlay_states[overlay_curr]
        if s.decr ~= nil then
            settings[s.prop] = settings[s.prop] + s.decr
        elseif s.prevf ~= nil then
            settings[s.prop] = s.prevf(settings[s.prop])
        end
        apply_settings(ctx, false, true)
    elseif vkey == RESTORE_KEY then
        for i,s in ipairs(overlay_states) do
            settings[s.prop] = s.def
        end
        apply_settings(ctx, false, true)
    end
end

function m.gamepad_input(ctx, inputs)
    local v = inputs["RSy"]
    if v then
        if v == -1 and overlay_curr < #overlay_states then -- moving down
            overlay_curr = overlay_curr + 1
        elseif v == 1 and overlay_curr > 1 then -- moving up
            overlay_curr = overlay_curr - 1
        end
    end

    v = inputs["RSx"]
    if v then
        if v == -1 then -- moving left
            local s = overlay_states[overlay_curr]
            if s.decr ~= nil then
                settings[s.prop] = settings[s.prop] + s.decr
                -- set up the repeat change
                delta = s.decr
                frame_count = 0
            elseif s.prevf ~= nil then
                settings[s.prop] = s.prevf(settings[s.prop])
            end
            apply_settings(ctx, false, false) -- apply
        elseif v == 1 then -- moving right
            local s = overlay_states[overlay_curr]
            if s.decr ~= nil then
                settings[s.prop] = settings[s.prop] + s.incr
                -- set up the repeat change
                delta = s.incr
                frame_count = 0
            elseif s.nextf ~= nil then
                settings[s.prop] = s.nextf(settings[s.prop])
            end
            apply_settings(ctx, false, false) -- apply
        elseif v == 0 then -- stop change
            delta = 0
            apply_settings(ctx, false, true) -- apply and save
        end
    end
end

function m.init(ctx)
    -- find the base address of the block of camera settings
    local pattern = "\xAE\x47\x89\x40\x66\x66\x98\x41\x9A\x99"
    local loc = memory.search_process(pattern)
    if loc then
        bases.camera = loc
        log(string.format("Camera block base address: %s", hex(bases.camera)))
    else
        log("problem: unable to find code pattern for camera block")
    end

    settings = load_ini(ctx, "camera.ini")

    -- find replays opcode
    local pattern = "\x41\xc6\x45\x08\x04"
    local loc = memory.search_process(pattern)
    if loc then
        bases.replays = loc
        log(string.format("Replays op-code address: %s", hex(bases.replays)))
    else
        log("problem: unable to find code pattern for replays switch")
    end

    -- find ball cursor place
    --[[
00000001515ED611 | 89 B5 BC FF FF FF                    | mov dword ptr ss:[rbp-44],esi          |
00000001515ED617 | 0F 28 B5 B0 FF FF FF                 | movaps xmm6,xmmword ptr ss:[rbp-50]    |
00000001515ED61E | 0F 29 8D C0 FF FF FF                 | movaps xmmword ptr ss:[rbp-40],xmm1    | store ball cursor coordinates
    
    local pattern = "\x89\xb5\xbc\xff\xff\xff\x0f\x28\xb5\xb0\xff\xff\xff"
    local loc = memory.search_process(pattern)
    if loc then
        loc = loc + #pattern
        bases.ball = loc
        log(string.format("Ball cursor op-code address: %s", hex(bases.ball)))
    else
        log("problem: unable to find code pattern for ball cursor read")
    end
--]]
    -- register for events
    ctx.register("set_teams", m.set_teams)
    ctx.register("overlay_on", m.overlay_on)
    ctx.register("key_down", m.key_down)
    ctx.register("gamepad_input", m.gamepad_input)
end

return m
