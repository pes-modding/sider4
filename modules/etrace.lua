-- Event tracer
-- prints event and context info, reacting to various events

local m = {}

local function t2s(t)
    local parts = {}
    for k,v in pairs(t) do
        parts[#parts + 1] = string.format("%s=%s", k, v)
    end
    table.sort(parts) -- sort alphabetically
    return string.format("{%s}", table.concat(parts,", "))
end

-- utility function to log message with a timestamp
local function tlog(...)
    local msg = string.format(...)
    log(string.format("%s | %s", os.date("%Y-%m-%d %H:%M:%S"), msg))
end

function m.set_teams(ctx, home, away)
    tlog("teams: %d vs %d", home, away)
    tlog("ctx: %s", t2s(ctx))
end

function m.set_match_time(ctx, num_minutes)
    tlog("match_time: %d", num_minutes)
    tlog("ctx: %s", t2s(ctx))
end

function m.set_stadium(ctx, options)
    tlog("set_stadium: %s", t2s(options))
    tlog("ctx: %s", t2s(ctx))
end

function m.set_conditions(ctx, options)
    tlog("set_conditions: %s", t2s(options))
    tlog("ctx: %s", t2s(ctx))
end

function m.init(ctx)
   ctx.register("set_teams", m.set_teams)
   ctx.register("set_match_time", m.set_match_time)
   ctx.register("set_stadium", m.set_stadium)
   ctx.register("set_conditions", m.set_conditions)
end

return m
