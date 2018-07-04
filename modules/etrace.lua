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

function m.set_home(ctx, id)
    tlog("home team: %d", id)
    tlog("ctx: %s", t2s(ctx))
end

function m.set_away(ctx, id)
    tlog("away team: %d", id)
    tlog("ctx: %s", t2s(ctx))
end

function m.set_conditions(ctx, options)
    tlog("set_conditions")
    tlog("ctx: %s", t2s(ctx))
end

function m.init(ctx)
   ctx.register("set_home_team", m.set_home)
   ctx.register("set_away_team", m.set_away)
   ctx.register("set_conditions", m.set_conditions)
end

return m
