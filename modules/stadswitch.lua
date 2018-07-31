-- Stadium switcher

local m = {}

function m.set_match_time(ctx, match_time)
    if ctx.tournament_id == 48 or ctx.tournament_id == 65535 then
        log("setting match time to 1 minute")
        return 1
    end
end

function m.set_stadium(ctx, options)
    if ctx.tournament_id == 48 and ctx.match_info == 53 then
        -- Konami Cup final
        log("Konami Cup FINAL: switching stadium to Camp Nou!")
        options.stadium = 2   -- Camp Nou
        return options
    end
end

function m.set_conditions(ctx, options)
    if ctx.tournament_id == 48 and ctx.match_info == 53 then
        -- Konami Cup final
        log("Konami Cup FINAL: setting weather")
        options.weather = 1
        options.weather_effects = 2
        options.timeofday = 1
        options.season = 0
        return options
    end
end

function m.init(ctx)
   ctx.register("set_match_time", m.set_match_time)
   ctx.register("set_stadium", m.set_stadium)
   ctx.register("set_conditions", m.set_conditions)
end

return m
