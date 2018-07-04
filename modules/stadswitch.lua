-- Stadium switcher

local m = {}

function m.set_stadium(ctx, options)
    if ctx.tournament_id == 48 and ctx.match_info == 53 then
        -- Konami Cup final
        log("Konami Cup FINAL: switching stadium to Camp Nou!")
        options.stadium = 2   -- Camp Nou
        return options
    end
end

function m.init(ctx)
   ctx.register("set_stadium", m.set_stadium)
end

return m
