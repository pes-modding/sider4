--[[
==================================
trophy.lua - version 1.1

programming by: juce
using save data files by: saintric
==================================

Trophy server module is used to add trophy celebrations
to tournaments that do not have them in the game.

This works in 2 steps:

#1. We force the game to use scenes from tournaments
that do have trophy presentations. So without even adding
any content, you can have some existing trophy be shown
during English Super Cup - in this module, we use
American Cup.

#2. Then we can replace the content of the cup files with
custom made trophy. Those files are put into "content/trophy-server"
folder insider sider. The trophy files should still have the old names
but the trophy inside can be changed, of course. This way
it becomes possible to have proper trophies for all leagues, cups
and supercups.

All game modes are supported: League, Cup, Master League.

--]]

local m = { version = "1.1" }

local content_root = ".\\content\\trophy-server"
local tcontent = nil

-- add more entries to this "remap" table
-- for other tournaments, where you want to have trophies.
--
-- IMPORTANT: You must remap cups to cups and leagues to leagues,
-- otherwise the game gets confused. For example, English Premier League (17)
-- can be remapped to French League (20), and then the trophy ceremony will
-- be correctly displayed after the last league match (if you win it :-))
--
-- DO NOT remap cups to leagues or leagues to cups - that will not work well.
--
-- For reference, use doc/tournaments.txt provided with sider:
-- It has tournament ids for all tournaments in the game.

local remap = {
    [86] =  { 43, "eng_community_shield" },
    [17] =  { 20, "eng_premier_league" },
    [18] =  { 20, "ita_serie_a" },
    [116] = { 21, "rus_premier_league" },
}

function m.trophy_rewrite(ctx, tournament_id)
    tcontent = nil
    local entry = remap[tournament_id]
    if entry then
        local tid, relpath = unpack(entry)
        if tid and relpath then
            tcontent = content_root .. "\\" .. relpath .. "\\"
            log(string.format("This tournament is: %d. Remapping trophy scenes to: %d", tournament_id, tid))
            log(string.format("Using content from: %s", tcontent))
            return tid
        end
    end
end

function m.make_key(ctx, filename)
    if tcontent then
        return tcontent .. filename
    end
end

function m.get_filepath(ctx, filename, key)
    if tcontent then
        return key
    end
end

function m.init(ctx)
    if content_root:sub(1,1) == "." then
        content_root = ctx.sider_dir .. content_root
    end
    ctx.register("trophy_rewrite", m.trophy_rewrite)
    ctx.register("livecpk_make_key", m.make_key)
    ctx.register("livecpk_get_filepath", m.get_filepath)
    log("trophy server: version " .. m.version)
end

return m
