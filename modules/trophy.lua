--[[
========================
trophy.lua - version 1.1
========================

Trophy server module is used to add trophy celebrations
to tournaments that do not have them in the game.

This works in 2 steps:

#1. We force the game to using scenes from tournaments
that do have trophy presentations. So without even adding
any content, you can have some existing trophy be shown
during English Super Cup - in this module, we use
American Cup.

#2. Then we can replace the content of the cup files with
custom made trophy. Those files are put into "content/trophy-server"
folder insider sider. The trophy files should still have the old names
but the trophy inside can be changed, of course. This way
it becomes possible to have proper Community Shield and
English Premier League trophies for the corresponding tournaments.

--]]

local m = {}

local content_root = ".\\content\\trophy-server"
local tcontent = nil

-- add more entries to this "remap" table
-- for other tournaments, where you want to have trophies.
local remap = {
    [86] = { 43, "eng_community_shield" },
    [17] = { 46, "eng_premier_league" },
}

function m.trophy_rewrite(ctx, tournament_id)
    tcontent = nil
    local entry = remap[tournament_id]
    if entry then
        local tid, relpath = unpack(entry)
        if tid and relpath then
            tcontent = content_root .. "\\" .. relpath .. "\\"
            log(string.format("This tournament is: %d. Remapping cup scenes to: %d", tournament_id, tid))
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
end

return m
