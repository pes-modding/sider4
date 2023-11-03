-- PES 2018 lua common utilities for sider 4
-- author: zlac, 2018-2020, backporting to PES2018 by MjTs-140914, 24-03-2022
-- version: 1.0
-- originally posted on evo-web

local m = {}

-- exposed members/methods
-- ###########################################################
m.version = "1.1"
m.teams_in_playable_leagues_map = {}
m.compID_to_tournamentID_map = {}  
m.tournamentID_to_compID_map = {}

function m.try_unzlib(data)
    local konami_header = {}
    if #data >= 16 and string.lower(data:sub(4,8)) == "wesys" then
		-- file seems to carry standard Konami zlib header ...
        konami_header["magic"] = data:sub(1,3)
        konami_header["wesys"] = "WESYS"
        konami_header["compressed_size"] = memory.unpack("u32", data:sub(9,12))
        konami_header["uncompressed_size"] = memory.unpack("u32", data:sub(13,16))
        return zlib.uncompress(data:sub(-(#data-16)), konami_header["uncompressed_size"])
    elseif #data > 0 then
        -- doesn't seem to be standard Konami-zlibbed file, but seems to be a file with some data ...
        -- file contents were probably not zlibbed to begin with ... return raw data
        return data, "ERR_NOT_ZLIBBED"
    else
        -- Houston, we have a problem!
        return nil, "ERR_NO_DATA"
    end

end

function m.has_value(tab, val)
    for index, value in pairs(tab or {}) do
        if value == val then
            return true
        end
    end
    return false
end

function m.nil2str(value)
	if value ~= nil then
		return value
	else
		return "N/A"
	end
end

function m.tid_same_league(home_id, away_id)
    local _empty = {}
    
    for index, value in pairs(m.teams_in_playable_leagues_map or _empty) do
        if m.has_value(value, home_id) and m.has_value(value, away_id) then    
            return (m.compID_to_tournamentID_map or _empty)[index]
        end
    end
    
    return nil
end



-- helper methods/members
-- #########################################################

local compentry_bin_chunks = {}
local compentry_bin_full
local compreg_bin_chunks = {}
local compreg_bin_full
-- competiton IDs from Competition.bin - these are NOT identical to tournament_ID's which are used by sider
local playable_league_comp_ids = {9, 66, -- England 1st and 2nd div
                             10, 69, -- Italy 1st and 2nd div
                             11, 67, -- Spain 1st and 2nd div
                             12, 68, -- France 1st and 2nd div
                             13, -- Netherlands
                             14, -- Portugal
                             21, 90, -- Brasil 1st and 2nd div
                             22, -- Argentina
                             23, -- Chile
                             39, -- PEU (Bundesliga?)
                             40, -- PLA (Mexico/USA?)
                             41, -- PAS (J-League?)
						}


local function is_it_compentry_file(filename)
	filename = string.lower(filename)

	if string.match(filename, "common\\etc\\pesdb\\competitionentry%d?%.bin") then
		return true
	else
		return false
	end
end

local function is_it_compreg_file(filename)
	filename = string.lower(filename)

	if string.match(filename, "common\\etc\\pesdb\\competitionregulation%d?%.bin") then
		return true
	else
		return false
	end
end

function get_compentry_data(filename, data)
    local bytes, err = m.try_unzlib(data)
    if bytes and (not err or err == "ERR_NOT_ZLIBBED") then
        -- unzlibbed successfully ...
        log(string.format("Unzlibbed data retrieved for file %s:: len: %d", filename, #bytes))
        -- ... db files can be reloaded by the game (e.g. when live update is (un)applied in exhibition mode)

        local block_size = 12 -- block size for one competition entry
        local teamID_offs = 0 -- ZERO-based offset!!! Lua indices start from 1!!
        local teamID_len = 4
        local compID_offs = 10 -- ZERO-based offset
        local compID_len = 1

        local i = 0
        local block_start = 1
        while block_start <= #bytes do
            local teamID = memory.unpack("u32", string.sub( bytes, block_start + teamID_offs, block_start + teamID_offs + teamID_len - 1 ))
            local compID = string.byte(string.sub( bytes, block_start + compID_offs, block_start + compID_offs + compID_len - 1 ))     
            --log(string.format("teamID:%s, Comp ID:%s", teamID, compID))
			if m.has_value(playable_league_comp_ids, compID) then -- ignore cups, supercups, etc. - leagues only
                if m.teams_in_playable_leagues_map[compID] ~= nil then
                    if m.has_value(m.teams_in_playable_leagues_map[compID], teamID) == false then
                        table.insert(m.teams_in_playable_leagues_map[compID], teamID)
                    end
                else
                    m.teams_in_playable_leagues_map[compID] = { teamID }
                end
            end

            i = i + 1
            block_start = i * block_size + 1
        end
    else
        log(string.format("Error while unzlibbing %s: %s", filename, m.nil2str(err)))
    end
end

function get_compreg_data(filename, data)
    local bytes, err = m.try_unzlib(data)
    if bytes and (not err or err == "ERR_NOT_ZLIBBED") then
        -- unzlibbed successfully ...
        log(string.format("Unzlibbed data retrieved for file %s:: len: %d", filename, #bytes))
        -- ... db files can be reloaded by the game (e.g. when live update is (un)applied in exhibition mode)

        local block_size =  148 -- 48 (pes 2019) 2352 (pes2021) -- block size for one competition entry
        local tournamentID_offs = 2 -- ZERO-based offset!!! Lua indices start from 1!!
        local tournamentID_len = 2
        local compID_offs = 7 -- 6 (pes 2019) 8 (pes2021)-- ZERO-based offset
        local compID_len = 1

        local i = 0
        local block_start = 1

        while block_start <= #bytes do
            local tournamentID = memory.unpack("u16", string.sub( bytes, block_start + tournamentID_offs, block_start + tournamentID_offs + tournamentID_len - 1 ))
            local compID = string.byte(string.sub( bytes, block_start + compID_offs, block_start + compID_offs + compID_len - 1 ))
            --log(string.format("tournamentID:%s, Comp ID:%s", tournamentID, compID))
            if m.has_value(playable_league_comp_ids, compID) then -- ignore cups, supercups, etc. - leagues only
                if m.compID_to_tournamentID_map[compID] == nil then
                    m.compID_to_tournamentID_map[compID] =  tournamentID
                end
                if m.tournamentID_to_compID_map[tournamentID] == nil then
                    m.tournamentID_to_compID_map[tournamentID] = compID
                end
            end

            i = i + 1
            block_start = i * block_size + 1
        end
    else
        log(string.format("Error while unzlibbing %s: %s", filename, m.nil2str(err)))
    end
end

function read_file_contents(ctx, filename, addr, len, total_size, offset)
    if is_it_compentry_file(filename) then
        -- log("CompetitionEntry.bin intercepted ... " .. filename)
        -- addr is actually a pointer to data in memory, so if we want
        -- to use this data later, we need to make a copy of it now:
        local bytes = memory.read(addr, len)
        -- accumulate data chunks in a table, in case the file is large and gets loaded in mulitiple reads
        compentry_bin_chunks[#compentry_bin_chunks + 1] = bytes
        if offset + len >= total_size then
            -- got everything: now combine all chunks into one binary str
            compentry_bin_full = table.concat(compentry_bin_chunks)
			-- do something useful with full data ...
            get_compentry_data(filename, compentry_bin_full)
            -- ... and release memory held by chunks table
            compentry_bin_chunks = {}
            compentry_bin_full = nil
        end
    end

    if is_it_compreg_file(filename) then
        -- log("CompetitionRegulation.bin intercepted ... " .. filename)
        local bytes = memory.read(addr, len)
        compreg_bin_chunks[#compreg_bin_chunks + 1] = bytes
        if offset + len >= total_size then
            compreg_bin_full = table.concat(compreg_bin_chunks)
            get_compreg_data(filename, compreg_bin_full)
            compreg_bin_chunks = {}
            compreg_bin_full = nil
        end
    end
end


function m.init(ctx)
	ctx.register("livecpk_read", read_file_contents)
	ctx.common_lib = m
end

return m