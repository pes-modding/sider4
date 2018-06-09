#define UNICODE

//#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <list>
#include <string>
#include <unordered_map>
#include "imageutil.h"
#include "sider.h"
#include "utf8.h"
#include "common.h"
#include "patterns.h"

#include "lua.hpp"
#include "lauxlib.h"
#include "lualib.h"

#ifndef LUA_OK
#define LUA_OK 0
#endif

#define DBG if (_config->_debug)

#define smaller(a,b) ((a<b)?a:b)

using namespace std;

CRITICAL_SECTION _cs;
lua_State *L = NULL;

struct FILE_HANDLE_INFO {
    HANDLE handle;
    DWORD size;
    DWORD sizeHigh;
    DWORD currentOffset;
    DWORD currentOffsetHigh;
    DWORD padding[4];
};

struct FILE_LOAD_INFO {
    BYTE *vtable;
    FILE_HANDLE_INFO *file_handle_info;
    DWORD dw0[2];
    LONGLONG two;
    DWORD dw1[4];
    char *cpk_filename;
    LONGLONG cpk_filesize;
    LONGLONG filesize;
    DWORD dw2[2];
    LONGLONG offset_in_cpk;
    DWORD total_bytes_to_read;
    DWORD max_bytes_to_read;
    DWORD bytes_to_read;
    DWORD bytes_read_so_far;
    DWORD dw3[2];
    LONGLONG buffer_size;
    BYTE *buffer;
    BYTE *buffer2;
};

struct READ_STRUCT {
    BYTE b0[0xa0];
    LONGLONG filesize;
    FILE_HANDLE_INFO *fileinfo;
    union {
        struct {
            DWORD low;
            DWORD high;
        } parts;
        LONGLONG full;
    } offset;
    BYTE b1[0x20];
    char filename[0x80];
};

struct BUFFER_INFO {
    LONGLONG data0;
    BYTE *someptr;
    LONGLONG data1;
    BYTE *buffer;
    BYTE *buffer2;
    BYTE b0[0x1c0];
    char *filename;
};

struct FILE_INFO {
    DWORD size;
    DWORD size_uncompressed;
    LONGLONG offset_in_cpk;
};

typedef unordered_map<string,wstring*> lookup_cache_t;
lookup_cache_t _lookup_cache;

//typedef LONGLONG (*pfn_alloc_mem_t)(BUFFER_INFO *bi, LONGLONG size);
//pfn_alloc_mem_t _org_alloc_mem;

extern "C" BOOL sider_read_file(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped,
    struct READ_STRUCT *rs);

extern "C" void sider_get_size(char *filename, struct FILE_INFO *fi);

extern "C" BOOL sider_read_file_hk(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped);

extern "C" void sider_get_size_hk();

extern "C" void sider_extend_cpk_hk();

static DWORD dwThreadId;
static DWORD hookingThreadId = 0;
static HMODULE myHDLL;
static HHOOK handle;

bool _is_game(false);
bool _is_sider(false);
bool _is_edit_mode(false);
HANDLE _mh = NULL;

struct module_t {
    lookup_cache_t *cache;
    lua_State* L;
    /*
    int evt_trophy_check;
    int evt_lcpk_make_key;
    int evt_lcpk_get_filepath;
    int evt_lcpk_rewrite;
    int evt_set_home_team;
    int evt_set_away_team;
    int evt_set_tid;
    int evt_set_match_time;
    int evt_set_stadium_choice;
    int evt_set_stadium;
    int evt_set_conditions;
    int evt_after_set_conditions;
    int evt_set_stadium_for_replay;
    int evt_set_conditions_for_replay;
    int evt_after_set_conditions_for_replay;
    int evt_get_ball_name;
    int evt_get_stadium_name;
    int evt_enter_edit_mode;
    int evt_exit_edit_mode;
    int evt_enter_replay_gallery;
    int evt_exit_replay_gallery;
    */
};
list<module_t*> _modules;
module_t* _curr_m;

wchar_t module_filename[MAX_PATH];
wchar_t dll_log[MAX_PATH];
wchar_t dll_ini[MAX_PATH];
wchar_t sider_dir[MAX_PATH];

static void string_strip_quotes(wstring& s)
{
    static const wchar_t* chars = L" \t\n\r\"'";
    int e = s.find_last_not_of(chars);
    s.erase(e + 1);
    int b = s.find_first_not_of(chars);
    s.erase(0,b);
}

class config_t {
public:
    bool _debug;
    bool _livecpk_enabled;
    bool _lookup_cache_enabled;
    bool _lua_enabled;
    bool _luajit_extensions_enabled;
    list<wstring> _lua_extra_globals;
    int _dll_mapping_option;
    wstring _section_name;
    list<wstring> _code_sections;
    list<wstring> _cpk_roots;
    list<wstring> _exe_names;
    list<wstring> _module_names;
    bool _close_sider_on_exit;
    bool _start_minimized;
    BYTE *_hp_at_read_file;
    BYTE *_hp_at_get_size;
    BYTE *_hp_at_extend_cpk;

    ~config_t() {}
    config_t(const wstring& section_name, const wchar_t* config_ini) :
                 _section_name(section_name),
                 _debug(false),
                 _livecpk_enabled(false),
                 _lookup_cache_enabled(true),
                 _lua_enabled(true),
                 _luajit_extensions_enabled(false),
                 _close_sider_on_exit(false),
                 _start_minimized(false),
                 _hp_at_read_file(NULL),
                 _hp_at_get_size(NULL),
                 _hp_at_extend_cpk(NULL)
    {
        wchar_t settings[32767];
        RtlZeroMemory(settings, sizeof(settings));
        GetPrivateProfileSection(_section_name.c_str(),
            settings, sizeof(settings)/sizeof(wchar_t), config_ini);

        wchar_t* p = settings;
        while (*p) {
            wstring pair(p);
            wstring key(pair.substr(0, pair.find(L"=")));
            wstring value(pair.substr(pair.find(L"=")+1));
            string_strip_quotes(value);

            if (wcscmp(L"exe.name", key.c_str())==0) {
                _exe_names.push_back(value);
            }
            else if (wcscmp(L"code.section", key.c_str())==0) {
                _code_sections.push_back(value);
            }
            else if (wcscmp(L"lua.module", key.c_str())==0) {
                _module_names.push_back(value);
            }
            else if (wcscmp(L"lua.extra-globals", key.c_str())==0) {
                bool done(false);
                int start = 0, end = 0;
                while (!done) {
                    end = value.find(L",", start);
                    done = (end == string::npos);

                    wstring name((done) ?
                        value.substr(start) :
                        value.substr(start, end - start));
                    string_strip_quotes(name);
                    if (!name.empty()) {
                        _lua_extra_globals.push_back(name);
                    }
                    start = end + 1;
                }
            }
            else if (wcscmp(L"cpk.root", key.c_str())==0) {
                if (value[value.size()-1] != L'\\') {
                    value += L'\\';
                }
                // handle relative roots
                if (value[0]==L'.') {
                    wstring rel(value);
                    value = sider_dir;
                    value += rel;
                }
                _cpk_roots.push_back(value);
            }

            p += wcslen(p) + 1;
        }

        _debug = GetPrivateProfileInt(_section_name.c_str(),
            L"debug", _debug,
            config_ini);

        _close_sider_on_exit = GetPrivateProfileInt(_section_name.c_str(),
            L"close.on.exit", _close_sider_on_exit,
            config_ini);

        _start_minimized = GetPrivateProfileInt(_section_name.c_str(),
            L"start.minimized", _start_minimized,
            config_ini);

        _livecpk_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"livecpk.enabled", _livecpk_enabled,
            config_ini);

        _lookup_cache_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"lookup-cache.enabled", _lookup_cache_enabled,
            config_ini);

        _lua_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"lua.enabled", _lua_enabled,
            config_ini);

        _luajit_extensions_enabled = GetPrivateProfileInt(_section_name.c_str(),
            L"luajit.ext.enabled", _luajit_extensions_enabled,
            config_ini);
    }
};

config_t* _config;

bool init_paths() {
    wchar_t *p;

    // prep log filename
    memset(dll_log, 0, sizeof(dll_log));
    if (GetModuleFileName(myHDLL, dll_log, MAX_PATH)==0) {
        return FALSE;
    }
    p = wcsrchr(dll_log, L'.');
    wcscpy(p, L".log");

    // prep ini filename
    memset(dll_ini, 0, sizeof(dll_ini));
    wcscpy(dll_ini, dll_log);
    p = wcsrchr(dll_ini, L'.');
    wcscpy(p, L".ini");

    // prep sider dir
    memset(sider_dir, 0, sizeof(sider_dir));
    wcscpy(sider_dir, dll_log);
    p = wcsrchr(sider_dir, L'\\');
    *(p+1) = L'\0';

    return true;
}

static int sider_log(lua_State *L) {
    const char *s = luaL_checkstring(L, -1);
    lua_getfield(L, lua_upvalueindex(1), "_FILE");
    const char *fname = lua_tostring(L, -1);
    logu_("[%s] %s\n", fname, s);
    lua_pop(L, 2);
    return 0;
}

void read_configuration(config_t*& config)
{
    wchar_t names[1024];
    size_t names_len = sizeof(names)/sizeof(wchar_t);
    GetPrivateProfileSectionNames(names, names_len, dll_ini);

    wchar_t *p = names;
    while (p && *p) {
        wstring name(p);
        if (name == L"sider") {
            config = new config_t(name, dll_ini);
            break;
        }
        p += wcslen(p) + 1;
    }
}

static bool skip_process(wchar_t* name)
{
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        if (wcsicmp(filename, L"\\explorer.exe") == 0) {
            return true;
        }
        if (wcsicmp(filename, L"\\steam.exe") == 0) {
            return true;
        }
        if (wcsicmp(filename, L"\\steamwebhelper.exe") == 0) {
            return true;
        }
    }
    return false;
}

static bool is_sider(wchar_t* name)
{
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        if (wcsicmp(filename, L"\\sider.exe") == 0) {
            return true;
        }
    }
    return false;
}

static bool write_mapping_info(config_t *config)
{
    // determine the size needed
    DWORD size = sizeof(wchar_t);
    list<wstring>::iterator it;
    for (it = _config->_exe_names.begin();
            it != _config->_exe_names.end();
            it++) {
        size += sizeof(wchar_t) * (it->size() + 1);
    }

    _mh = CreateFileMapping(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE | SEC_COMMIT,
        0, size, SIDER_FM);
    if (!_mh) {
        log_(L"W: CreateFileMapping FAILED: %d\n", GetLastError());
        return false;
    }
    wchar_t *mem = (wchar_t*)MapViewOfFile(_mh, FILE_MAP_WRITE, 0, 0, 0);
    if (!mem) {
        log_(L"W: MapViewOfFile FAILED: %d\n", GetLastError());
        CloseHandle(_mh);
        return false;
    }

    memset(mem, 0, size);
    for (it = config->_exe_names.begin();
            it != _config->_exe_names.end();
            it++) {
        wcscpy(mem, it->c_str());
        mem += it->size() + 1;
    }
    return true;
}

static bool is_pes(wchar_t* name, wstring** match)
{
    HANDLE h = OpenFileMapping(FILE_MAP_READ, FALSE, SIDER_FM);
    if (!h) {
        int err = GetLastError();
        wchar_t *t = new wchar_t[MAX_PATH];
        GetModuleFileName(NULL, t, MAX_PATH);
        log_(L"R: OpenFileMapping FAILED (for %s): %d\n", t, err);
        delete t;
        return false;
    }
    BYTE *patterns = (BYTE*)MapViewOfFile(h, FILE_MAP_READ, 0, 0, 0);
    if (!patterns) {
        int err= GetLastError();
        wchar_t *t = new wchar_t[MAX_PATH];
        GetModuleFileName(NULL, t, MAX_PATH);
        log_(L"R: MapViewOfFile FAILED (for %s): %d\n", t, err);
        delete t;
        CloseHandle(h);
        return false;
    }

    bool result = false;
    wchar_t *filename = wcsrchr(name, L'\\');
    if (filename) {
        wchar_t *s = (wchar_t*)patterns;
        while (*s != L'\0') {
            if (wcsicmp(filename, s) == 0) {
                *match = new wstring(s);
                result = true;
                break;
            }
            s = s + wcslen(s) + 1;
        }
    }
    UnmapViewOfFile(h);
    CloseHandle(h);
    return result;
}

wstring* _have_live_file(char *file_name)
{
    wchar_t unicode_filename[512];
    memset(unicode_filename, 0, sizeof(unicode_filename));
    Utf8::fUtf8ToUnicode(unicode_filename, file_name);

    wchar_t fn[512];
    for (list<wstring>::iterator it = _config->_cpk_roots.begin();
            it != _config->_cpk_roots.end();
            it++) {
        memset(fn, 0, sizeof(fn));
        wcscpy(fn, it->c_str());
        wchar_t *p = (unicode_filename[0] == L'\\') ? unicode_filename + 1 : unicode_filename;
        wcscat(fn, p);

        HANDLE handle;
        handle = CreateFileW(fn,           // file to open
                           GENERIC_READ,          // open for reading
                           FILE_SHARE_READ,       // share for reading
                           NULL,                  // default security
                           OPEN_EXISTING,         // existing file only
                           FILE_ATTRIBUTE_NORMAL,  // normal file
                           NULL);                 // no attr. template

        if (handle != INVALID_HANDLE_VALUE)
        {
            CloseHandle(handle);
            return new wstring(fn);
        }
    }

    return NULL;
}

wstring* have_live_file(char *file_name)
{
    //logu_("have_live_file: %p --> %s\n", (DWORD)file_name, file_name);
    if (!_config->_lookup_cache_enabled) {
        // no cache
        return _have_live_file(file_name);
    }
    unordered_map<string,wstring*>::iterator it;
    it = _lookup_cache.find(string(file_name));
    if (it != _lookup_cache.end()) {
        return it->second;
    }
    else {
        //logu_("_lookup_cache MISS for (%s)\n", file_name);
        wstring* res = _have_live_file(file_name);
        _lookup_cache.insert(pair<string,wstring*>(string(file_name),res));
        return res;
    }
}

bool file_exists(wstring *fullpath, LONGLONG *size)
{
    HANDLE handle = CreateFileW(
        fullpath->c_str(),     // file to open
        GENERIC_READ,          // open for reading
        FILE_SHARE_READ,       // share for reading
        NULL,                  // default security
        OPEN_EXISTING,         // existing file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                 // no attr. template

    if (handle != INVALID_HANDLE_VALUE)
    {
        if (size != NULL) {
            DWORD *p = (DWORD*)size;
            *size = GetFileSize(handle, p+1);
        }
        CloseHandle(handle);
        return true;
    }
    return false;
}

__declspec(dllexport) bool start_minimized()
{
    return _config && _config->_start_minimized;
}

void sider_get_size(char *filename, struct FILE_INFO *fi)
{
    wstring *fn;
    fn = have_live_file(filename);
    if (fn != NULL) {
        log_(L"get_size:: livecpk file found: %s\n", fn->c_str());
        HANDLE handle = CreateFileW(fn->c_str(),  // file to open
                           GENERIC_READ,          // open for reading
                           FILE_SHARE_READ,       // share for reading
                           NULL,                  // default security
                           OPEN_EXISTING,         // existing file only
                           FILE_ATTRIBUTE_NORMAL, // normal file
                           NULL);                 // no attr. template

        if (handle != INVALID_HANDLE_VALUE)
        {
            DWORD sz = GetFileSize(handle, NULL);
            log_(L"get_size:: livecpk file size: %x vs original size in cpk: %x\n", sz, fi->size);
            CloseHandle(handle);
            fi->size = sz;
            fi->size_uncompressed = sz;
            //fi->offset_in_cpk = 0;
        }
    }
}

BOOL sider_read_file(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped,
    struct READ_STRUCT *rs)
{
    BOOL result;
    HANDLE orgHandle = hFile;
    DWORD orgBytesToRead = nNumberOfBytesToRead;
    HANDLE handle = INVALID_HANDLE_VALUE;
    wstring *filename = NULL;

    //log_(L"rs (R12) = %p\n", rs);
    if (rs) {
        //logu_("rs->filesize: %llx, rs->offset: %llx, rs->filename: %s\n",
        //    rs->filesize, rs->offset.full, rs->filename);

        BYTE* p = (BYTE*)rs;
        FILE_LOAD_INFO *fli = *((FILE_LOAD_INFO **)(p - 0x18));
        /*
        if (fli) {
            // log some info about this file loading operation
            logu_("fli->cpk_filename: %s\n", fli->cpk_filename);
            logu_("fli->cpk_filesize: %llx\n", fli->cpk_filesize);
            logu_("fli->offset_in_cpk: %llx\n", fli->offset_in_cpk);
            logu_("fli->filesize: %llx\n", fli->filesize);
            logu_("fli->total_bytes_to_read: %x\n", fli->total_bytes_to_read);
            logu_("fli->max_bytes_to_read: %x\n", fli->max_bytes_to_read);
            logu_("fli->bytes_read_so_far: %x\n", fli->bytes_read_so_far);
            logu_("fli->bytes_to_read: %x\n", fli->bytes_to_read);
            logu_("fli->buffer_size: %llx\n", fli->buffer_size);
            logu_("fli->buffer: %p\n", fli->buffer);
            logu_("fli->buffer2: %p\n", fli->buffer2);
        }
        */

        filename = have_live_file(rs->filename);
        if (filename != NULL) {
            log_(L"read_file:: livecpk file found: %s\n", filename->c_str());
            handle = CreateFileW(filename->c_str(),   // file to open
                               GENERIC_READ,          // open for reading
                               FILE_SHARE_READ,       // share for reading
                               NULL,                  // default security
                               OPEN_EXISTING,         // existing file only
                               FILE_ATTRIBUTE_NORMAL, // normal file
                               NULL);                 // no attr. template

            if (handle != INVALID_HANDLE_VALUE)
            {
                DWORD sz = GetFileSize(handle, NULL);
                //log_(L"livecpk file size: %x (decimal: %u) vs original size in cpk: %x (decimal: %u)\n",
                //    sz, sz, rs->filesize, rs->filesize);

                // replace file handle
                orgHandle = hFile;
                hFile = handle;

                // set correct offset
                LONG offsetHigh = rs->offset.parts.high;
                SetFilePointer(hFile, rs->offset.parts.low, &offsetHigh, FILE_BEGIN);
                rs->offset.parts.high = offsetHigh;
                LONGLONG offset = rs->offset.full;

                if (fli) {
                    // adjust offset for multi-part reads
                    SetFilePointer(hFile, fli->bytes_read_so_far, NULL, FILE_CURRENT);
                    offset = offset + fli->bytes_read_so_far;

                    // trace file read info
                    DBG logu_("read_file:: fli->total_bytes_to_read: %x\n", fli->total_bytes_to_read);
                    DBG logu_("read_file:: fli->max_bytes_to_read: %x\n", fli->max_bytes_to_read);
                    DBG logu_("read_file:: fli->bytes_to_read: %x\n", fli->bytes_to_read);
                    DBG logu_("read_file:: fli->bytes_read_so_far: %x\n", fli->bytes_read_so_far);
                    DBG logu_("read_file:: fli->filesize: %llx\n", fli->filesize);
                    DBG logu_("read_file:: fli->buffer_size: %llx\n", fli->buffer_size);
                    DBG logu_("read_file:: fli->cpk_filename: %s\n", fli->cpk_filename);
                    DBG logu_("read_file:: fli->offset_in_cpk: %llx\n", fli->offset_in_cpk);
                }

                log_(L"read_file:: livecpk file offset: %llx\n", offset);
            }
        }
    }

    result = ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    //log_(L"ReadFile(%x, %p, %x, %x, %p)\n",
    //    hFile, lpBuffer, nNumberOfBytesToRead, *lpNumberOfBytesRead, lpOverlapped);

    if (handle != INVALID_HANDLE_VALUE) {
        log_(L"read_file:: called ReadFile(%x, %p, %x, %x, %p)\n",
            hFile, lpBuffer, nNumberOfBytesToRead, *lpNumberOfBytesRead, lpOverlapped);
        CloseHandle(handle);

        if (orgBytesToRead > *lpNumberOfBytesRead) {
            //log_(L"file-size adjustment: actually read = %x, reporting as read = %x\n",
            //    *lpNumberOfBytesRead, orgBytesToRead);
        }

        // fake a read from cpk
        if (orgBytesToRead > *lpNumberOfBytesRead) {
            *lpNumberOfBytesRead = orgBytesToRead;
        }
        //SetFilePointer(orgHandle, *lpNumberOfBytesRead, 0, FILE_CURRENT);
    }

    return result;
}

BYTE* get_target_location(BYTE *call_location)
{
    if (call_location) {
        BYTE* bptr = call_location;
        DWORD protection = 0;
        DWORD newProtection = PAGE_EXECUTE_READWRITE;
        if (VirtualProtect(bptr, 8, newProtection, &protection)) {
            // get memory location where call target addr is stored
            // format of indirect call is like this:
            // call [addr] : FF 15 <4-byte-offset>
            DWORD* ptr = (DWORD*)(call_location + 2);
            return call_location + 6 + ptr[0];
        }
    }
    return NULL;
}

void hook_indirect_call(BYTE *loc, BYTE *p) {
    if (!loc) {
        return;
    }
    DWORD protection = 0;
    DWORD newProtection = PAGE_EXECUTE_READWRITE;
    BYTE *addr_loc = get_target_location(loc);
    log_(L"loc: %p, addr_loc: %p\n", loc, addr_loc);
    if (VirtualProtect(addr_loc, 8, newProtection, &protection)) {
        BYTE** v = (BYTE**)addr_loc;
        *v = p;
        log_(L"hook_indirect_call: hooked at %p\n", loc);
    }
}

void hook_call(BYTE *loc, BYTE *p, size_t nops) {
    if (!loc) {
        return;
    }
    DWORD protection = 0;
    DWORD newProtection = PAGE_EXECUTE_READWRITE;
    if (VirtualProtect(loc, 16, newProtection, &protection)) {
        memcpy(loc, "\x48\xb8", 2);
        memcpy(loc+2, &p, sizeof(BYTE*));  // mov rax,<target_addr>
        memcpy(loc+10, "\xff\xd0", 2);      // call rax
        if (nops) {
            memset(loc+12, '\x90', nops);  // nop ;one of more nops for padding
        }
        log_(L"hook_call: hooked at %p\n", loc);
    }
}

static void push_context_table(lua_State *L)
{
    lua_newtable(L);

    char *sdir = (char*)Utf8::unicodeToUtf8(sider_dir);
    lua_pushstring(L, sdir);
    Utf8::free(sdir);
    lua_setfield(L, -2, "sider_dir");

    //lua_pushcfunction(L, sider_context_register);
    //lua_setfield(L, -2, "register");
}

static void push_env_table(lua_State *L, const wchar_t *script_name)
{
    char *sandbox[] = {
        "assert", "table", "pairs", "ipairs",
        "string", "math", "tonumber", "tostring",
        "unpack", "error", "_VERSION", "type", "io",
    };

    lua_newtable(L);
    for (int i=0; i<sizeof(sandbox)/sizeof(char*); i++) {
        lua_pushstring(L, sandbox[i]);
        lua_getglobal(L, sandbox[i]);
        lua_settable(L, -3);
    }
    /* DISABLING FOR NOW, as this is a SECURITY issue
    // extra globals
    for (list<wstring>::iterator i = _config->_lua_extra_globals.begin();
            i != _config->_lua_extra_globals.end();
            i++) {
        char *name = (char*)Utf8::unicodeToUtf8(i->c_str());
        lua_pushstring(L, name);
        lua_getglobal(L, name);
        if (lua_isnil(L, -1)) {
            logu_("WARNING: Unknown Lua global: %s. Skipping it\n",
                name);
            lua_pop(L, 2);
        }
        else {
            lua_settable(L, -3);
        }
        Utf8::free(name);
    }
    */

    // stripped-down os library: with only time, clock, and date
    char *os_names[] = { "time", "clock", "date" };
    lua_newtable(L);
    lua_getglobal(L, "os");
    for (int i=0; i<sizeof(os_names)/sizeof(char*); i++) {
        lua_getfield(L, -1, os_names[i]);
        lua_setfield(L, -3, os_names[i]);
    }
    lua_pop(L, 1);
    lua_setfield(L, -2, "os");

    lua_pushstring(L, "log");
    lua_pushvalue(L, -2);  // upvalue for sider_log C-function
    lua_pushcclosure(L, sider_log, 1);
    lua_settable(L, -3);
    lua_pushstring(L, "_FILE");
    char *sname = (char*)Utf8::unicodeToUtf8(script_name);
    lua_pushstring(L, sname);
    Utf8::free(sname);
    lua_settable(L, -3);

    /*
    // memory lib
    lua_newtable(L);
    lua_pushstring(L, "read");
    lua_pushcclosure(L, memory_read, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "write");
    lua_pushcclosure(L, memory_write, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "search");
    lua_pushcclosure(L, memory_search, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "pack");
    lua_pushcclosure(L, memory_pack, 0);
    lua_settable(L, -3);
    lua_pushstring(L, "unpack");
    lua_pushcclosure(L, memory_unpack, 0);
    lua_settable(L, -3);
    lua_setfield(L, -2, "memory");

    // gameplay lib
    init_gameplay_lib(L);

    // gfx lib
    init_gfx_lib(L);
    */

    // set _G
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "_G");

    // load some LuaJIT extenstions
    if (_config->_luajit_extensions_enabled) {
        char *ext[] = { "ffi", "bit" };
        for (int i=0; i<sizeof(ext)/sizeof(char*); i++) {
            lua_getglobal(L, "require");
            lua_pushstring(L, ext[i]);
            if (lua_pcall(L, 1, 1, 0) != 0) {
                const char *err = luaL_checkstring(L, -1);
                logu_("Problem loading LuaJIT module (%s): %s\n. "
                      "Skipping it.\n", ext[i], err);
                lua_pop(L, 1);
                continue;
            }
            else {
                lua_setfield(L, -2, ext[i]);
            }
        }
    }
}

void init_lua_support()
{
    if (_config->_lua_enabled) {
        log_(L"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        log_(L"Initilizing Lua module system:\n");
        log_(L"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");

        // load and initialize lua modules
        L = luaL_newstate();
        luaL_openlibs(L);

        // prepare context table
        push_context_table(L);

        // load registered modules
        for (list<wstring>::iterator it = _config->_module_names.begin();
                it != _config->_module_names.end();
                it++) {
            // Use Win32 API to read the script into a buffer:
            // we do not want any nasty surprises with filename encodings
            wstring script_file(sider_dir);
            script_file += L"modules\\";
            script_file += it->c_str();

            log_(L"Loading module: %s ...\n", it->c_str());

            DWORD size = 0;
            HANDLE handle;
            handle = CreateFileW(
                script_file.c_str(),   // file to open
                GENERIC_READ,          // open for reading
                FILE_SHARE_READ,       // share for reading
                NULL,                  // default security
                OPEN_EXISTING,         // existing file only
                FILE_ATTRIBUTE_NORMAL, // normal file
                NULL);                 // no attr. template

            if (handle == INVALID_HANDLE_VALUE)
            {
                log_(L"PROBLEM: Unable to open file: %s\n",
                    script_file.c_str());
                continue;
            }

            size = GetFileSize(handle, NULL);
            BYTE *buf = new BYTE[size+1];
            memset(buf, 0, size+1);
            DWORD bytesRead = 0;
            if (!ReadFile(handle, buf, size, &bytesRead, NULL)) {
                log_(L"PROBLEM: ReadFile error for lua module: %s\n",
                    it->c_str());
                CloseHandle(handle);
                continue;
            }
            CloseHandle(handle);
            // script is now in memory

            char *mfilename = (char*)Utf8::unicodeToUtf8(it->c_str());
            string mfile(mfilename);
            Utf8::free(mfilename);
            int r = luaL_loadbuffer(L, (const char*)buf, size, mfile.c_str());
            delete buf;
            if (r != 0) {
                const char *err = lua_tostring(L, -1);
                logu_("Lua module loading problem: %s. "
                      "Skipping it\n", err);
                lua_pop(L, 1);
                continue;
            }

            // set environment
            push_env_table(L, it->c_str());
            lua_setfenv(L, -2);

            // run the module
            if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                logu_("Lua module initializing problem: %s. "
                      "Skipping it\n", err);
                lua_pop(L, 1);
                continue;
            }

            // check that module chunk is correctly constructed:
            // it must return a table
            if (!lua_istable(L, -1)) {
                logu_("PROBLEM: Lua module (%s) must return a table. "
                      "Skipping it\n", mfile.c_str());
                lua_pop(L, 1);
                continue;
            }

            // now we have module table on the stack
            // run its "init" method, with a context object
            lua_getfield(L, -1, "init");
            if (!lua_isfunction(L, -1)) {
                logu_("PROBLEM: Lua module (%s) does not "
                      "have \"init\" function. Skipping it.\n",
                      mfile.c_str());
                lua_pop(L, 1);
                continue;
            }

            module_t *m = new module_t();
            memset(m, 0, sizeof(module_t));
            m->cache = new lookup_cache_t();
            m->L = luaL_newstate();
            _curr_m = m;

            lua_pushvalue(L, 1); // ctx
            if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                logu_("PROBLEM: Lua module (%s) \"init\" function "
                      "returned an error: %s\n", mfile.c_str(), err);
                logu_("Module (%s) is NOT activated\n", mfile.c_str());
                lua_pop(L, 1);
                // pop the module table too, since we are not using it
                lua_pop(L, 1);
            }
            else {
                logu_("OK: Lua module initialized: %s\n", mfile.c_str());
                logu_("gettop: %d\n", lua_gettop(L));

                // add to list of loaded modules
                _modules.push_back(m);
            }
        }
        log_(L"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
        log_(L"Lua module system initialized.\n");
        log_(L"Active modules: %d\n", _modules.size());
        log_(L"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
    }
}

bool _install_func(IMAGE_SECTION_HEADER *h);

DWORD install_func(LPVOID thread_param) {
    log_(L"DLL attaching to (%s).\n", module_filename);
    log_(L"Mapped into PES.\n");
    logu_("UTF-8 check: ленинградское время ноль часов ноль минут.\n");

    _is_game = true;
    _is_edit_mode = false;

    InitializeCriticalSection(&_cs);
    //_addr_cache = new addr_cache_t(&_cs);

    log_(L"debug = %d\n", _config->_debug);
    //if (_config->_game_speed) {
    //    log_(L"game.speed = %0.3f\n", *(_config->_game_speed));
    //}
    log_(L"livecpk.enabled = %d\n", _config->_livecpk_enabled);
    log_(L"lookup-cache.enabled = %d\n", _config->_lookup_cache_enabled);
    log_(L"lua.enabled = %d\n", _config->_lua_enabled);
    log_(L"luajit.ext.enabled = %d\n", _config->_luajit_extensions_enabled);
    //log_(L"address-cache.enabled = %d\n", (int)(!_config->_ac_off));
    log_(L"close.on.exit = %d\n", _config->_close_sider_on_exit);
    log_(L"start.minimized = %d\n", _config->_start_minimized);

    for (list<wstring>::iterator it = _config->_cpk_roots.begin();
            it != _config->_cpk_roots.end();
            it++) {
        log_(L"Using cpk.root: %s\n", it->c_str());
    }

    if (_config->_code_sections.size() == 0) {
        log_(L"No code sections specified in config: nothing to do then.");
        return 0;
    }

    list<wstring>::iterator it = _config->_code_sections.begin();
    for (; it != _config->_code_sections.end(); it++) {
        char *section_name = (char*)Utf8::unicodeToUtf8(it->c_str());
        IMAGE_SECTION_HEADER *h = GetSectionHeader(section_name);
        Utf8::free(section_name);

        if (!h) {
            log_(L"Unable to find code section: %s. Skipping\n", it->c_str());
            continue;
        }
        logu_("h->Misc.VirtualSize: %p\n", h->Misc.VirtualSize);
        if (h->Misc.VirtualSize < 0x10000) {
            log_(L"Section too small: %s (%p). Skipping\n", it->c_str(), h->Misc.VirtualSize);
            continue;
        }

        log_(L"Examining code section: %s\n", it->c_str());
        if (_install_func(h)) {
            init_lua_support();
            break;
        }
    }
    log_(L"Sider initialization complete.\n");
    return 0;
}

bool all_found(config_t *cfg) {
    return (
        cfg->_hp_at_read_file > 0 &&
        cfg->_hp_at_get_size > 0 &&
        cfg->_hp_at_extend_cpk > 0
    );
}

bool _install_func(IMAGE_SECTION_HEADER *h) {
    BYTE* base = (BYTE*)GetModuleHandle(NULL);
    base += h->VirtualAddress;
    log_(L"Searching code section at: %p\n", base);
    bool result(false);

#define NUM_PATTERNS 3
    if (_config->_livecpk_enabled) {
        BYTE *frag[NUM_PATTERNS];
        frag[0] = lcpk_pattern_at_read_file;
        frag[1] = lcpk_pattern_at_get_size;
        frag[2] = lcpk_pattern_at_write_cpk_filesize;
        size_t frag_len[NUM_PATTERNS];
        frag_len[0] = sizeof(lcpk_pattern_at_read_file)-1;
        frag_len[1] = sizeof(lcpk_pattern_at_get_size)-1;
        frag_len[2] = sizeof(lcpk_pattern_at_write_cpk_filesize)-1;
        int offs[NUM_PATTERNS];
        offs[0] = lcpk_offs_at_read_file;
        offs[1] = lcpk_offs_at_get_size;
        offs[2] = lcpk_offs_at_write_cpk_filesize;
        BYTE **addrs[NUM_PATTERNS];
        addrs[0] = &_config->_hp_at_read_file;
        addrs[1] = &_config->_hp_at_get_size;
        addrs[2] = &_config->_hp_at_extend_cpk;

        for (int j=0; j<NUM_PATTERNS; j++) {
            BYTE *p = find_code_frag(base, h->Misc.VirtualSize,
                frag[j], frag_len[j]);
            if (!p) {
                continue;
            }
            *(addrs[j]) = p + offs[j];
        }

        if (all_found(_config)) {
            result = true;

            // hooks
            log_(L"DBG:: sider_read_file_hk: %p\n", sider_read_file_hk);
            log_(L"DBG:: sider_get_size_hk: %p\n", sider_get_size_hk);
            log_(L"DBG:: sider_extend_cpk_hk: %p\n", sider_extend_cpk_hk);

            hook_indirect_call(_config->_hp_at_read_file, (BYTE*)sider_read_file_hk);
            hook_call(_config->_hp_at_get_size, (BYTE*)sider_get_size_hk, 0);
            hook_call(_config->_hp_at_extend_cpk, (BYTE*)sider_extend_cpk_hk, 1);
        }
    }

    return result;
}

INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
    wstring *match = NULL;
    INT result = FALSE;
    HWND main_hwnd;

    switch(Reason) {
        case DLL_PROCESS_ATTACH:
            myHDLL = hDLL;
            memset(module_filename, 0, sizeof(module_filename));
            if (GetModuleFileName(NULL, module_filename, MAX_PATH)==0) {
                return FALSE;
            }
            if (!init_paths()) {
                return FALSE;
            }
            //log_(L"DLL_PROCESS_ATTACH: %s\n", module_filename);
            if (skip_process(module_filename)) {
                return FALSE;
            }

            if (is_sider(module_filename)) {
                _is_sider = true;
                read_configuration(_config);
                if (!write_mapping_info(_config)) {
                    return FALSE;
                }
                return TRUE;
            }

            if (is_pes(module_filename, &match)) {
                read_configuration(_config);

                wstring version;
                get_module_version(hDLL, version);
                log_(L"============================\n");
                log_(L"Sider DLL: version %s\n", version.c_str());
                log_(L"Filename match: %s\n", match->c_str());

                install_func(NULL);

                delete match;
                return TRUE;
            }

            return result;
            break;

        case DLL_PROCESS_DETACH:
            //log_(L"DLL_PROCESS_DETACH: %s\n", module_filename);

            if (_is_sider) {
                UnmapViewOfFile(_mh);
                CloseHandle(_mh);
            }

            if (_is_game) {
                log_(L"DLL detaching from (%s).\n", module_filename);
                log_(L"Unmapping from PES.\n");

                if (L) { lua_close(L); }
                DeleteCriticalSection(&_cs);

                // tell sider.exe to close
                if (_config->_close_sider_on_exit) {
                    main_hwnd = FindWindow(SIDERCLS, NULL);
                    if (main_hwnd) {
                        PostMessage(main_hwnd, SIDER_MSG_EXIT, 0, 0);
                        log_(L"Posted message for sider.exe to quit\n");
                    }
                }
            }
            break;

        case DLL_THREAD_ATTACH:
            //log_(L"DLL_THREAD_ATTACH: %s\n", module_filename);
            break;

        case DLL_THREAD_DETACH:
            //log_(L"DLL_THREAD_DETACH: %s\n", module_filename);
            break;

    }

    return TRUE;
}

LRESULT CALLBACK meconnect(int code, WPARAM wParam, LPARAM lParam)
{
    if (hookingThreadId == GetCurrentThreadId()) {
        log_(L"called in hooking thread!\n");
    }
    return CallNextHookEx(handle, code, wParam, lParam);
}

void setHook()
{
    handle = SetWindowsHookEx(WH_CBT, meconnect, myHDLL, 0);
    log_(L"------------------------\n");
    log_(L"handle = %p\n", handle);
}

void unsetHook()
{
    UnhookWindowsHookEx(handle);
}
