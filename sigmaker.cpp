#include "converter.h"
#include "generator.h"
#include "misc.h"
#include "search.h"
#include "sigmaker.h"

// idasdk
#include <idp.hpp>
#include <loader.hpp>

static bool idaapi run(size_t arg);
static plugmod_t* idaapi init();

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL,
    init,
    nullptr,
    run,
    PLUGIN_DESCRIPTION,
    nullptr,
    PLUGIN_NAME,
    PLUGIN_HOTKEY
};

static bool idaapi run(size_t arg)
{
    WindowPlugin();
    return true;
}

static plugmod_t* idaapi init()
{
    Settings.Load();
    return PLUGIN_OK;
}

void WindowPlugin()
{
    int action = 0;
    if (ask_form(
        PLUGIN_NAME " " PLUGIN_VERSION "\n"
        /* 00 */    "<#Code\\: Create a function pattern:R>\n"
        /* 01 */    "<#Code\\: Create pattern from position:R>\n"
        /* 02 */    "<#IDA\\: Create a function pattern:R>\n"
        /* 03 */    "<#IDA\\: Create pattern from position:R>\n"
        /* 04 */    "<#Test pattern:R>\n"
        /* 05 */    "<#Converter:R>\n"
        /* 06 */    "<#Options:R>>\n"
        , &action) != 1)
        return;

    switch (action)
    {
    case 0:
    case 1:
        CreateCode(action == 1);
        break;
    case 2:
    case 3:
        CreateIDA(action == 3);
        break;
    case 4:
        WindowTest();
        break;
    case 5:
        WindowConverter();
        break;
    case 6:
        WindowOptions();
        break;
    }
}

void WindowOptions()
{
    ushort dataType = Settings.dataType;
    char wildcard = Settings.wildcard,
        wildcardBuffer[3];
    bool reopen = false;

    qsnprintf(wildcardBuffer, sizeof(wildcardBuffer), "%02X", wildcard);

    if (ask_form(
        "Options\n"
        /* 00 */    "<#Add only relilable data:R>\n"
        /* 01 */    "<#Include unsafe data:R>\n"
        /* 02 */    "<#Algorithm from SourceMod makesig.idc:R>>\n"
        "<Wildcard-byte in signatures:A:3:2:>"
        , &dataType, wildcardBuffer) != 1)
    {
        WindowPlugin();
        return;
    }
    
    Settings.dataType = dataType;

    char* endptr;
    Settings.wildcard = static_cast<unsigned char>(strtoul(wildcardBuffer, &endptr, 16));
    
    if (*endptr != '\0')
    {
        Settings.wildcard = wildcard;
        warning("Invalid wildcard-byte: %s", wildcardBuffer);
        reopen = true;
    }
    
    Settings.Save();

    reopen ? WindowOptions() : WindowPlugin();
}
