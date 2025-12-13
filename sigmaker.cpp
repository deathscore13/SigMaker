#include "converter.h"
#include "generator.h"
#include "misc.h"
#include "search.h"
#include "sigmaker.h"

void ShowOptionsWindow()
{
    ushort dataType = Settings.dataType;
    char wildcard = Settings.wildcard,
        wildcardBuffer[3];
    bool reopen = false;

    qsnprintf(wildcardBuffer, sizeof(wildcardBuffer), "%02X", wildcard);

    if (ask_form(
        "Options\n"
        /* 00 */    "<##Generate#Add only relilable data:R>\n"
        /* 01 */    "<#Include unsafe data:R>\n"
        /* 02 */    "<#Algorithm from SourceMod makesig.idc:R>>\n"
        "<Wildcard-byte in signatures:A:3:2:>"
        , &dataType, wildcardBuffer) != 1)
    {
        ShowPluginWindow();
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

    reopen ? ShowOptionsWindow() : ShowPluginWindow();
}

void ShowPluginWindow()
{
    int action = 0;
    if (ask_form(
        PLUGIN_NAME "\n"
        /* 00 */    "<#Auto create IDA pattern:R>\n"
        /* 01 */    "<#Auto create code pattern:R>\n"
        /* 02 */    "<#Create IDA pattern from selection:R>\n"
        /* 03 */    "<#Create code pattern from selection:R>\n"
        /* 04 */    "<#Test IDA pattern:R>\n"
        /* 05 */    "<#Test code pattern:R>\n"
        /* 06 */    "<#Converter:R>\n"
        /* 07 */    "<#Configure the plugin:R>>\n"
        , &action) != 1)
        return;

    switch (action)
    {
    case 0:
        GenerateIDA();
        break;
    case 1:
        GenerateCode();
        break;
    case 2:
        CreateIDA();
        break;
    case 3:
        CreateCode();
        break;
    case 4:
        ShowIDAWindow();
        break;
    case 5:
        ShowCodeWindow();
        break;
    case 6:
        ShowSigConverter();
        break;
    case 7:
        ShowOptionsWindow();
        break;
    }
}

bool idaapi run(size_t arg)
{
    ShowPluginWindow();
    return true;
}

static plugmod_t* idaapi init()
{
    Settings.Load();
    return PLUGIN_OK;
}

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
