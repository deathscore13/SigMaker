#include "misc.h"
#include "sigmaker.h"
#include "generator.h"

// idasdk
#include <diskio.hpp>


Settings_t Settings;

void Settings_t::Save()
{
    qstring path;
    path.sprnt("%s\\" PLUGIN_NAME PLUGIN_VERSION ".bin", get_user_idadir());

    FILE* file = qfopen(path.c_str(), "wb");
    if (file)
    {
        qfwrite(file, this, sizeof(Settings_t));
        qfclose(file);
    }
}

void Settings_t::Load()
{
    qstring path;
    path.sprnt("%s\\" PLUGIN_NAME PLUGIN_VERSION ".bin", get_user_idadir());

    FILE* file = qfopen(path.c_str(), "rb");
    if (file)
    {
        qfread(file, this, sizeof(Settings_t));
        qfclose(file);
    }
    else
    {
        this->Save();
    }
}

void Stage(const char* text)
{
    static const char CHAR = '=';
    static const int WIDTH = 64;
    
    size_t len = strlen(text);
    if (WIDTH <= len)
    {
        msg("%s\n", text);
        return;
    }

    size_t total = WIDTH - len,
        left = total / 2,
        right = total - left;

    msg("%s%s%s\n", qstring(left, CHAR).c_str(), text, qstring(right, CHAR).c_str());
}

bool SigRange(qstring& outSig, bool showError)
{
    twinpos_t pos1, pos2;
    if (!read_selection(get_current_viewer(), &pos1, &pos2))
    {
        if (showError)
            msg("You must select a address\n");

        return false;
    }

    ea_t start = pos1.at->toea(),
        end = pos2.at->toea() + 1;

    if (end - start < SIG_MIN_LEN)
    {
        if (showError)
            msg("Your selection is too short\n");

        return false;
    }

    insn_t ins;
    func_item_iterator_t iter;
    iter.set_range(start, end);
    ea_t current = iter.current();

    while ((current = iter.current()) != BADADDR && decode_insn(&ins, current) != 0)
    {
        if (ins.size < 5)
            AddBytesToSig(outSig, current, ins.size);
        else
            AddInsToSig(&ins, outSig);

        if (iter.next_not_tail() == false)
            break;
    }

    return true;
}
