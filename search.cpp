#include "converter.h"
#include "idaEx.h"
#include "misc.h"
#include "search.h"

// idasdk
#include <funcs.hpp>
#include <kernwin.hpp>
#include <search.hpp>

static int idaapi WindowTestChangeCB(int field_id, form_actions_t& fa)
{
    if (field_id < 0)
        return 1;

    int mask = 0;
    fa.get_combobox_value(1, &mask);
    fa.enable_field(3, !mask);

    return 1;
}

void WindowTest()
{
    qstring sig, mask;
    if (SigRange(sig))
        IDAToCode(sig, sig, mask);

    int action = 0;
    if (ask_form(
        "Test pattern\n"
        "%/"
        "Enter or select a range\n"
        "<Signature :q::64:>\n"
        "<Mask      :q3::64:>\n"
        "<#Code:R0>\n"
        "<#IDA:R1>>\n",
        WindowTestChangeCB,
        &sig, &mask, &action) != 1)
        return;

    switch (action)
    {
    case 0:
        if (CodeToIDA(sig, mask, sig))
        {
            Stage(" Test code pattern ");
            SearchForSigs(sig);
            Stage("");
        }
        else
        {
            msg("Empty signature or mask\n");
        }
        break;
    case 1:
        idaEx::ltrim(sig);
        sig.rtrim();

        if (sig.empty())
        {
            msg("Empty signature\n");
            break;
        }

        Stage(" Test IDA pattern ");
        SearchForSigs(sig);
        Stage("");
        break;
    }
}

void SearchForSigs(const qstring& sig)
{
    show_wait_box("Please wait...");

    ea_t addr = find_binary(inf_get_min_ea(), inf_get_max_ea(), sig.c_str(), 16, SEARCH_DOWN);
    if (addr == BADADDR)
    {
        msg("Signature not found\n");
    }
    else
    {
        qstring name;
		do
		{
            get_func_name(&name, addr);
			msg("Found at: %X (%s)\n", addr, name.c_str());
			addr = find_binary(addr + 1, inf_get_max_ea(), sig.c_str(), 16, SEARCH_DOWN);
		} while (addr != BADADDR);
	}

    hide_wait_box();
}

UNIQUE_RESULT isUnique(const char* sig)
{
    ea_t addr = find_binary(inf_get_min_ea(), inf_get_max_ea(), sig, 16, SEARCH_DOWN);
    if (addr == BADADDR)
        return UNIQUE_ERROR;

    if (find_binary(addr + 1, inf_get_max_ea(), sig, 16, SEARCH_DOWN) != BADADDR)
        return UNIQUE_FALSE;

    return UNIQUE_TRUE;
}
