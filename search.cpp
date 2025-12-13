#include "converter.h"
#include "misc.h"
#include "search.h"

// idasdk
#include <expr.hpp>
#include <search.hpp>

bool isUnique(const qstring& sig)
{
    ea_t addr = find_binary(inf_get_min_ea(), inf_get_max_ea(), sig.c_str(), 16, SEARCH_DOWN);
    if (addr == BADADDR)
        return true;

    if (find_binary(addr + 1, inf_get_max_ea(), sig.c_str(), 16, SEARCH_DOWN) != BADADDR)
		return false;

    return true;
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

void ShowIDAWindow(const qstring* sigIDA)
{
    qstring sig;
    if (sigIDA)
        sig = *sigIDA;

    if (sig.empty())
        SigRange(sig);

    if (ask_form(
        "Test IDA pattern\n"
        "<Signature :q::64:>\n"
        , &sig) != 1)
        return;

    Stage(" Test IDA pattern ");

    if (sig.empty())
        msg("Empty field\n");
    else
        SearchForSigs(sig);
    
    Stage("");
}

void ShowCodeWindow(const qstring* sigIDA)
{
    qstring sig, mask;
    if (sigIDA)
        sig = *sigIDA;

    if (sig.empty() && SigRange(sig))
        IDAToCode(sig, sig, mask);;

    if (ask_form(
        "Test code pattern\n"
        "<Signature :q::64:>\n"
        "<Mask      :q::64:>\n"
        , &sig, &mask) != 1)
        return;

    Stage(" Test code pattern ");

    if (sig.empty())
    {
        msg("Empty field\n");
    }
    else
    {
        CodeToIDAC(sig.c_str(), mask, sig);
        SearchForSigs(sig);
    }

    Stage("");
}
