#include "converter.h"
#include "generator.h"
#include "search.h"

void AddBytesToSig(qstring& sig, ea_t addr, uint16 size)
{
    int i = -1;
    while (++i < size)
        sig.cat_sprnt("%02X ", get_byte(addr + i));
}

void AddWildcardsToSig(qstring& sig, uint16 size)
{
    int i = -1;
    while (++i < size)
        sig.cat_sprnt("? ");
}

bool isWildcard(insn_t* ins)
{
    switch (Settings.dataType)
    {
    case 0:
        // data & code (far) refs
        if (get_first_dref_from(ins->ea) != BADADDR &&
            get_first_cref_from(ins->ea) != BADADDR)
            return false;
    case 1:
        // data & code (near) refs
        if (get_first_dref_from(ins->ea) != BADADDR &&
            get_first_fcref_from(ins->ea) != BADADDR)
            return false;
    case 2:
        // https://github.com/alliedmodders/sourcemod/blob/1.10-dev/tools/ida_scripts/makesig.idc#L50
        if (ins->ops[0].type != o_near &&
            ins->ops[0].type != o_far)
            return false;
    }

    return true;
}

void AddInsToSig(insn_t *ins, qstring& sig)
{
    unsigned int size = 0;
    int i = -1;
    while (++i < UA_MAXOP)
    {
        if (ins->ops[i].type == o_void)
            break;

        if (ins->ops[i].offb != 0)
        {
            size = ins->ops[i].offb;
            break;
        }
    }

    if (size == 0)
    {
        AddBytesToSig(sig, ins->ea, ins->size);
        return;
    }

    AddBytesToSig(sig, ins->ea, size);

    if (isWildcard(ins))
        AddBytesToSig(sig, ins->ea + size, ins->size - size);
    else
        AddWildcardsToSig(sig, ins->size - size);
}

bool AddOneInsToSig(qstring& sig, ea_t& addr)
{
    insn_t ins;

    if (decode_insn(&ins, addr) == 0)
        return false;

    if (ins.size == 0)
        return false;

    if (ins.size < 5)
        AddBytesToSig(sig, addr, ins.size);
    else
        AddInsToSig(&ins, sig);

    addr += ins.size;
    return true;
}

bool AutoGenerate(ea_t addr, qstring& outSig, bool showError)
{
    if (addr == BADADDR)
    {
        if (showError)
            msg("You must select an address\n");

        return false;
    }

    func_t* func = get_func(addr);
    if (!func)
    {
        if (showError)
            msg("Function not found at address %X\n", addr);

        return false;
    }

    qstring buffer;
    if (get_func_name(&buffer, addr))
        buffer += " ";

    addr = func->start_ea;
    msg("Function %saddress: %X\n", buffer.c_str(), addr);

    show_wait_box("Please Wait...");

    outSig.clear();
    ea_t current = addr;
    do
    {
        if (!AddOneInsToSig(outSig, current))
        {
            if (showError)
                msg("Dropped a signature due to decompilation failure: %02X\n", current);

            hide_wait_box();
            return false;
        }
    } while (!isUnique(outSig));

    hide_wait_box();
    return true;
}


void CreateIDA()
{
    Stage(" Create IDA pattern ");

    qstring sig;
    if (!SigRange(sig, true))
        return;

    msg("Signature: %s\n", sig.c_str());
    Stage("");
}

void CreateCode()
{
    Stage(" Create code pattern ");

    qstring sig;
    if (!SigRange(sig, true))
        return;

    qstring buffer;
    IDAToCode(sig, sig, buffer);

    msg("Signature: %s\n"
        "Mask:      %s\n", sig.c_str(), buffer.c_str());
    Stage("");
}

void GenerateIDA()
{
    Stage(" Auto create IDA pattern ");

    qstring sig;
    if (AutoGenerate(get_screen_ea(), sig, true))
        msg("Signature: %s\n", sig.c_str());
    else
        msg("Failed to automatically generate signature\n");

    Stage("");
}

void GenerateCode()
{
    Stage(" Auto create code pattern ");

    qstring sig;
    if (AutoGenerate(get_screen_ea(), sig, true))
    {
        qstring mask;
        IDAToCode(sig, sig, mask);
        msg("Signature: %s\n"
            "Mask:      %s\n", sig.c_str(), mask.c_str());
    }
    else
    {
        msg("Failed to automatically generate signature\n");
    }

    Stage("");
}
