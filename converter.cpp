#include "converter.h"
#include "idaEx.h"
#include "misc.h"

// idasdk
#include <kernwin.hpp>

static int idaapi WindowConverterChangeCB(int field_id, form_actions_t& fa)
{
    if (field_id < 0)
        return 1;

    int mask = 0;
    fa.get_combobox_value(1, &mask);
    fa.enable_field(3, !mask);

    return 1;
}

void WindowConverter()
{
    qstring sig, mask;
    int action = 0;

    if (ask_form(
        "Converter\n"
        "%/"
        "<Signature :q::64:>\n"
        "<Mask      :q3::64:>\n"
        "<#Code to IDA:R0>\n"
        "<#IDA to Code:R1>>\n",
        WindowConverterChangeCB,
        &sig, &mask, &action) != 1)
        return;

    switch (action)
    {
    case 0:
        if (CodeToIDA(sig.c_str(), mask, sig))
        {
            Stage(" Convert code to IDA ");
            msg("Signature: %s\n", sig.c_str());
            Stage("");
        }
        else
        {
            msg("Empty signature or mask\n");
        }
        break;
    case 1:
        if (IDAToCode(sig, sig, mask))
        {
            Stage(" Convert IDA to code ");
            msg("Signature: %s\n"
                "Mask:      %s\n",
                sig.c_str(), mask.c_str());
            Stage("");
        }
        else
        {
            msg("Empty signature\n");
        }
        break;
    }
}

int CreateSignature(const char* ptr, qstring& outBytes, qstring* outMask = nullptr)
{
    outBytes.clear();
    if (outMask)
        outMask->clear();

    int count = 0;
    char* endptr = nullptr;
    while (*ptr != '\0')
    {
        if (*ptr == '?')
        {
            outBytes.append(Settings.wildcard);
            if (outMask)
                outMask->append('?');

            ptr++;
            count++;

            if (*ptr == '?')
                ptr++;
        }
        else if (qisxdigit(*ptr))
        {
            unsigned long val = strtoul(ptr, &endptr, 16);
            if (endptr == ptr)
                break;

            outBytes.append(static_cast<unsigned char>(val & 0xFF));
            if (outMask)
                outMask->append('x');

            ptr = endptr;
            count++;
        }
        else
        {
            ptr++;
        }
    }

    return count;
}

bool CodeToIDA(qstring code, const qstring& mask, qstring& outSig)
{
    idaEx::ltrim(code);
    code.rtrim();

    size_t len = mask.length();
    if (code.empty() || !len)
        return false;

    qstring sig;
    CreateSignature(code.c_str(), sig);
    outSig.clear();

    size_t i = -1;
    while (++i < len)
    {
        if (mask[i] == '?')
            outSig += "? ";
        else
            outSig.cat_sprnt("%02X ", static_cast<unsigned char>(sig[i]));
    }

    return true;
}

bool IDAToCode(qstring sig, qstring& outSig, qstring &outMask)
{
    idaEx::ltrim(sig);
    sig.rtrim();

    if (sig.empty())
        return false;

    qstring bytes;
    outMask.clear();
    int count = CreateSignature(sig.c_str(), bytes, &outMask);
    outSig.clear();

    int i = -1;
    while (++i < count)
        outSig.cat_sprnt("\\x%02X", static_cast<unsigned char>(bytes[i]));

    return true;
}
