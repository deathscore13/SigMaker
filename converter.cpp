// idasdk
#include <expr.hpp>

#include "converter.h"
#include "misc.h"

static int idaapi ShowSigConverter_chgcb(int field_id, form_actions_t& fa)
{
    if (field_id < 0)
        return 1;

    int mask = 0;
    fa.get_combobox_value(1, &mask);
    fa.enable_field(3, !mask);

    return 1;
}

void ShowSigConverter()
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
        ShowSigConverter_chgcb,
        &sig, &mask, &action) != 1)
        return;

    switch (action)
    {
    case 0:
        Stage(" Convert code to IDA ");
        CodeToIDA(sig.c_str(), sig, mask);
        msg("Signature: %s\n", sig.c_str());
        break;
    case 1:
        Stage(" Convert IDA to code ");
        IDAToCode(sig, sig, mask);
        msg("Signature: %s\n"
            "Mask:      %s\n",
            sig.c_str(), mask.c_str());
        break;
    }

    Stage("");
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

void IDAToCode(const qstring& sig, qstring& outSig, qstring &outMask)
{
    outMask.clear();
    qstring bytes;
    int count = CreateSignature(sig.c_str(), bytes, &outMask);
    outSig.clear();

    int i = -1;
    while (++i < count)
        outSig.cat_sprnt("\\x%02X", static_cast<unsigned char>(bytes[i]));
}

void CodeToIDA(const char* code, const qstring& mask, qstring& outSig)
{
    qstring sig;
    CreateSignature(code, sig);
    outSig.clear();

    size_t i = -1, len = mask.length();
    while (++i < len)
    {
        if (mask[i] == '?')
            outSig += "? ";
        else
            outSig.cat_sprnt("0x%02X ", static_cast<unsigned char>(sig[i]));
    }
}

void CodeToIDAC(const char* code, const qstring& mask, qstring& outSig)
{
    qstring sig;
    CreateSignature(code, sig);
    outSig.clear();

    size_t i = -1, len = mask.length();
    while (++i < len)
    {
        if (mask[i] == '?')
            outSig += "? ";
        else
            outSig.cat_sprnt("%02X ", static_cast<unsigned char>(sig[i]));
    }
}
