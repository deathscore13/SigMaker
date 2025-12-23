#include "idaEx.h"

namespace idaEx
{

qstring& ltrim(qstring& qstr)
{
    if (!qstr.empty())
    {
        char* start = qstr.begin();
        char* end = qstr.end();
        while (start < end && qisspace(*start))
            ++start;

        if (start > qstr.begin())
        {
            size_t size = end - start;
            if (size > 0)
            {
                qstring temp = start;
                qstr = temp;
            }
            else
            {
                qstr.clear();
            }
        }
    }
    return qstr;
}

}
