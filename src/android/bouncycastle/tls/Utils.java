package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

class Utils
{
    static void writeBufTo(ByteArrayOutputStream buf, OutputStream output)
        throws IOException
    {
        buf.writeTo(output);
    }

    static int compareUnsigned(byte[] a, byte[] b)
    {
        if (a == b)
        {
            return 0;
        }
        if (a == null)
        {
            return -1;
        }
        if (b == null)
        {
            return 1;
        }
        int minLen = Math.min(a.length, b.length);
        for (int i = 0; i < minLen; ++i)
        {
            int aVal = a[i] & 0xFF, bVal = b[i] & 0xFF;
            if (aVal < bVal)
            {
                return -1;
            }
            if (aVal > bVal)
            {
                return 1;
            }
        }
        if (a.length < b.length)
        {
            return -1;
        }
        if (a.length > b.length)
        {
            return 1;
        }
        return 0;
    }
}
