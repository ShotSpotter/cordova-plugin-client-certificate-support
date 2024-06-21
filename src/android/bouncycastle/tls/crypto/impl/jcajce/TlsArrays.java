package org.bouncycastle.tls.crypto.impl.jcajce;

class TlsArrays
{
    private TlsArrays()
    {
        // static class, hide constructor
    }

    public static boolean areAllZeroes(byte[] buf, int off, int len)
    {
        int bits = 0;
        for (int i = 0; i < len; ++i)
        {
            bits |= buf[off + i];
        }
        return bits == 0;
    }
}
