package org.bouncycastle.jcajce.provider;

import java.io.ByteArrayOutputStream;

import org.bouncycastle.util.Arrays;

class DataArrayOutputStream
    extends ByteArrayOutputStream
{
    synchronized void clearAndReset()
    {
        Arrays.fill(buf, 0, count, (byte)0);
        count = 0;
    }

    byte[] getBuffer()
    {
        return buf;
    }
}
