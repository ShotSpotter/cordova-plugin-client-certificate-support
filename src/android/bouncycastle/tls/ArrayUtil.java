package org.bouncycastle.tls;

class ArrayUtil
{
    public static boolean isNullOrEmpty(byte[] array)
    {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(int[] array)
    {
        return null == array || array.length < 1;
    }

    public static boolean isNullOrEmpty(Object[] array)
    {
        return null == array || array.length < 1;
    }

    public static boolean constantTimeAreEqual(int len, byte[] a, int aOff, byte[] b, int bOff)
    {
        if (null == a)
        {
            throw new NullPointerException("'a' cannot be null");
        }
        if (null == b)
        {
            throw new NullPointerException("'b' cannot be null");
        }
        if (len < 0)
        {
            throw new IllegalArgumentException("'len' cannot be negative");
        }
        if (aOff > (a.length - len))
        {
            throw new IndexOutOfBoundsException("'aOff' value invalid for specified length");
        }
        if (bOff > (b.length - len))
        {
            throw new IndexOutOfBoundsException("'bOff' value invalid for specified length");
        }

        int d = 0;
        for (int i = 0; i < len; ++i)
        {
            d |= (a[aOff + i] ^ b[bOff + i]);
        }
        return 0 == d;
    }
}
