package org.bouncycastle.tls.crypto.impl;

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
}
