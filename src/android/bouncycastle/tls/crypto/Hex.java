package org.bouncycastle.tls.crypto;

import java.io.IOException;

class Hex
{
    protected final byte[] encodingTable =
    {
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
        (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f'
    };

    /*
     * set up the decoding table.
     */
    protected final byte[] decodingTable = new byte[128];

    protected Hex()
    {
        for (int i = 0; i < decodingTable.length; i++)
        {
            decodingTable[i] = (byte)0xff;
        }

        for (int i = 0; i < encodingTable.length; i++)
        {
            decodingTable[encodingTable[i]] = (byte)i;
        }

        decodingTable['A'] = decodingTable['a'];
        decodingTable['B'] = decodingTable['b'];
        decodingTable['C'] = decodingTable['c'];
        decodingTable['D'] = decodingTable['d'];
        decodingTable['E'] = decodingTable['e'];
        decodingTable['F'] = decodingTable['f'];
    }

    private static final Hex encoder = new Hex();

    public static byte[] decodeStrict(String data)
    {
        try
        {
            return encoder.decodeStrict(data, 0, data.length());
        }
        catch (Exception e)
        {
            throw new IllegalStateException("exception decoding Hex string: " + e.getMessage(), e);
        }
    }

    byte[] decodeStrict(String str, int off, int len) throws IOException
    {
        if (null == str)
        {
            throw new NullPointerException("'str' cannot be null");
        }
        if (off < 0 || len < 0 || off > (str.length() - len))
        {
            throw new IndexOutOfBoundsException("invalid offset and/or length specified");
        }
        if (0 != (len & 1))
        {
            throw new IOException("a hexadecimal encoding must have an even number of characters");
        }

        int resultLen = len >>> 1;
        byte[] result = new byte[resultLen];

        int strPos = off;
        for (int i = 0; i < resultLen; ++i)
        {
            byte b1 = decodingTable[str.charAt(strPos++)];
            byte b2 = decodingTable[str.charAt(strPos++)];

            int n = (b1 << 4) | b2;
            if (n < 0)
            {
                throw new IOException("invalid characters encountered in Hex string");
            }

            result[i] = (byte)n;
        }
        return result;
    }

}
