/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * BigInteger utilities.
 */
public final class BigIntegers
{
    public static final BigInteger ZERO = BigInteger.valueOf(0);
    public static final BigInteger ONE = BigInteger.valueOf(1);

    private static final int MAX_ITERATIONS = 1000;

    /**
     * Return the passed in value as an unsigned byte array.
     * 
     * @param value value to be converted.
     * @return a byte array without a leading zero byte if present in the signed encoding.
     */
    public static byte[] asUnsignedByteArray(
        BigInteger value)
    {
        byte[] bytes = value.toByteArray();
        
        if (bytes[0] == 0)
        {
            byte[] tmp = new byte[bytes.length - 1];
            
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            
            return tmp;
        }
        
        return bytes;
    }

    /**
     * Return the passed in value as an unsigned byte array.
     *
     * @param value value to be converted.
     * @return a byte array without a leading zero byte if present in the signed encoding.
     */
    public static byte[] asUnsignedByteArray(int length, BigInteger value)
    {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length)
        {
            return bytes;
        }

        int start = bytes[0] == 0 ? 1 : 0;
        int count = bytes.length - start;

        if (count > length)
        {
            throw new IllegalArgumentException("standard length exceeded for value");
        }

        byte[] tmp = new byte[length];
        System.arraycopy(bytes, start, tmp, tmp.length - count, count);
        return tmp;
    }

    /**
     * Return a random BigInteger not less than 'min' and not greater than 'max'
     * 
     * @param min the least value that may be generated
     * @param max the greatest value that may be generated
     * @param random the source of randomness
     * @return a random BigInteger value in the range [min,max]
     */
    public static BigInteger createRandomInRange(
        BigInteger      min,
        BigInteger      max,
        SecureRandom    random)
    {
        int cmp = min.compareTo(max);
        if (cmp >= 0)
        {
            if (cmp > 0)
            {
                throw new IllegalArgumentException("'min' may not be greater than 'max'");
            }

            return min;
        }

        if (min.bitLength() > max.bitLength() / 2)
        {
            return createRandomInRange(ZERO, max.subtract(min), random).add(min);
        }

        for (int i = 0; i < MAX_ITERATIONS; ++i)
        {
            BigInteger x = new BigInteger(max.bitLength(), random);
            if (x.compareTo(min) >= 0 && x.compareTo(max) <= 0)
            {
                return x;
            }
        }

        // fall back to a faster (restricted) method
        return new BigInteger(max.subtract(min).bitLength() - 1, random).add(min);
    }

    public static BigInteger fromUnsignedByteArray(byte[] buf)
    {
        return new BigInteger(1, buf);
    }

    public static BigInteger fromUnsignedByteArray(byte[] buf, int off, int length)
    {
        byte[] mag = buf;
        if (off != 0 || length != buf.length)
        {
            mag = new byte[length];
            System.arraycopy(buf, off, mag, 0, length);
        }
        return new BigInteger(1, mag);
    }

    /**
     * Return a positive BigInteger in the range of 0 to 2**bitLength - 1.
     *
     * @param bitLength maximum bit length for the generated BigInteger.
     * @param random a source of randomness.
     * @return a positive BigInteger
     */
    public static BigInteger createRandomBigInteger(int bitLength, SecureRandom random)
    {
        return new BigInteger(1, createRandom(bitLength, random));
    }

    private static byte[] createRandom(int bitLength, SecureRandom random)
        throws IllegalArgumentException
    {
        if (bitLength < 1)
        {
            throw new IllegalArgumentException("bitLength must be at least 1");
        }

        int nBytes = (bitLength + 7) / 8;

        byte[] rv = new byte[nBytes];

        random.nextBytes(rv);

        // strip off any excess bits in the MSB
        int xBits = 8 * nBytes - bitLength;
        rv[0] &= (byte)(255 >>> xBits);

        return rv;
    }
}
