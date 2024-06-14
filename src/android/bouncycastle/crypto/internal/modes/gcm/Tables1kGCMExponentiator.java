/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.crypto.internal.modes.gcm;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.util.Arrays;

public class Tables1kGCMExponentiator implements GCMExponentiator
{
    // A lookup table of the power-of-two powers of 'x'
    // - lookupPowX2[i] = x^(2^i)
    private List lookupPowX2;

    public void init(byte[] x)
    {
        int[] y = GCMUtil.asInts(x);
        if (lookupPowX2 != null && Arrays.areEqual(y, (int[])lookupPowX2.get(0)))
        {
            return;
        }

        lookupPowX2 = new ArrayList(8);
        lookupPowX2.add(y);
    }

    public void exponentiateX(long pow, byte[] output)
    {
        int[] y = GCMUtil.oneAsInts();
        int bit = 0;
        while (pow > 0)
        {
            if ((pow & 1L) != 0)
            {
                GCMUtil.multiply(y, getMultiplier(bit));
            }
            ++bit;
            pow >>>= 1;
        }

        GCMUtil.asBytes(y, output);
    }

    private int[] getMultiplier(int bit)
    {
        ensureAvailable(bit);

        return (int[])lookupPowX2.get(bit);
    }

    private void ensureAvailable(int bit)
    {
        int count = lookupPowX2.size();
        if (count <= bit)
        {
            int[] tmp = (int[])lookupPowX2.get(count - 1);
            do
            {
                tmp = Arrays.clone(tmp);
                GCMUtil.multiply(tmp, tmp);
                lookupPowX2.add(tmp);
            }
            while (++count <= bit);
        }
    }
}
