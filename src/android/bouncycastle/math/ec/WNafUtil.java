/***************************************************************/
/******    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ******/
/***************************************************************/
package org.bouncycastle.math.ec;

import java.math.BigInteger;

public abstract class WNafUtil
{
    public static final String PRECOMP_NAME = "bc_wnaf";

    private static final int[] DEFAULT_WINDOW_SIZE_CUTOFFS = new int[]{ 13, 41, 121, 337, 897, 2305 };

    private static final byte[] EMPTY_BYTES = new byte[0];
    private static final int[] EMPTY_INTS = new int[0];
    private static final ECPoint[] EMPTY_POINTS = new ECPoint[0];

    public static int[] generateCompactNaf(BigInteger k)
    {
        if ((k.bitLength() >>> 16) != 0)
        {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (k.signum() == 0)
        {
            return EMPTY_INTS;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);

        int bits = _3k.bitLength();
        int[] naf = new int[bits >> 1];

        BigInteger diff = _3k.xor(k);

        int highBit = bits - 1, length = 0, zeroes = 0;
        for (int i = 1; i < highBit; ++i)
        {
            if (!diff.testBit(i))
            {
                ++zeroes;
                continue;
            }

            int digit  = k.testBit(i) ? -1 : 1;
            naf[length++] = (digit << 16) | zeroes;
            zeroes = 1;
            ++i;
        }

        naf[length++] = (1 << 16) | zeroes;

        if (naf.length > length)
        {
            naf = trim(naf, length);
        }

        return naf;
    }

    public static int[] generateCompactWindowNaf(int width, BigInteger k)
    {
        if (width == 2)
        {
            return generateCompactNaf(k);
        }

        if (width < 2 || width > 16)
        {
            throw new IllegalArgumentException("'width' must be in the range [2, 16]");
        }
        if ((k.bitLength() >>> 16) != 0)
        {
            throw new IllegalArgumentException("'k' must have bitlength < 2^16");
        }
        if (k.signum() == 0)
        {
            return EMPTY_INTS;
        }

        int[] wnaf = new int[k.bitLength() / width + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

        boolean carry = false;
        int length = 0, pos = 0;

        while (pos <= k.bitLength())
        {
            if (k.testBit(pos) == carry)
            {
                ++pos;
                continue;
            }

            k = k.shiftRight(pos);

            int digit = k.intValue() & mask;
            if (carry)
            {
                ++digit;
            }

            carry = (digit & sign) != 0;
            if (carry)
            {
                digit -= pow2;
            }

            int zeroes = length > 0 ? pos - 1 : pos;
            wnaf[length++] = (digit << 16) | zeroes;
            pos = width;
        }

        // Reduce the WNAF array to its actual length
        if (wnaf.length > length)
        {
            wnaf = trim(wnaf, length);
        }

        return wnaf;
    }

    public static byte[] generateJSF(BigInteger g, BigInteger h)
    {
        int digits = Math.max(g.bitLength(), h.bitLength()) + 1;
        byte[] jsf = new byte[digits];

        BigInteger k0 = g, k1 = h;
        int j = 0, d0 = 0, d1 = 0;

        int offset = 0;
        while ((d0 | d1) != 0 || k0.bitLength() > offset || k1.bitLength() > offset)
        {
            int n0 = ((k0.intValue() >>> offset) + d0) & 7, n1 = ((k1.intValue() >>> offset) + d1) & 7;

            int u0 = n0 & 1;
            if (u0 != 0)
            {
                u0 -= (n0 & 2);
                if ((n0 + u0) == 4 && (n1 & 3) == 2)
                {
                    u0 = -u0;
                }
            }

            int u1 = n1 & 1;
            if (u1 != 0)
            {
                u1 -= (n1 & 2);
                if ((n1 + u1) == 4 && (n0 & 3) == 2)
                {
                    u1 = -u1;
                }
            }

            if ((d0 << 1) == 1 + u0)
            {
                d0 ^= 1;
            }
            if ((d1 << 1) == 1 + u1)
            {
                d1 ^= 1;
            }

            if (++offset == 30)
            {
                offset = 0;
                k0 = k0.shiftRight(30);
                k1 = k1.shiftRight(30);
            }

            jsf[j++] = (byte)((u0 << 4) | (u1 & 0xF));
        }

        // Reduce the JSF array to its actual length
        if (jsf.length > j)
        {
            jsf = trim(jsf, j);
        }

        return jsf;
    }

    public static byte[] generateNaf(BigInteger k)
    {
        if (k.signum() == 0)
        {
            return EMPTY_BYTES;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);

        int digits = _3k.bitLength() - 1;
        byte[] naf = new byte[digits];

        BigInteger diff = _3k.xor(k);

        for (int i = 1; i < digits; ++i)
        {
            if (diff.testBit(i))
            {
                naf[i - 1] = (byte)(k.testBit(i) ? -1 : 1);
                ++i;
            }
        }

        naf[digits - 1] = 1;

        return naf;
    }

    /**
     * Computes the Window NAF (non-adjacent Form) of an integer.
     * @param width The width <code>w</code> of the Window NAF. The width is
     * defined as the minimal number <code>w</code>, such that for any
     * <code>w</code> consecutive digits in the resulting representation, at
     * most one is non-zero.
     * @param k The integer of which the Window NAF is computed.
     * @return The Window NAF of the given width, such that the following holds:
     * <code>k = &sum;<sub>i=0</sub><sup>l-1</sup> k<sub>i</sub>2<sup>i</sup>
     * </code>, where the <code>k<sub>i</sub></code> denote the elements of the
     * returned <code>byte[]</code>.
     */
    public static byte[] generateWindowNaf(int width, BigInteger k)
    {
        if (width == 2)
        {
            return generateNaf(k);
        }

        if (width < 2 || width > 8)
        {
            throw new IllegalArgumentException("'width' must be in the range [2, 8]");
        }
        if (k.signum() == 0)
        {
            return EMPTY_BYTES;
        }

        byte[] wnaf = new byte[k.bitLength() + 1];

        // 2^width and a mask and sign bit set accordingly
        int pow2 = 1 << width;
        int mask = pow2 - 1;
        int sign = pow2 >>> 1;

        boolean carry = false;
        int length = 0, pos = 0;

        while (pos <= k.bitLength())
        {
            if (k.testBit(pos) == carry)
            {
                ++pos;
                continue;
            }

            k = k.shiftRight(pos);

            int digit = k.intValue() & mask;
            if (carry)
            {
                ++digit;
            }

            carry = (digit & sign) != 0;
            if (carry)
            {
                digit -= pow2;
            }

            length += (length > 0) ? pos - 1 : pos;
            wnaf[length++] = (byte)digit;
            pos = width;
        }

        // Reduce the WNAF array to its actual length
        if (wnaf.length > length)
        {
            wnaf = trim(wnaf, length);
        }
        
        return wnaf;
    }

    public static int getNafWeight(BigInteger k)
    {
        if (k.signum() == 0)
        {
            return 0;
        }

        BigInteger _3k = k.shiftLeft(1).add(k);
        BigInteger diff = _3k.xor(k);

        return diff.bitCount();
    }

    public static WNafPreCompInfo getWNafPreCompInfo(ECPoint p)
    {
        return getWNafPreCompInfo(p.getCurve().getPreCompInfo(p, PRECOMP_NAME));
    }

    public static WNafPreCompInfo getWNafPreCompInfo(PreCompInfo preCompInfo)
    {
        return (preCompInfo instanceof WNafPreCompInfo) ? (WNafPreCompInfo)preCompInfo : null;
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @return the window size to use
     */
    public static int getWindowSize(int bits)
    {
        return getWindowSize(bits, DEFAULT_WINDOW_SIZE_CUTOFFS);
    }

    /**
     * Determine window width to use for a scalar multiplication of the given size.
     * 
     * @param bits the bit-length of the scalar to multiply by
     * @param windowSizeCutoffs a monotonically increasing list of bit sizes at which to increment the window width
     * @return the window size to use
     */
    public static int getWindowSize(int bits, int[] windowSizeCutoffs)
    {
        int w = 0;
        for (; w < windowSizeCutoffs.length; ++w)
        {
            if (bits < windowSizeCutoffs[w])
            {
                break;
            }
        }
        return w + 2;
    }

    public static ECPoint mapPointWithPrecomp(ECPoint p, final int width, final boolean includeNegated,
        final ECPointMap pointMap)
    {
        final ECCurve c = p.getCurve();
        final WNafPreCompInfo wnafPreCompP = precompute(p, width, includeNegated);

        ECPoint q = pointMap.map(p);
        c.precompute(q, PRECOMP_NAME, new PreCompCallback()
        {
            public PreCompInfo precompute(PreCompInfo existing)
            {
                WNafPreCompInfo result = new WNafPreCompInfo();

                ECPoint twiceP = wnafPreCompP.getTwice();
                if (twiceP != null)
                {
                    ECPoint twiceQ = pointMap.map(twiceP);
                    result.setTwice(twiceQ);
                }

                ECPoint[] preCompP = wnafPreCompP.getPreComp();
                ECPoint[] preCompQ = new ECPoint[preCompP.length];
                for (int i = 0; i < preCompP.length; ++i)
                {
                    preCompQ[i] = pointMap.map(preCompP[i]);
                }
                result.setPreComp(preCompQ);

                if (includeNegated)
                {
                    ECPoint[] preCompNegQ = new ECPoint[preCompQ.length];
                    for (int i = 0; i < preCompNegQ.length; ++i)
                    {
                        preCompNegQ[i] = preCompQ[i].negate();
                    }
                    result.setPreCompNeg(preCompNegQ);
                }

                return result;
            }
        });

        return q;
    }

    public static WNafPreCompInfo precompute(final ECPoint p, final int width, final boolean includeNegated)
    {
        final ECCurve c = p.getCurve();

        return (WNafPreCompInfo)c.precompute(p, PRECOMP_NAME, new PreCompCallback()
        {
            public PreCompInfo precompute(PreCompInfo existing)
            {
                WNafPreCompInfo existingWNaf = (existing instanceof WNafPreCompInfo) ? (WNafPreCompInfo)existing : null;

                int reqPreCompLen = 1 << Math.max(0, width - 2);

                if (checkExisting(existingWNaf, reqPreCompLen, includeNegated))
                {
                    return existingWNaf;
                }

                ECPoint[] preComp = null, preCompNeg = null;
                ECPoint twiceP = null;

                if (existingWNaf != null)
                {
                    preComp = existingWNaf.getPreComp();
                    preCompNeg = existingWNaf.getPreCompNeg();
                    twiceP = existingWNaf.getTwice();
                }

                int iniPreCompLen = 0;
                if (preComp == null)
                {
                    preComp = EMPTY_POINTS;
                }
                else
                {
                    iniPreCompLen = preComp.length;
                }

                if (iniPreCompLen < reqPreCompLen)
                {
                    preComp = resizeTable(preComp, reqPreCompLen);

                    if (reqPreCompLen == 1)
                    {
                        preComp[0] = p.normalize();
                    }
                    else
                    {
                        int curPreCompLen = iniPreCompLen;
                        if (curPreCompLen == 0)
                        {
                            preComp[0] = p;
                            curPreCompLen = 1;
                        }

                        ECFieldElement iso = null;

                        if (reqPreCompLen == 2)
                        {
                            preComp[1] = p.threeTimes();
                        }
                        else
                        {
                            ECPoint isoTwiceP = twiceP, last = preComp[curPreCompLen - 1];
                            if (isoTwiceP == null)
                            {
                                isoTwiceP = preComp[0].twice();
                                twiceP = isoTwiceP;

                                /*
                                 * For Fp curves with Jacobian projective coordinates, use a (quasi-)isomorphism
                                 * where 'twiceP' is "affine", so that the subsequent additions are cheaper. This
                                 * also requires scaling the initial point's X, Y coordinates, and reversing the
                                 * isomorphism as part of the subsequent normalization.
                                 * 
                                 *  NOTE: The correctness of this optimization depends on:
                                 *      1) additions do not use the curve's A, B coefficients.
                                 *      2) no special cases (i.e. Q +/- Q) when calculating 1P, 3P, 5P, ...
                                 */
                                if (!twiceP.isInfinity() && ECAlgorithms.isFpCurve(c) && c.getFieldSize() >= 64)
                                {
                                    switch (c.getCoordinateSystem())
                                    {
                                    case ECCurve.COORD_JACOBIAN:
                                    case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
                                    case ECCurve.COORD_JACOBIAN_MODIFIED:
                                    {
                                        iso = twiceP.getZCoord(0);
                                        isoTwiceP = c.createPoint(twiceP.getXCoord().toBigInteger(), twiceP.getYCoord()
                                            .toBigInteger());

                                        ECFieldElement iso2 = iso.square(), iso3 = iso2.multiply(iso);
                                        last = last.scaleX(iso2).scaleY(iso3);

                                        if (iniPreCompLen == 0)
                                        {
                                            preComp[0] = last;
                                        }
                                        break;
                                    }
                                    }
                                }
                            }

                            while (curPreCompLen < reqPreCompLen)
                            {
                                /*
                                 * Compute the new ECPoints for the precomputation array. The values 1, 3,
                                 * 5, ..., 2^(width-1)-1 times p are computed
                                 */
                                preComp[curPreCompLen++] = last = last.add(isoTwiceP);
                            }
                        }

                        /*
                         * Having oft-used operands in affine form makes operations faster.
                         */
                        c.normalizeAll(preComp, iniPreCompLen, reqPreCompLen - iniPreCompLen, iso);
                    }
                }

                if (includeNegated)
                {
                    int pos;
                    if (preCompNeg == null)
                    {
                        pos = 0;
                        preCompNeg = new ECPoint[reqPreCompLen]; 
                    }
                    else
                    {
                        pos = preCompNeg.length;
                        if (pos < reqPreCompLen)
                        {
                            preCompNeg = resizeTable(preCompNeg, reqPreCompLen);
                        }
                    }

                    while (pos < reqPreCompLen)
                    {
                        preCompNeg[pos] = preComp[pos].negate();
                        ++pos;
                    }
                }

                WNafPreCompInfo result = new WNafPreCompInfo();
                result.setPreComp(preComp);
                result.setPreCompNeg(preCompNeg);
                result.setTwice(twiceP);
                return result;
            }

            private boolean checkExisting(WNafPreCompInfo existingWNaf, int reqPreCompLen, boolean includeNegated)
            {
                return existingWNaf != null
                    && checkTable(existingWNaf.getPreComp(), reqPreCompLen)
                    && (!includeNegated || checkTable(existingWNaf.getPreCompNeg(), reqPreCompLen));
            }

            private boolean checkTable(ECPoint[] table, int reqLen)
            {
                return table != null && table.length >= reqLen;
            }
        });
    }

    private static byte[] trim(byte[] a, int length)
    {
        byte[] result = new byte[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static int[] trim(int[] a, int length)
    {
        int[] result = new int[length];
        System.arraycopy(a, 0, result, 0, result.length);
        return result;
    }

    private static ECPoint[] resizeTable(ECPoint[] a, int length)
    {
        ECPoint[] result = new ECPoint[length];
        System.arraycopy(a, 0, result, 0, a.length);
        return result;
    }
}
