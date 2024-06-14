package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.internal.DataLengthException;
import org.bouncycastle.crypto.internal.DerivationFunction;
import org.bouncycastle.crypto.internal.DerivationParameters;
import org.bouncycastle.crypto.internal.Digest;
import org.bouncycastle.crypto.internal.params.KDFParameters;

/**
 * Generator for Concatenation Key Derivation Function defined in NIST SP 800-56A, Sect 5.8.1
 */
class ConcatenationKDFGenerator
    implements DerivationFunction
{
    private Digest  digest;
    private byte[]  shared;
    private byte[]  otherInfo;
    private int     hLen;

    /**
     * @param digest the digest to be used as the source of generated bytes
     */
    public ConcatenationKDFGenerator(
        Digest digest)
    {
        this.digest = digest;
        this.hLen = digest.getDigestSize();
    }

    public void init(
        DerivationParameters    param)
    {
        if (param instanceof KDFParameters)
        {
            KDFParameters p = (KDFParameters)param;

            shared = p.getSharedSecret();
            otherInfo = p.getIV();
        }
        else
        {
            throw new IllegalArgumentException("KDF parameters required for KDF generator");
        }
    }

    /**
     * return the underlying digest.
     */
    public Digest getDigest()
    {
        return digest;
    }

    /**
     * int to octet string.
     */
    private void ItoOSP(
        int     i,
        byte[]  sp)
    {
        sp[0] = (byte)(i >>> 24);
        sp[1] = (byte)(i >>> 16);
        sp[2] = (byte)(i >>> 8);
        sp[3] = (byte)(i >>> 0);
    }

    /**
     * fill len bytes of the output buffer with bytes generated from
     * the derivation function.
     *
     * @throws DataLengthException if the out buffer is too small.
     */
    public int generateBytes(
        byte[]  out,
        int     outOff,
        int     len)
        throws DataLengthException, IllegalArgumentException
    {
        if ((out.length - len) < outOff)
        {
            throw new DataLengthException("output buffer too small");
        }
        
        byte[]  hashBuf = new byte[hLen];
        byte[]  C = new byte[4];
        int     counter = 1;
        int     outputLen = 0;

        digest.reset();

        if (len > hLen)
        {
            do
            {
                ItoOSP(counter, C);

                digest.update(C, 0, C.length);
                digest.update(shared, 0, shared.length);
                if (otherInfo != null)
                {
                    digest.update(otherInfo, 0, otherInfo.length);
                }

                digest.doFinal(hashBuf, 0);
    
                System.arraycopy(hashBuf, 0, out, outOff + outputLen, hLen);
                outputLen += hLen;
            }
            while ((counter++) < (len / hLen));
        }

        if (outputLen < len)
        {
            ItoOSP(counter, C);

            digest.update(C, 0, C.length);
            digest.update(shared, 0, shared.length);

            if (otherInfo != null)
            {
                digest.update(otherInfo, 0, otherInfo.length);
            }

            digest.doFinal(hashBuf, 0);

            System.arraycopy(hashBuf, 0, out, outOff + outputLen, len - outputLen);
        }

        return len;
    }
}
