package org.bouncycastle.crypto.general;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.internal.Xof;
import org.bouncycastle.crypto.internal.params.AsymmetricKeyParameter;
import org.bouncycastle.math.ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

final class Ed448PrivateKeyParameters
    extends AsymmetricKeyParameter
{
    public static final int KEY_SIZE = Ed448.SECRET_KEY_SIZE;
    public static final int SIGNATURE_SIZE = Ed448.SIGNATURE_SIZE;

    private final Ed448 ed448 = new Ed448()
    {
        @Override
        protected Xof createXof()
        {
            return (Xof)Register.createDigest(FipsSHS.Algorithm.SHAKE256);
        }
    };

    private final byte[] data = new byte[KEY_SIZE];

    public Ed448PrivateKeyParameters(SecureRandom random)
    {
        super(true);

        ed448.generatePrivateKey(random, data);
    }

    public Ed448PrivateKeyParameters(byte[] buf, int off)
    {
        super(true);

        System.arraycopy(buf, off, data, 0, KEY_SIZE);
    }

    public Ed448PrivateKeyParameters(InputStream input) throws IOException
    {
        super(true);

        if (KEY_SIZE != Streams.readFully(input, data))
        {
            throw new EOFException("EOF encountered in middle of Ed448 private key");
        }
    }

    public void encode(byte[] buf, int off)
    {
        System.arraycopy(data, 0, buf, off, KEY_SIZE);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(data);
    }

    public Ed448PublicKeyParameters generatePublicKey()
    {
        byte[] publicKey = new byte[Ed448.PUBLIC_KEY_SIZE];
        ed448.generatePublicKey(data, 0, publicKey, 0);
        return new Ed448PublicKeyParameters(publicKey, 0);
    }

    public void sign(int algorithm, Ed448PublicKeyParameters publicKey, byte[] ctx, byte[] msg, int msgOff, int msgLen, byte[] sig, int sigOff)
    {
        byte[] pk = new byte[Ed448.PUBLIC_KEY_SIZE];
        if (null == publicKey)
        {
            ed448.generatePublicKey(data, 0, pk, 0);
        }
        else
        {
            publicKey.encode(pk, 0);
        }

        switch (algorithm)
        {
        case Ed448.Algorithm.Ed448:
        {
            ed448.sign(data, 0, pk, 0, ctx, msg, msgOff, msgLen, sig, sigOff);
            break;
        }
        case Ed448.Algorithm.Ed448ph:
        {
            if (Ed448.PREHASH_SIZE != msgLen)
            {
                throw new IllegalArgumentException("msgLen");
            }

            ed448.signPrehash(data, 0, pk, 0, ctx, msg, msgOff, sig, sigOff);
            break;
        }
        default:
        {
            throw new IllegalArgumentException("algorithm");
        }
        }
    }
}
