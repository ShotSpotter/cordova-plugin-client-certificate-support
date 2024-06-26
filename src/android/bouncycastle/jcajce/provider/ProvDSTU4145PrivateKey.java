package org.bouncycastle.jcajce.provider;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import javax.security.auth.Destroyable;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricDSTU4145PrivateKey;
import org.bouncycastle.jcajce.interfaces.DSTU4145PrivateKey;
import org.bouncycastle.jcajce.spec.DSTU4145ParameterSpec;
import org.bouncycastle.jcajce.spec.DSTU4145PrivateKeySpec;

class ProvDSTU4145PrivateKey
    implements Destroyable, DSTU4145PrivateKey, ProvKey<AsymmetricDSTU4145PrivateKey>
{
    private static final long serialVersionUID = 7245981689601667138L;

    private transient AsymmetricDSTU4145PrivateKey baseKey;

    ProvDSTU4145PrivateKey(
        Algorithm algorithm,
        DSTU4145PrivateKey key)
    {
        DSTU4145ParameterSpec params = key.getParams();

        this.baseKey = new AsymmetricDSTU4145PrivateKey(algorithm, DSTU4145Util.convertToECParams(params), key.getS());
    }

    ProvDSTU4145PrivateKey(
        Algorithm algorithm,
        DSTU4145PrivateKeySpec keySpec)
    {
        this.baseKey = new AsymmetricDSTU4145PrivateKey(algorithm, DSTU4145Util.convertToECParams(keySpec.getParams()), keySpec.getS());
    }

    ProvDSTU4145PrivateKey(
        AsymmetricDSTU4145PrivateKey key)
    {
        this.baseKey = key;
    }

    public AsymmetricDSTU4145PrivateKey getBaseKey()
    {
        KeyUtil.checkDestroyed(this);
        
        return baseKey;
    }

    public String getAlgorithm()
    {
        return baseKey.getAlgorithm().getName();
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        KeyUtil.checkDestroyed(this);

        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        return baseKey.getEncoded();
    }

    public DSTU4145ParameterSpec getParams()
    {
        return DSTU4145Util.convertToECSpec(baseKey.getParameters());
    }

    public BigInteger getS()
    {
        return baseKey.getS();
    }

    public boolean equals(Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof ProvDSTU4145PrivateKey))
        {
            return false;
        }

        ProvDSTU4145PrivateKey other = (ProvDSTU4145PrivateKey)o;

        return this.baseKey.equals(other.baseKey);
    }

    public int hashCode()
    {
        return baseKey.hashCode();
    }

    public void destroy()
    {
        baseKey.destroy();
    }

    public boolean isDestroyed()
    {
        return baseKey.isDestroyed();
    }

    public String toString()
    {
        if (isDestroyed())
        {
            return KeyUtil.destroyedPrivateKeyToString("DSTU4145");
        }

        try
        {
            return KeyUtil.privateKeyToString("DSTU4145", baseKey.getS(), baseKey.getParameters().getDomainParameters());
        }
        catch (Exception e)
        {
            return KeyUtil.restrictedToString("DSTU4145");
        }
    }

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        Algorithm alg = (Algorithm)in.readObject();

        byte[] enc = (byte[])in.readObject();

        baseKey = new AsymmetricDSTU4145PrivateKey(alg, enc);
    }

    private void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        if (isDestroyed())
        {
            throw new IOException("key has been destroyed");
        }

        out.defaultWriteObject();

        out.writeObject(baseKey.getAlgorithm());
        out.writeObject(this.getEncoded());
    }
}
