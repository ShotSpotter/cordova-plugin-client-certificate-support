package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * An ASN.1 class that encodes to nothing, used in the OER library to deal with the Optional type.
 */
public class ASN1Absent
    extends ASN1Primitive
{

    public static final ASN1Absent INSTANCE = new ASN1Absent();

    private ASN1Absent()
    {

    }

    public int hashCode()
    {
        return 0;
    }

    @Override
    boolean isConstructed()
    {
        return false;
    }

    @Override
    int encodedLength()
        throws IOException
    {
        return 0;
    }

    @Override
    void encode(ASN1OutputStream out)
        throws IOException
    {

    }

    boolean encodeConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
        throws IOException
    {
        return 0;
    }

    void encode(ASN1OutputStream out, boolean withTag)
        throws IOException
    {

    }

    boolean asn1Equals(ASN1Primitive o)
    {
        return o == this;
    }
}
