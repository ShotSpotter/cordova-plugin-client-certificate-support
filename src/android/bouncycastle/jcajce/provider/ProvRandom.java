package org.bouncycastle.jcajce.provider;


import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.EntropySource;
import org.bouncycastle.crypto.EntropySourceProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

class ProvRandom
    extends AsymmetricAlgorithmProvider
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider" + ".random.";

    public void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("SecureRandom.DEFAULT", PREFIX + "DefSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final SecureRandom random = provider.getDefaultSecureRandom();

                return new SecureRandomSpi()
                {
                    @Override
                    protected void engineSetSeed(byte[] bytes)
                    {
                        random.setSeed(bytes);
                    }

                    @Override
                    protected void engineNextBytes(byte[] bytes)
                    {
                        random.nextBytes(bytes);
                    }

                    @Override
                    protected byte[] engineGenerateSeed(int numBytes)
                    {
                        return random.generateSeed(numBytes);
                    }
                };
            }
        });

        provider.addAlgorithmImplementation("SecureRandom.NONCEANDIV", PREFIX + "NonceAndIVSecureRandom", new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                final EntropySourceProvider entropySourceProvider = provider.getEntropySourceProvider();
                final EntropySource seedSource = entropySourceProvider.get((provider.getProviderDefaultSecurityStrength() / 2) + 1);

                final SecureRandom random = provider.getProviderDefaultRandomBuilder()
                    .fromEntropySource(entropySourceProvider)
                    .setPersonalizationString(generatePersonalizationString())
                    .build(seedSource.getEntropy(), false, Strings.toByteArray("Bouncy Castle FIPS Provider Nonce/IV"));

                return new SecureRandomSpi()
                {
                    @Override
                    protected void engineSetSeed(byte[] bytes)
                    {
                        random.setSeed(bytes);
                    }

                    @Override
                    protected void engineNextBytes(byte[] bytes)
                    {
                        random.nextBytes(bytes);
                    }

                    @Override
                    protected byte[] engineGenerateSeed(int numBytes)
                    {
                        return random.generateSeed(numBytes);
                    }
                };
            }
        });
    }

    private byte[] generatePersonalizationString()
    {
        return Arrays.concatenate(Strings.toByteArray("NonceAndIV"),
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
}
