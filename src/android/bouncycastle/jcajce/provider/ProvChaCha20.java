package org.bouncycastle.jcajce.provider;

import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.crypto.Parameters;
import org.bouncycastle.crypto.ParametersWithIV;
import org.bouncycastle.crypto.SymmetricKeyGenerator;
import org.bouncycastle.crypto.general.ChaCha20;

final class ProvChaCha20
    extends AlgorithmProvider
{
    private static final String PREFIX = ProvChaCha20.class.getName();

    private ParametersCreatorProvider<Parameters> generalParametersCreatorProvider = new ParametersCreatorProvider<Parameters>()
    {
        public ParametersCreator get(final Parameters parameters)
        {
            return new IvParametersCreator((ParametersWithIV)parameters);
        }
    };

    @Override
    void configure(final BouncyCastleFipsProvider provider)
    {
        provider.addAlgorithmImplementation("KeyGenerator.CHACHA20", PREFIX + "$KeyGenerator", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseKeyGenerator(provider, "ChaCha20", 256, true, new KeyGeneratorCreator()
                {
                    public SymmetricKeyGenerator createInstance(int keySize, SecureRandom random)
                    {
                        // keySize ignored
                        return new ChaCha20.KeyGenerator(random);
                    }
                });
            }
        }));
        provider.addAlias("KeyGenerator", "CHACHA20", "CHACHA7539");

        provider.addAlgorithmImplementation("AlgorithmParameters.CHACHA20", PREFIX + "$AlgParams", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new ASN1AlgorithmParameters("ChaCha20");
            }
        }));
        provider.addAlias("AlgorithmParameters", "CHACHA20", "CHACHA7539");

        provider.addAlgorithmImplementation("AlgorithmParameterGenerator.CHACHA20",PREFIX + "$AlgParamGen", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new IVAlgorithmParameterGenerator(provider, "ChaCha20", 12);
            }
        }));
        provider.addAlias("AlgorithmParameterGenerator", "CHACHA20", "CHACHA7539");

        final Class[] ivOnlySpec = new Class[]{IvParameterSpec.class};

        provider.addAlgorithmImplementation("Cipher.CHACHA20", PREFIX + "$Base", new GuardedEngineCreator(new EngineCreator()
        {
            public Object createInstance(Object constructorParameter)
            {
                return new BaseCipher.Builder(provider, 96, ChaCha20.STREAM)
                    .withParameters(ivOnlySpec)
                    .withGeneralOperators(generalParametersCreatorProvider, new ChaCha20.OperatorFactory(), null).build();
            }
        }));
        provider.addAlias("Cipher", "CHACHA20", "CHACHA7539");
    }
}
