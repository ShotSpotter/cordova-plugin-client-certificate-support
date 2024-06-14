package org.bouncycastle.crypto.general;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.IllegalKeyException;
import org.bouncycastle.crypto.SymmetricKey;
import org.bouncycastle.crypto.SymmetricSecretKey;
import org.bouncycastle.crypto.internal.CipherParameters;
import org.bouncycastle.crypto.internal.KeyGenerationParameters;
import org.bouncycastle.crypto.internal.StreamCipher;
import org.bouncycastle.crypto.internal.ValidatedSymmetricKey;
import org.bouncycastle.crypto.internal.params.KeyParameterImpl;
import org.bouncycastle.crypto.internal.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * Source class for implementations of ChaCha20 based algorithms.
 */
public final class ChaCha20
{
    private ChaCha20()
    {
    }

    /**
     * Raw ChaCha20 algorithm, can be used for creating general purpose ChaCha20 keys.
     */
    public static final GeneralAlgorithm ALGORITHM = new GeneralAlgorithm("ChaCha20");

    private static final EngineProvider ENGINE_PROVIDER;

    static
    {
        EngineProvider provider = new EngineProvider();

        provider.createEngine();

        ENGINE_PROVIDER = provider;
    }

    public static final Parameters STREAM = new Parameters(ALGORITHM);

    /**
     * Parameters for ChaCha20 cipher.
     */
    public static final class Parameters
        extends GeneralParametersWithIV<Parameters>
    {
        private Parameters(GeneralAlgorithm algorithm, byte[] iv)
        {
            super(algorithm, 12, iv);
            if (iv != null && iv.length != 12)
            {
                throw new IllegalArgumentException("IV must be 12 bytes long");
            }
        }

        Parameters(GeneralAlgorithm algorithm)
        {
            this(algorithm, null);
        }

        public Parameters withIV(SecureRandom random)
        {
            byte[] iv = new byte[12];
            
            random.nextBytes(iv);

            return create(this.getAlgorithm(), iv);
        }

        protected Parameters create(GeneralAlgorithm algorithm, byte[] iv)
        {
            return new Parameters(algorithm, iv);
        }
    }

    /**
     * ChaCha20 key generator.
     */
    public static final class KeyGenerator
        extends GuardedSymmetricKeyGenerator
    {
        private static final int keySizeInBits = 256;
        
        private final GeneralAlgorithm algorithm;
        private final SecureRandom random;

        public KeyGenerator(SecureRandom random)
        {
            this(ALGORITHM, random);
        }

        public KeyGenerator(GeneralParameters parameterSet, SecureRandom random)
        {
             this((GeneralAlgorithm)parameterSet.getAlgorithm(), random);
        }

        private KeyGenerator(GeneralAlgorithm algorithm, SecureRandom random)
        {
            this.algorithm = algorithm;
            this.random = random;
        }

        public SymmetricKey doGenerateKey()
        {
            CipherKeyGenerator cipherKeyGenerator = new CipherKeyGenerator();

            cipherKeyGenerator.init(new KeyGenerationParameters(random, keySizeInBits));

            return new SymmetricSecretKey(algorithm, cipherKeyGenerator.generateKey());
        }
    }

    /**
     * Factory for basic ChaCha20 encryption/decryption operators.
     */
    public static final class OperatorFactory
        extends GuardedSymmetricStreamOperatorFactory<Parameters>
    {
        @Override
        protected StreamCipher createCipher(boolean forEncryption, SymmetricKey key, Parameters parameters, SecureRandom random)
        {
            StreamCipher cipher = ENGINE_PROVIDER.createEngine();

            CipherParameters params = Utils.getKeyParameter(validateKey(key, parameters.getAlgorithm()));

            if (parameters.iv == null || parameters.iv.length != 12)
            {
                throw new IllegalArgumentException("IV must be 12 bytes long");
            }

            cipher.init(forEncryption, new ParametersWithIV(params, parameters.iv));

            return cipher;
        }
    }

    private static ValidatedSymmetricKey validateKey(SymmetricKey key, Algorithm algorithm)
    {
        ValidatedSymmetricKey vKey = PrivilegedUtils.getValidatedKey(key);

        int keyLength = vKey.getKeySizeInBits();
        if (invalidKeySize(keyLength))
        {
            throw new IllegalKeyException("ChaCha20 key must be 256 bits");
        }

        Utils.checkKeyAlgorithm(vKey, ALGORITHM, algorithm);

        return vKey;
    }

    private static boolean invalidKeySize(int keyLength)
    {
        return keyLength != 256;
    }

    private static final class EngineProvider
        implements org.bouncycastle.crypto.internal.EngineProvider<StreamCipher>
    {
        static final byte[] input = Hex.decode("00112233445566778899aabbccddeeff");
        static final byte[] output = Hex.decode("39ec094e9d907f1d0524a9cc7401a4b6");
        static final byte[] iv = Hex.decode("000000000000000000000000");
        static final byte[] key = Hex.decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

        public StreamCipher createEngine()
        {
            return SelfTestExecutor.validate(ALGORITHM, new ChaCha7539Engine(), new VariantKatTest<ChaCha7539Engine>()
            {
                public void evaluate(ChaCha7539Engine engine)
                {

                    byte[] tmp = new byte[input.length];

                    engine.init(true, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    engine.processBytes(input, 0, input.length, tmp, 0);

                    if (!Arrays.areEqual(output, tmp))
                    {
                        fail("Failed self test on encryption");
                    }

                    engine.init(false, new ParametersWithIV(new KeyParameterImpl(key), iv));

                    engine.processBytes(output, 0, output.length, tmp, 0);

                    if (!Arrays.areEqual(input, tmp))
                    {
                        fail("Failed self test on decryption");
                    }
                }
            });
        }
    }
}
