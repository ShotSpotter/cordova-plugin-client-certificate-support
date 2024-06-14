package org.bouncycastle.crypto.fips;

import org.bouncycastle.crypto.EntropySource;

class DRBGPseudoRandom
    implements DRBG
{
    private final FipsAlgorithm algorithm;
    private final DRBGProvider drbgProvider;
    private final EntropySource entropySource;

    private DRBG drbg;

    DRBGPseudoRandom(FipsAlgorithm algorithm, EntropySource entropySource, DRBGProvider drbgProvider)
    {
        this.algorithm = algorithm;
        this.entropySource = new ContinuousTestingEntropySource(entropySource);
        this.drbgProvider = drbgProvider;
    }

    /**
     * Return the block size of the underlying DRBG
     *
     * @return number of bits produced each cycle.
     */
    public int getBlockSize()
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.getBlockSize();
        }
    }

    public int getSecurityStrength()
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.getSecurityStrength();
        }
    }

    private void lazyInitDRBG()
    {
        if (drbg == null)
        {
            drbg = drbgProvider.get(entropySource);
            // FSM_TRANS:5.5, "CONDITIONAL TEST", "DRBG HEALTH CHECKS", "Invoke DRBG Health Check"
            SelfTestExecutor.validate(algorithm, drbg.createSelfTest(algorithm));   // instance health test
            // FSM_TRANS:5.6, "DRBG HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Health Check successful"
        }
    }

    public int generate(byte[] output, byte[] additionalInput, boolean predictionResistant)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            // if predictionResistant a reseed will be performed at the start of generate.
            if (predictionResistant)
            {
                // FSM_STATE:5.8, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                // FSM_TRANS:5.11, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));    // reseed health test
                // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                // FSM_TRANS:5.13, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"
            }

            // check if a reseed is required...
            if (drbg.generate(output, additionalInput, predictionResistant) < 0)
            {
                // FSM_STATE:5.8, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
                // FSM_TRANS:5.11, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
                SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));    // reseed health test
                // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
                // FSM_TRANS:5.13, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"

                drbg.reseed(null);
                return drbg.generate(output, additionalInput, predictionResistant);
            }

            return output.length;
        }
    }

    public void reseed(byte[] additionalInput)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            // FSM_STATE:5.8, "DRBG RESEED HEALTH CHECKS", "The module is performing DRBG Reseed Health Check self-test"
            // FSM_TRANS:5.11, "CONDITIONAL TEST", "DRBG RESEED HEALTH CHECKS", "Invoke DRBG Reseed Health Check"
            SelfTestExecutor.validate(algorithm, drbg.createReseedSelfTest(algorithm));   // reseed health test.
            // FSM_TRANS:5.12, "DRBG RESEED HEALTH CHECKS", "CONDITIONAL TEST", "DRBG Reseed Health Check successful"
            // FSM_TRANS:5.13, "DRBG RESEED HEALTH CHECKS", "SOFT ERROR", "DRBG Reseed Health Check failed"

            drbg.reseed(additionalInput);
        }
    }

    public VariantInternalKatTest createSelfTest(FipsAlgorithm algorithm)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.createSelfTest(algorithm);
        }
    }

    public VariantInternalKatTest createReseedSelfTest(FipsAlgorithm algorithm)
    {
        synchronized (this)
        {
            lazyInitDRBG();

            return drbg.createReseedSelfTest(algorithm);
        }
    }
}
