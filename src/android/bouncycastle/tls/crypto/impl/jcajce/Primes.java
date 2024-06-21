package org.bouncycastle.tls.crypto.impl.jcajce;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.BigIntegers;

/**
 * Utility methods for generating primes and testing for primality.
 */
abstract class Primes
{
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /**
     * A fast check for small divisors, up to some implementation-specific limit.
     *
     * @param candidate
     *            the {@link BigInteger} instance to test for division by small factors.
     *
     * @return <code>true</code> if the candidate is found to have any small factors,
     *         <code>false</code> otherwise.
     */
    public static boolean hasAnySmallFactors(BigInteger candidate)
    {
        checkCandidate(candidate, "candidate");

        return implHasAnySmallFactors(candidate);
    }

    /**
     * FIPS 186-4 C.3.1 Miller-Rabin Probabilistic Primality Test
     *
     * Run several iterations of the Miller-Rabin algorithm with randomly-chosen bases.
     *
     * @param candidate
     *            the {@link BigInteger} instance to test for primality.
     * @param random
     *            the source of randomness to use to choose bases.
     * @param iterations
     *            the number of randomly-chosen bases to perform the test for.
     * @return <code>false</code> if any witness to compositeness is found amongst the chosen bases
     *         (so <code>candidate</code> is definitely NOT prime), or else <code>true</code>
     *         (indicating primality with some probability dependent on the number of iterations
     *         that were performed).
     */
    public static boolean isMRProbablePrime(BigInteger candidate, SecureRandom random, int iterations)
    {
        checkCandidate(candidate, "candidate");

        if (random == null)
        {
            throw new IllegalArgumentException("'random' cannot be null");
        }
        if (iterations < 1)
        {
            throw new IllegalArgumentException("'iterations' must be > 0");
        }

        if (candidate.bitLength() == 2)
        {
            return true;
        }
        if (!candidate.testBit(0))
        {
            return false;
        }

        BigInteger wSubOne = candidate.subtract(ONE);
        BigInteger wSubTwo = candidate.subtract(TWO);

        int a = wSubOne.getLowestSetBit();
        BigInteger m = wSubOne.shiftRight(a);

        for (int i = 0; i < iterations; ++i)
        {
            BigInteger b = BigIntegers.createRandomInRange(TWO, wSubTwo, random);

            if (!implMRProbablePrimeToBase(candidate, wSubOne, m, a, b))
            {
                return false;
            }
        }

        return true;
    }

    private static void checkCandidate(BigInteger n, String name)
    {
        if (n == null || n.signum() < 1 || n.bitLength() < 2)
        {
            throw new IllegalArgumentException("'" + name + "' must be non-null and >= 2");
        }
    }

    private static boolean implHasAnySmallFactors(BigInteger x)
    {
        /*
         * Bundle trial divisors into ~32-bit moduli then use fast tests on the ~32-bit remainders.
         */
        int m = 2 * 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23;
        int r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 2) == 0 || (r % 3) == 0 || (r % 5) == 0 || (r % 7) == 0 || (r % 11) == 0 || (r % 13) == 0
            || (r % 17) == 0 || (r % 19) == 0 || (r % 23) == 0)
        {
            return true;
        }

        m = 29 * 31 * 37 * 41 * 43;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 29) == 0 || (r % 31) == 0 || (r % 37) == 0 || (r % 41) == 0 || (r % 43) == 0)
        {
            return true;
        }

        m = 47 * 53 * 59 * 61 * 67;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 47) == 0 || (r % 53) == 0 || (r % 59) == 0 || (r % 61) == 0 || (r % 67) == 0)
        {
            return true;
        }

        m = 71 * 73 * 79 * 83;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 71) == 0 || (r % 73) == 0 || (r % 79) == 0 || (r % 83) == 0)
        {
            return true;
        }

        m = 89 * 97 * 101 * 103;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 89) == 0 || (r % 97) == 0 || (r % 101) == 0 || (r % 103) == 0)
        {
            return true;
        }

        m = 107 * 109 * 113 * 127;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 107) == 0 || (r % 109) == 0 || (r % 113) == 0 || (r % 127) == 0)
        {
            return true;
        }

        m = 131 * 137 * 139 * 149;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 131) == 0 || (r % 137) == 0 || (r % 139) == 0 || (r % 149) == 0)
        {
            return true;
        }

        m = 151 * 157 * 163 * 167;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 151) == 0 || (r % 157) == 0 || (r % 163) == 0 || (r % 167) == 0)
        {
            return true;
        }

        m = 173 * 179 * 181 * 191;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 173) == 0 || (r % 179) == 0 || (r % 181) == 0 || (r % 191) == 0)
        {
            return true;
        }

        m = 193 * 197 * 199 * 211;
        r = x.mod(BigInteger.valueOf(m)).intValue();
        if ((r % 193) == 0 || (r % 197) == 0 || (r % 199) == 0 || (r % 211) == 0)
        {
            return true;
        }

        /*
         * NOTE: Unit tests depend on SMALL_FACTOR_LIMIT matching the
         * highest small factor tested here.
         */
        return false;
    }

    private static boolean implMRProbablePrimeToBase(BigInteger w, BigInteger wSubOne, BigInteger m, int a, BigInteger b)
    {
        BigInteger z = b.modPow(m, w);

        if (z.equals(ONE) || z.equals(wSubOne))
        {
            return true;
        }

        boolean result = false;

        for (int j = 1; j < a; ++j)
        {
            z = z.modPow(TWO, w);

            if (z.equals(wSubOne))
            {
                result = true;
                break;
            }

            if (z.equals(ONE))
            {
                return false;
            }
        }

        return result;
    }
}