package org.bouncycastle.jcajce.provider;

import java.lang.reflect.Constructor;
import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.crypto.BadPaddingException;

/**
 * Holder for things that are not always available...
 */
class ClassUtil
{
    private static final Constructor aeadBadTagConstructor;

    static
    {
        Class aeadBadTagClass = lookup("javax.crypto.AEADBadTagException");
        if (aeadBadTagClass != null)
        {
            aeadBadTagConstructor = findExceptionConstructor(aeadBadTagClass);
        }
        else
        {
            aeadBadTagConstructor = null;
        }
    }

    private static Constructor findExceptionConstructor(Class clazz)
    {
        try
        {
            return clazz.getConstructor(new Class[]{String.class});
        }
        catch (Exception e)
        {
            return null;
        }
    }

    static Class lookup(final String className)
    {
        return AccessController.doPrivileged(new PrivilegedAction<Class>()
        {
            public Class run()
            {
                try
                {
                    ClassLoader loader = ClassUtil.class.getClassLoader();

                    if (loader == null)
                    {
                        loader = ClassLoader.getSystemClassLoader();
                    }

                    return loader.loadClass(className);
                }
                catch (Exception e)
                {
                    return null;
                }
            }
        });
    }

    public static void throwBadTagException(String message)
        throws BadPaddingException
    {
        if (aeadBadTagConstructor != null)
        {
            BadPaddingException aeadBadTag = null;
            try
            {
                aeadBadTag = (BadPaddingException)aeadBadTagConstructor
                        .newInstance(new Object[]{message});
            }
            catch (Exception i)
            {
                // Shouldn't happen, but fall through to BadPaddingException
            }
            if (aeadBadTag != null)
            {
                throw aeadBadTag;
            }
        }

        throw new BadPaddingException(message);
    }
}
