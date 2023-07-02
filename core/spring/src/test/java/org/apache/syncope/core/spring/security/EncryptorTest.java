package org.apache.syncope.core.spring.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;


@RunWith(Parameterized.class)
public class EncryptorTest{
    private static List<Encryptor> ENCRYPTORS;
    private static MockedStatic<ApplicationContextProvider> UTIL;

    // Parameters constructed by category partition
    private final PlainTextValue plainText;
    private final CipherAlgorithm cipherAlgorithm;

    @BeforeClass
    public static void setUp(){
        DefaultListableBeanFactory factory=new DefaultListableBeanFactory();

        factory.registerSingleton("securityProperties", new SecurityProperties());

        UTIL = Mockito.mockStatic(ApplicationContextProvider.class);
        UTIL.when(ApplicationContextProvider::getBeanFactory).thenReturn(factory);
        UTIL.when(ApplicationContextProvider::getApplicationContext).thenReturn(new DummyConfigurableApplicationContext(factory));

        // Configure different instances of encryptor through different private keys.
        List<Encryptor> encryptors = new ArrayList<>();

        for (PrivateKeyType privateKey: PrivateKeyType.values()) {
            encryptors.add(Encryptor.getInstance(privateKey.key));
        }

        ENCRYPTORS = encryptors;
    }


    // Generated with https://www.random.org/strings/
    private enum PrivateKeyType {
        VALID_STRING("3RdZ8QfJ6wmmRHkJ"),
        EMPTY_STRING(""),
        INVALID_ONE_CHAR_STRING("r"),
        INVALID_FIFTEEN_CHARS_STRING("uZskLibmHjAxqcN"),
        NULL_STRING(null);

        private String key;

        PrivateKeyType(String key) {
            this.key = key;
        }
    }


    public EncryptorTest(PlainTextValue plainText, CipherAlgorithm cipherAlgorithm) {
        this.plainText = plainText;
        this.cipherAlgorithm = cipherAlgorithm;
    }

    private enum PlainTextValue {
        VALID_STRING("secret_password"),
        EMPTY_STRING(""),
        NULL_STRING(null);

        private String value;

        PlainTextValue(String value) {
            this.value = value;
        }

    }


    @Parameterized.Parameters
    public static Collection<Object[]> getParameters() {
        List<Object[]> parameters = new ArrayList<>();

        for(PlainTextValue value: PlainTextValue.values()) {
            for (CipherAlgorithm cipher : CipherAlgorithm.values()) {
                Object[] parameterSet = {value, cipher};
                parameters.add(parameterSet);
            }
        }
        return parameters;
    }

    @Test
    public void testEncryptWithoutVerify() throws Exception {

        for (Encryptor encryptor: ENCRYPTORS) {

            String encryptedValue = encryptor.encode(plainText.value, cipherAlgorithm);

            switch (plainText) {
                case NULL_STRING:
                    Assert.assertEquals("A null value must return a null ciphertext", encryptedValue, null);
                    break;

                default:
                    Assert.assertNotEquals("The encrypted value must not be null", encryptedValue, null);
                    Assert.assertNotEquals("The encrypted value must be different then the original one",
                        encryptedValue, plainText.value);
            }
        }


    }


    @Test
    public void testEncryptWithVerify() throws Exception {

        for (Encryptor encryptor: ENCRYPTORS) {
            String encryptedValue = encryptor.encode(plainText.value, cipherAlgorithm);

            switch (plainText) {
                case NULL_STRING:
                    Assert.assertFalse("A null value cannot be verified",
                        encryptor.verify(plainText.value, cipherAlgorithm, encryptedValue));
                    break;

                default:
                    Assert.assertTrue("The verification of the ciphertext and plaintext has failed",
                        encryptor.verify(plainText.value, cipherAlgorithm, encryptedValue));
            }
        }

    }

}
