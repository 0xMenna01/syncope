package org.apache.syncope.core.spring.security;

import static org.junit.jupiter.api.Assertions.*;

import org.apache.syncope.common.lib.types.CipherAlgorithm;
import org.apache.syncope.core.spring.ApplicationContextProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

public class EncryptorTest {
    private static List<Encryptor> ENCRYPTORS;

    private static MockedStatic<ApplicationContextProvider> UTIL;


    @BeforeAll
    public static void setUp() {
        DefaultListableBeanFactory factory = new DefaultListableBeanFactory();

        factory.registerSingleton("securityProperties", new SecurityProperties());

        UTIL = Mockito.mockStatic(ApplicationContextProvider.class);
        UTIL.when(ApplicationContextProvider::getBeanFactory).thenReturn(factory);
        UTIL.when(ApplicationContextProvider::getApplicationContext).thenReturn(new DummyConfigurableApplicationContext(factory));

        // Configure different instances of encryptor through different private keys.
        List<Encryptor> encryptors = new ArrayList<>();

        for (PrivateKeyType privateKey : PrivateKeyType.values()) {
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

    private enum PlainTextValue {
        VALID_STRING("secret_password"),
        EMPTY_STRING(""),
        NULL_STRING(null);

        private String value;

        PlainTextValue(String value) {
            this.value = value;
        }

    }

    private static Stream<Arguments> getParameters() {
        List<Arguments> parameters = new ArrayList<>();

        for (PlainTextValue value : PlainTextValue.values()) {
            for (CipherAlgorithm cipher : CipherAlgorithm.values()) {
                Arguments argument = Arguments.of(value, cipher);
                parameters.add(argument);
            }
        }
        return parameters.stream();
    }

    @ParameterizedTest
    @MethodSource("getParameters")
    public void testEncryptWithoutVerify(PlainTextValue plainText, CipherAlgorithm cipherAlgorithm) throws Exception {
        for (Encryptor encryptor : ENCRYPTORS) {
            String encryptedValue = encryptor.encode(plainText.value, cipherAlgorithm);

            switch (plainText) {
                case NULL_STRING:
                    assertNull(encryptedValue, "A null value must return a null ciphertext");
                    break;

                default:
                    assertNotNull(encryptedValue, "The encrypted value must not be null");
                    assertNotEquals(encryptedValue, plainText.value,
                        "The encrypted value must be different than the original one");
            }
        }
    }

    @ParameterizedTest
    @MethodSource("getParameters")
    public void testEncryptWithVerify(PlainTextValue plainText, CipherAlgorithm cipherAlgorithm) throws Exception {

        for (Encryptor encryptor : ENCRYPTORS) {
            String encryptedValue = encryptor.encode(plainText.value, cipherAlgorithm);

            switch (plainText) {
                case NULL_STRING:
                    assertFalse(encryptor.verify(plainText.value, cipherAlgorithm, encryptedValue),
                        "A null value cannot be verified");
                    break;

                default:
                    assertTrue(encryptor.verify(plainText.value, cipherAlgorithm, encryptedValue),
                        "The verification of the ciphertext and plaintext has failed");
            }
        }
    }

    @ParameterizedTest
    @MethodSource("getParameters")
    public void testEncryptMultipleTimes(PlainTextValue plainText, CipherAlgorithm cipherAlgorithm) throws Exception {

        for (Encryptor encryptor : ENCRYPTORS) {
            String encryptedValue = encryptor.encode(plainText.value, cipherAlgorithm);

            if (!plainText.equals(PlainTextValue.NULL_STRING)) {
                if (cipherAlgorithm.isSalted() || cipherAlgorithm.equals(CipherAlgorithm.BCRYPT))
                    assertNotEquals(encryptedValue, encryptor.encode(plainText.value, cipherAlgorithm));

                else assertEquals(encryptedValue, encryptor.encode(plainText.value, cipherAlgorithm));
            }

        }
    }

    @AfterAll
    public static void tearDown() {
        UTIL.close();
    }

}
