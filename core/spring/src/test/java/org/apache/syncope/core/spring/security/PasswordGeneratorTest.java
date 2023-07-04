package org.apache.syncope.core.spring.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.apache.syncope.core.spring.SpringTestConfiguration;
import org.apache.syncope.core.spring.security.utils.TestUtils;
import org.apache.syncope.core.spring.security.utils.impl.TestImplementation;
import org.apache.syncope.core.spring.security.utils.impl.TestPasswordPolicy;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@SpringJUnitConfig(classes = {SpringTestConfiguration.class})
public class PasswordGeneratorTest {

    private final DefaultPasswordGenerator passwordGenerator = new DefaultPasswordGenerator();


    @ParameterizedTest
    @MethodSource("buildPolicies")
    public void testDefaultPasswordGeneration(PoliciesType policiesType) {
        boolean isExceptionExpected = TestUtils.isExceptionExpected(policiesType);

        try {
            List<PasswordPolicy> policies = null;
            switch (policiesType) {
                case EMPTY_LIST:
                    policies = new ArrayList<PasswordPolicy>();
                    break;
                case INVALID_LIST:
                    policies = TestUtils.mockInvalidListForPolicies();
                    break;
                case VALID_LIST:
                    DefaultPasswordRuleConf defaultPasswordRuleConf = TestUtils.createDefaultPasswordRuleConfig();
                    // Be sure to check password generation matches the digit
                    defaultPasswordRuleConf.setDigit(1);
                    TestImplementation passwordRule = new TestImplementation();
                    passwordRule.setBody(POJOHelper.serialize(defaultPasswordRuleConf));
                    policies = List.of(new TestPasswordPolicy(passwordRule));
                    break;
            }

            String generatedPassword = passwordGenerator.generate(policies);

            assertFalse(isExceptionExpected, "An exception was expected because policies is of type: " +
                policiesType.toString());

            if (policiesType.equals(PoliciesType.VALID_LIST))
                assertTrue(generatedPassword.chars().anyMatch(Character::isDigit));

        } catch (Exception e) {
            assertTrue(isExceptionExpected, "No exception was expected" +
                ", but " + e.getClass().getName() + " has been thrown\n");
        }
    }


    @ParameterizedTest
    @MethodSource("buildRules")
    public void testGenerationMultipleRules(GenerationRule generationRule) {
        DefaultPasswordRuleConf defaultPasswordRuleConf = TestUtils.createDefaultPasswordRuleConfig();
        testMultipleRules(defaultPasswordRuleConf, generationRule);
    }


    @ParameterizedTest
    @MethodSource("buildRules")
    public void testOtherGeneratorsMultipleRules(GenerationRule generationRule) {
        DefaultPasswordRuleConf[] defaultGenerators = TestUtils.buildOtherGenerators();
        for (DefaultPasswordRuleConf generator : defaultGenerators) {
            testMultipleRules(generator, generationRule);
        }
    }

    @Test
    public void testFixedDigitsPasswd() {
        DefaultPasswordRuleConf onlyDigitGenerator = TestUtils.createLowMaxLengthOnlyDigitConfig();
        TestImplementation passwordRule = new TestImplementation();
        passwordRule.setBody(POJOHelper.serialize(onlyDigitGenerator));
        List<PasswordPolicy> policies = List.of(new TestPasswordPolicy(passwordRule));

        String generatedPassword = passwordGenerator.generate(policies);
        assertTrue(generatedPassword.chars().allMatch(Character::isDigit));
    }

    @Test
    public void testFixedAlphabeticalPasswd() {
        DefaultPasswordRuleConf onlyAlphabeticalConfig = TestUtils.createLowMaxLengthOnlyAlphabeticalConfig();
        TestImplementation passwordRule = new TestImplementation();
        passwordRule.setBody(POJOHelper.serialize(onlyAlphabeticalConfig));
        List<PasswordPolicy> policies = List.of(new TestPasswordPolicy(passwordRule));

        String generatedPassword = passwordGenerator.generate(policies);
        assertTrue(generatedPassword.chars().allMatch(Character::isAlphabetic));
    }


    private void testMultipleRules(DefaultPasswordRuleConf defaultPasswordRuleConf, GenerationRule generationRule) {
        setGenerationRule(defaultPasswordRuleConf, generationRule);

        TestImplementation passwordRule = new TestImplementation();
        passwordRule.setBody(POJOHelper.serialize(defaultPasswordRuleConf));
        List<PasswordPolicy> policies = List.of(new TestPasswordPolicy(passwordRule));

        String generatedPassword = passwordGenerator.generate(policies);
        assertRule(generatedPassword, generationRule);
    }

    private void assertRule(String generatedPassword, GenerationRule generationRule) {
        switch (generationRule) {
            case ALPHABETICAL -> assertTrue(generatedPassword.chars().anyMatch(Character::isAlphabetic));
            case UPPERCASE -> assertTrue(generatedPassword.chars().anyMatch(Character::isUpperCase));
            case LOWERCASE -> assertTrue(generatedPassword.chars().anyMatch(Character::isLowerCase));
            case DIGIT -> assertTrue(generatedPassword.chars().anyMatch(Character::isDigit));
            case SPECIAL ->
                assertTrue(generatedPassword.chars().anyMatch(c -> '$' == c || '!' == c || '#' == c || '*' == c));
        }
    }


    private void setGenerationRule(DefaultPasswordRuleConf defaultPasswordRuleConf, GenerationRule generationRule) {
        switch (generationRule) {
            case ALPHABETICAL -> defaultPasswordRuleConf.setAlphabetical(1);
            case UPPERCASE -> defaultPasswordRuleConf.setUppercase(1);
            case LOWERCASE -> defaultPasswordRuleConf.setLowercase(1);
            case DIGIT -> defaultPasswordRuleConf.setDigit(1);
            case SPECIAL -> {
                defaultPasswordRuleConf.setSpecial(1);
                defaultPasswordRuleConf.getSpecialChars().add('$');
                defaultPasswordRuleConf.getSpecialChars().add('!');
                defaultPasswordRuleConf.getSpecialChars().add('#');
                defaultPasswordRuleConf.getSpecialChars().add('*');
            }
        }
    }

    public enum PoliciesType {
        VALID_LIST,
        INVALID_LIST,
        EMPTY_LIST,
        NULL,
    }

    private enum GenerationRule {
        ALPHABETICAL,
        UPPERCASE,
        LOWERCASE,
        DIGIT,
        SPECIAL,
    }


    private static Stream<Arguments> buildPolicies() {
        List<Arguments> parameters = new ArrayList<>();

        for (PoliciesType value : PoliciesType.values()) {
            Arguments argument = Arguments.of(value);
            parameters.add(argument);
        }
        return parameters.stream();
    }


    private static Stream<Arguments> buildRules() {
        List<Arguments> parameters = new ArrayList<>();

        for (GenerationRule rule : GenerationRule.values()) {
            Arguments argument = Arguments.of(rule);
            parameters.add(argument);
        }
        return parameters.stream();
    }

}
