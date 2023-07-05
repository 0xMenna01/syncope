package org.apache.syncope.core.spring.security.utils;

import org.apache.commons.text.CharacterPredicate;
import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.provisioning.api.serialization.POJOHelper;
import org.apache.syncope.core.spring.SpringTestConfiguration;
import org.apache.syncope.core.spring.security.PasswordGeneratorTest;
import org.apache.syncope.core.spring.security.utils.impl.TestImplementation;
import org.apache.syncope.core.spring.security.utils.impl.TestPasswordPolicy;
import org.mockito.Mockito;
import org.passay.PasswordData;
import org.passay.RepeatCharactersRule;
import org.passay.RuleResult;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.List;


@SpringJUnitConfig(classes = {SpringTestConfiguration.class})
public class TestUtils {

    public static final int DEFAULT_MAX_LENGTH = 64;
    public static final int DEFAULT_MIN_LENGTH = 8;

    private TestUtils() {
    }

    public static List<PasswordPolicy> getPasswdPolicies(DefaultPasswordRuleConf ruleConfig) {
        TestImplementation passwordRule = new TestImplementation();
        passwordRule.setBody(POJOHelper.serialize(ruleConfig));
        return List.of(new TestPasswordPolicy(passwordRule));
    }

    public static List<PasswordPolicy> mockInvalidListForPolicies() {
        List<PasswordPolicy> invalidMockPolicies = Mockito.mock(List.class);
        Mockito.when(invalidMockPolicies.stream()).thenThrow(new RuntimeException("Invalid policies"));

        return invalidMockPolicies;
    }

    public static DefaultPasswordRuleConf createDefaultPasswordRuleConfig() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        defaultPasswordRuleConf.setMaxLength(DEFAULT_MAX_LENGTH);
        defaultPasswordRuleConf.setMinLength(DEFAULT_MIN_LENGTH);
        defaultPasswordRuleConf.setUppercase(1);
        
        return defaultPasswordRuleConf;
    }


    public static DefaultPasswordRuleConf buildCustomGenerator(PasswordGeneratorTest.DefaultGenerator generator) {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();

        switch (generator) {
            case INVALID_LENGTH -> {
                defaultPasswordRuleConf.setMinLength(5);
                defaultPasswordRuleConf.setMaxLength(4);
            }
            case FIXED_ALPHABETICAL -> {
                defaultPasswordRuleConf.setMinLength(5);
                defaultPasswordRuleConf.setAlphabetical(5);
            }
            case FIXED_UPPERCASE -> {
                defaultPasswordRuleConf.setMinLength(5);
                defaultPasswordRuleConf.setUppercase(5);
            }
            case FIXED_DIGIT -> {
                defaultPasswordRuleConf.setMinLength(5);
                defaultPasswordRuleConf.setDigit(5);
            }
            case FIXED_LOWERCASE -> {
                defaultPasswordRuleConf.setMinLength(5);
                defaultPasswordRuleConf.setLowercase(5);
            }
            case REPEATED_CHARS -> {
                defaultPasswordRuleConf.setRepeatSame(5);
            }
        }

        return defaultPasswordRuleConf;
    }

    public static boolean isExceptionExpected(PasswordGeneratorTest.PoliciesType policiesType) {
        boolean isExceptionExpected = true;

        if (policiesType.equals(PasswordGeneratorTest.PoliciesType.VALID_LIST) ||
            policiesType.equals(PasswordGeneratorTest.PoliciesType.EMPTY_LIST))
            isExceptionExpected = false;

        return isExceptionExpected;
    }

    private static int count(String password, CharacterPredicate predicate) {
        int count = 0;
        for (char c : password.toCharArray()) {
            if (predicate.test(c)) {
                count++;
            }
        }
        return count;
    }

    public static boolean verifyLowercaseRule(String password, int numValue) {
        return count(password, Character::isLowerCase) >= numValue;
    }

    public static boolean verifyDigitRule(String password, int numValue) {
        return count(password, Character::isDigit) >= numValue;
    }

    public static boolean verifyAlphabeticalRule(String password, int numValue) {
        return count(password, Character::isAlphabetic) >= numValue;
    }

    public static boolean verifyUppercaseRule(String password, int numValue) {
        return count(password, Character::isUpperCase) >= numValue;
    }

    public static boolean verifyLength(String password, int min, int max) {
        return password.length() >= min && password.length() <= max;
    }

    public static boolean verifyRepeatedRule(String password, int numRepeated) {
        RepeatCharactersRule rule = new RepeatCharactersRule(numRepeated);
        PasswordData passwordData = new PasswordData(password);
        RuleResult result = rule.validate(passwordData);
        return result.isValid();
    }


}
