package org.apache.syncope.core.spring.security.utils;

import org.apache.syncope.common.lib.policy.DefaultPasswordRuleConf;
import org.apache.syncope.core.persistence.api.entity.policy.PasswordPolicy;
import org.apache.syncope.core.spring.SpringTestConfiguration;
import org.apache.syncope.core.spring.security.PasswordGeneratorTest;
import org.mockito.Mockito;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.List;

@SpringJUnitConfig(classes = {SpringTestConfiguration.class})
public class TestUtils {

    private TestUtils() {
    }

    public static List<PasswordPolicy> mockInvalidListForPolicies() {
        List<PasswordPolicy> invalidMockPolicies = Mockito.mock(List.class);
        Mockito.when(invalidMockPolicies.stream()).thenThrow(new RuntimeException("Invalid policies"));

        return invalidMockPolicies;
    }

    public static DefaultPasswordRuleConf createDefaultPasswordRuleConfig() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        defaultPasswordRuleConf.setMaxLength(100);
        defaultPasswordRuleConf.setMinLength(8);
        defaultPasswordRuleConf.setUppercase(1);

        return defaultPasswordRuleConf;
    }

    private static DefaultPasswordRuleConf createEmptyPasswordRuleConfig() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        return defaultPasswordRuleConf;
    }

    public static DefaultPasswordRuleConf createLowMaxLengthOnlyDigitConfig() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        defaultPasswordRuleConf.setMinLength(5);
        defaultPasswordRuleConf.setMaxLength(5);
        defaultPasswordRuleConf.setRepeatSame(2);
        defaultPasswordRuleConf.setDigit(5);
        return defaultPasswordRuleConf;
    }

    public static DefaultPasswordRuleConf createLowMaxLengthOnlyAlphabeticalConfig() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        defaultPasswordRuleConf.setMinLength(5);
        defaultPasswordRuleConf.setMaxLength(5);
        defaultPasswordRuleConf.setAlphabetical(5);
        return defaultPasswordRuleConf;
    }

    private static DefaultPasswordRuleConf createZeroLengthPasswdRule() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        defaultPasswordRuleConf.setMinLength(0);
        return defaultPasswordRuleConf;
    }

    private static DefaultPasswordRuleConf createMinGreaterThanMaxLengthRule() {
        DefaultPasswordRuleConf defaultPasswordRuleConf = new DefaultPasswordRuleConf();
        defaultPasswordRuleConf.setMinLength(2);
        defaultPasswordRuleConf.setMaxLength(1);
        return defaultPasswordRuleConf;
    }

    public static DefaultPasswordRuleConf[] buildOtherGenerators() {
        DefaultPasswordRuleConf emptyRulesGenerator = createEmptyPasswordRuleConfig();
        DefaultPasswordRuleConf minLengthZeroGenerator = createZeroLengthPasswdRule();
        DefaultPasswordRuleConf minGreaterThanMaxGenerator = createMinGreaterThanMaxLengthRule();

        return new DefaultPasswordRuleConf[]{emptyRulesGenerator, minLengthZeroGenerator, minGreaterThanMaxGenerator};
    }


    public static boolean isExceptionExpected(PasswordGeneratorTest.PoliciesType policiesType) {
        boolean isExceptionExpected = true;

        if (policiesType.equals(PasswordGeneratorTest.PoliciesType.VALID_LIST) ||
            policiesType.equals(PasswordGeneratorTest.PoliciesType.EMPTY_LIST))
            isExceptionExpected = false;

        return isExceptionExpected;
    }


}
