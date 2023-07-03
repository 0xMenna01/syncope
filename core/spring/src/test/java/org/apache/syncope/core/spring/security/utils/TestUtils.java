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


    public static boolean isExceptionExpected(PasswordGeneratorTest.PoliciesType policiesType) {
        boolean isExceptionExpected = true;

        if (policiesType.equals(PasswordGeneratorTest.PoliciesType.VALID_LIST) ||
            policiesType.equals(PasswordGeneratorTest.PoliciesType.EMPTY_LIST))
            isExceptionExpected = false;

        return isExceptionExpected;
    }


}
