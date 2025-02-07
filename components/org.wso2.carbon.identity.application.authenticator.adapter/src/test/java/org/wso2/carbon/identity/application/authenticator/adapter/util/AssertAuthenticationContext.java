/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.adapter.util;

import org.testng.Assert;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.Map;

public class AssertAuthenticationContext {

    public static void assertAuthenticationContext(AuthenticationContext context,
                                                   AuthenticatedUser expectedUser) throws Exception {

        Assert.assertNotNull(context);
        AuthenticatedUser subject = context.getSubject();
        assertAuthenticatedUser(subject, expectedUser);
    }

    public static void assertAuthenticatedUser(AuthenticatedUser authenticatedUser, AuthenticatedUser expectedUser)
            throws Exception {

        Assert.assertNotNull(authenticatedUser);
        Assert.assertEquals(authenticatedUser.getUserId(), expectedUser.getUserId());
        Assert.assertEquals(authenticatedUser.getUserStoreDomain(), expectedUser.getUserStoreDomain());
        Assert.assertEquals(authenticatedUser.getUserName(), expectedUser.getUserName());
        Assert.assertEquals(authenticatedUser.isFederatedUser(), expectedUser.isFederatedUser());
        Assert.assertEquals(authenticatedUser.getFederatedIdPName(), expectedUser.getFederatedIdPName());
        Assert.assertEquals(authenticatedUser.getTenantDomain(), expectedUser.getTenantDomain());
        for (Map.Entry<ClaimMapping, String> claim : expectedUser.getUserAttributes().entrySet()) {
            Assert.assertEquals(authenticatedUser.getUserAttributes().get(claim.getKey()), claim.getValue());
        }
    }

    public static void assertFailureContext(AuthenticationContext context,
                                             String errorCode, String errorMgt) throws Exception {

        Assert.assertNotNull(context);
        Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), errorCode);
        Assert.assertEquals(context.getProperty(FrameworkConstants.AUTH_ERROR_MSG), errorMgt);
    }
}
