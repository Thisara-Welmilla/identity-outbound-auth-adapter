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

 import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

 public class TestAuthenticatedTestUserBuilder {

     public static class AuthenticatedUserConstants {

         public static final String USER_ID_TEST = "user-123";
         public static final String USERNAME_TEST = "testUser";
         public static final String LOCAL_USER_PREFIX = "local-";
         public static final String FED_USER_PREFIX = "fed-";
         public static final String USER_STORE_TEST = "PRIMARY";
         public static final String FED_IDP_NAME = "test-idp";
         public static final String ORG_ID = "0987";
         public static final String ORG_NAME = "org123";
     }

     public static AuthenticatedUser createAuthenticatedUser(String userPrefix, String tenantDomain) {

         AuthenticatedUser authenticatedUser = new AuthenticatedUser();
         authenticatedUser.setUserId(userPrefix + AuthenticatedUserConstants.USER_ID_TEST);
         authenticatedUser.setUserName(userPrefix + AuthenticatedUserConstants.USERNAME_TEST);
         authenticatedUser.setUserStoreDomain(AuthenticatedUserConstants.USER_STORE_TEST);
         if (userPrefix.equals(AuthenticatedUserConstants.FED_USER_PREFIX)) {
             authenticatedUser.setFederatedUser(true);
             authenticatedUser.setFederatedIdPName(AuthenticatedUserConstants.FED_IDP_NAME);
         } else {
             authenticatedUser.setFederatedUser(false);
         }
         authenticatedUser.setUserResidentOrganization(AuthenticatedUserConstants.ORG_ID);
         authenticatedUser.setAuthenticatedSubjectIdentifier(userPrefix + AuthenticatedUserConstants.USER_ID_TEST);
         authenticatedUser.setTenantDomain(tenantDomain);

         // set claims
         return authenticatedUser;
     }
}
