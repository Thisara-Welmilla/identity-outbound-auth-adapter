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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.UserClaim;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

public class AuthenticatedUserBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticatedUserBuilder.class);
    private AuthenticatedUser authenticatedUser;
    private final AuthenticatedUserData user;
    private final AuthenticationContext context;
    private final AuthenticatorAdapterConstants.UserType userType;
    
    public AuthenticatedUserBuilder(AuthenticatedUserData user, AuthenticationContext context) {

        this.user = user;
        this.context = context;
        userType = resolveIdpType();
    }

    private void validateUserData() throws ActionExecutionResponseProcessorException {

        if (StringUtils.isBlank(user.getId())) {
            throw new ActionExecutionResponseProcessorException("User Id is not found in the authenticated user data.");
        }
        if (AuthenticatorAdapterConstants.UserType.LOCAL.equals(userType) && user.getUserStore() == null) {
            throw new ActionExecutionResponseProcessorException("User store domain is not found in the authenticated " +
                    "user data for the local user.");
        }
    }

    public AuthenticatedUser buildAuthenticateduser()
            throws ActionExecutionResponseProcessorException {

        validateUserData();

        if (AuthenticatorAdapterConstants.UserType.FEDERATED.equals(userType)) {
            resolveFederatedUser();
        } else {
            resolveLocalUser();
        }
        authenticatedUser.setTenantDomain(context.getTenantDomain());
        authenticatedUser.setUserAttributes(resolveUserClaims());

        return authenticatedUser;
    }

    private AuthenticatorAdapterConstants.UserType resolveIdpType() {

        return context.getExternalIdP() == null ?
                AuthenticatorAdapterConstants.UserType.LOCAL : AuthenticatorAdapterConstants.UserType.FEDERATED;
    }

    private User resolveLocalUserFromUserStore(AuthenticationContext context, UserStore userStore)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager = resolveUserStoreManager(context, userStore.getName());
        try {
            return userStoreManager.getUser(authenticatedUser.getUserId(), null);

        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String message = "Error occurred when trying to resolve local user by user Id:" + user.getId();
            throw new ActionExecutionResponseProcessorException(message, e);

        } catch (UserIdNotFoundException e) {
            String message = "No user found for the given user Id:" + user.getId();
            throw new ActionExecutionResponseProcessorException(message, e);
        }
    }

    private void resolveFederatedUser() {

        authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(user.getId());
        authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
        authenticatedUser.setFederatedUser(true);
    }

    private void resolveLocalUser() throws ActionExecutionResponseProcessorException {

        User localUser = resolveLocalUserFromUserStore(context, user.getUserStore());
        authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                localUser.getUserStoreDomain() + CarbonConstants.DOMAIN_SEPARATOR + localUser.getUsername());
    }

    private Map<ClaimMapping, String> resolveUserClaims() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        for (UserClaim claim : user.getClaims()) {
            userAttributes.put(ClaimMapping.build(
                    claim.getName(), claim.getName(), null, false), claim.getValue());
        }
        return userAttributes;
    }

    private AbstractUserStoreManager resolveUserStoreManager(AuthenticationContext context, String userStoreDomain)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager;

        try {
            RealmService realmService = AuthenticatorAdapterDataHolder.getInstance().getRealmService();
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            if (StringUtils.isNotBlank(userStoreDomain)) {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager()
                        .getSecondaryUserStoreManager(userStoreDomain);
            } else {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
            }
        } catch (UserStoreException e) {
            throw new ActionExecutionResponseProcessorException("An error occurs when trying to retrieve the " +
                    "userStore manager for the given userStore domain name:" +  userStoreDomain, e );
        }

        if (StringUtils.isNotBlank(userStoreDomain) && userStoreManager == null) {
            String errorMessage = "No userStore is found for the given userStore domain name: " + userStoreDomain;
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }

        return userStoreManager;
    }
}
