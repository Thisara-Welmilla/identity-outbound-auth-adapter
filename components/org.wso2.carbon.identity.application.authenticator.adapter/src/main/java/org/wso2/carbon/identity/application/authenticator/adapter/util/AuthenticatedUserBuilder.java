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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.LOCAL;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants.USERNAME_CLAIM;

/**
 * This is responsible for building the authenticated user object from the authenticated user data.
 */
public class AuthenticatedUserBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticatedUserBuilder.class);
    private AuthenticatedUser authenticatedUser;
    private final AuthenticatedUserData user;
    private final AuthenticationContext context;
    private final AuthenticatorAdapterConstants.UserType userType;
    private String username;
    
    public AuthenticatedUserBuilder(AuthenticatedUserData user, AuthenticationContext context) {

        this.user = user;
        this.context = context;
        userType = resolveIdpType();
    }

    public AuthenticatedUser buildAuthenticateduser()
            throws AuthenticationFailedException {

        if ((AuthenticatorAdapterConstants.UserType.LOCAL.equals(userType))) {
            return buildLocalAuthenticatedUser();
        }
        return buildFederatedAuthenticatedUser();
    }

    private AuthenticatedUser buildFederatedAuthenticatedUser() throws AuthenticationFailedException {

        authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                resolveUserId());
        authenticatedUser.setFederatedIdPName(context.getExternalIdP().getIdPName());
        authenticatedUser.setUserAttributes(resolveUserClaims());
        resolveUsernameForFederatedUser();
        return authenticatedUser;
    }

    private AuthenticatedUser buildLocalAuthenticatedUser() throws AuthenticationFailedException {

        /* As there must be an existing user in the system by the given data, first resolve the user, then build
         authenticated user from it.
         */
        String userId = resolveUserId();
        AuthenticatedUserData.UserStore userStore = resolveUserStoreForLocalUser();
        User localUser = resolveLocalUserFromUserStore(userId, userStore);

        authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userStore
                 + CarbonConstants.DOMAIN_SEPARATOR + localUser.getUsername());
        authenticatedUser.setUserAttributes(resolveUserClaims());
        resolveUsernameForLocalUser(localUser);
        return authenticatedUser;
    }

    private AuthenticatorAdapterConstants.UserType resolveIdpType() {

        return LOCAL.equals(context.getExternalIdP().getIdPName()) ?
                AuthenticatorAdapterConstants.UserType.LOCAL : AuthenticatorAdapterConstants.UserType.FEDERATED;
    }

    private String resolveUserId() throws AuthenticationFailedException {

        if (StringUtils.isNotBlank(user.getUser().getId())) {
            return user.getUser().getId();
        }
        throw new AuthenticationFailedException("User Id is not found in the authenticated user data.");
    }

    private AuthenticatedUserData.UserStore resolveUserStoreForLocalUser()
            throws AuthenticationFailedException {

        if (user.getUser().getUserStore() != null) {
            return user.getUser().getUserStore();
        }
        throw new AuthenticationFailedException("User store domain is not found in the authenticated " +
                "user data for the local user.");
    }

    private User resolveLocalUserFromUserStore(String userId, AuthenticatedUserData.UserStore userStore)
            throws AuthenticationFailedException {

        AbstractUserStoreManager userStoreManager = resolveUserStoreManager(userStore.getName());
        try {
            return userStoreManager.getUser(userId, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String message = "Error occurred when trying to resolve local user by user Id:" + user.getUser().getId();
            throw new AuthenticationFailedException(message, e);
        }
    }

    private Map<ClaimMapping, String> resolveUserClaims() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        for (AuthenticatedUserData.Claim claim : user.getUser().getClaims()) {
            userAttributes.put(buildClaimMapping(claim.getUri()), claim.getValue());
        }
        return userAttributes;
    }

    private void resolveUsernameForFederatedUser() throws AuthenticationFailedException {

        if (username == null) {
            throw new AuthenticationFailedException(
                    "Username is not found in the authenticated user data.");
        } else if (StringUtils.isBlank(username)) {
            throw new AuthenticationFailedException("Username is empty in the authenticated user data.");
        }
        authenticatedUser.setUserName(username);
    }

    private void resolveUsernameForLocalUser(User resolvedUser) throws AuthenticationFailedException {

        if (!resolvedUser.getUsername().equals(username)) {
            throw new AuthenticationFailedException("Username in the authenticated user data does not " +
                    "match with the resolved user's username.");
        }
        authenticatedUser.setUserName(username);
    }

    private AbstractUserStoreManager resolveUserStoreManager(String userStoreDomain)
            throws AuthenticationFailedException {

        if (AuthenticatorAdapterConstants.UserType.LOCAL.equals(userType) && user.getUser().getUserStore() == null) {
            throw new AuthenticationFailedException("User store domain is not found in the authenticated " +
                    "user data for the local user.");
        }
      
    private ClaimMapping buildClaimMapping(String claimUri) {
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
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
            throw new AuthenticationFailedException("An error occurs when trying to retrieve the " +
                    "userStore manager for the given userStore domain name:" +  userStoreDomain, e);
        }

        if (StringUtils.isNotBlank(userStoreDomain) && userStoreManager == null) {
            String errorMessage = "No userStore is found for the given userStore domain name: " + userStoreDomain;
            throw new AuthenticationFailedException(errorMessage);
        }

        return userStoreManager;
    }
}
