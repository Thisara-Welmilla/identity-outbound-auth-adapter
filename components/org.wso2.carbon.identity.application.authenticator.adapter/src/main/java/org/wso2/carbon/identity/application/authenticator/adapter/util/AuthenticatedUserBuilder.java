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
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
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
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants.EXTERNAL_ID_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants.USERNAME_CLAIM;

/**
 * This is responsible for building the authenticated user object from the authenticated user data.
 */
public class AuthenticatedUserBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticatedUserBuilder.class);
    private AuthenticatedUser authenticatedUser;
    private final AuthenticatedUserData userFromResponse;
    private final AuthenticationContext context;
    private final AuthenticatorAdapterConstants.UserType userType;
    private String usernameFromResponse;
    
    public AuthenticatedUserBuilder(AuthenticatedUserData user, AuthenticationContext context) {

        this.userFromResponse = user;
        this.context = context;
        userType = resolveIdpType();
    }

    /**
     * This method is responsible for building the authenticated user object from the authenticated user data.
     *
     * @return AuthenticatedUser object.
     * @throws ActionExecutionResponseProcessorException If any error occurred when building the authenticated
     * user object.
     */
    public AuthenticatedUser buildAuthenticateduser() throws ActionExecutionResponseProcessorException {

        if ((AuthenticatorAdapterConstants.UserType.LOCAL.equals(userType))) {
            return buildLocalAuthenticatedUserFromResponse();
        }
        return buildFederatedAuthenticatedUserFromResponse();
    }

    private AuthenticatedUser buildFederatedAuthenticatedUserFromResponse()
            throws ActionExecutionResponseProcessorException {

        String userId = resolveUserIdFromResponse();
        authenticatedUser = AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(userId);
        Map<ClaimMapping, String> attributeMap = resolveUserNameAndClaimsFromResponse();
        // Set the user ID to the external ID claim for federated authenticators.
        attributeMap.put(buildClaimMapping(EXTERNAL_ID_CLAIM), userId);
        authenticatedUser.setUserAttributes(attributeMap);
        resolveUsernameForFederatedUser();
        return authenticatedUser;
    }

    private AuthenticatedUser buildLocalAuthenticatedUserFromResponse()
            throws ActionExecutionResponseProcessorException {

        /* As there must be an existing user in the system by the given data, first resolve the user, then build
         authenticated user from it.
         */
        String userId = resolveUserIdFromResponse();
        AuthenticatedUserData.UserStore userStore = resolveUserStoreForLocalUser();
        User localUserFromUserStore = resolveLocalUserFromUserStore(userId, userStore);

        authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userStore
                 + CarbonConstants.DOMAIN_SEPARATOR + localUserFromUserStore.getUsername());
        authenticatedUser.setUserAttributes(resolveUserNameAndClaimsFromResponse());
        validateUsernameForLocalUser(localUserFromUserStore);
        return authenticatedUser;
    }

    private AuthenticatorAdapterConstants.UserType resolveIdpType() {

        return LOCAL.equals(context.getExternalIdP().getIdPName()) ?
                AuthenticatorAdapterConstants.UserType.LOCAL : AuthenticatorAdapterConstants.UserType.FEDERATED;
    }

    private String resolveUserIdFromResponse() throws ActionExecutionResponseProcessorException {

        if (StringUtils.isNotBlank(userFromResponse.getUser().getId())) {
            return userFromResponse.getUser().getId();
        }
        // Todo: Add diagnostic log for the error scenario.
        throw new ActionExecutionResponseProcessorException("The 'userId' field is missing in the authentication " +
                "extension response.");
    }

    private AuthenticatedUserData.UserStore resolveUserStoreForLocalUser()
            throws ActionExecutionResponseProcessorException {

        if (userFromResponse.getUser().getUserStore() != null) {
            return userFromResponse.getUser().getUserStore();
        }
        // Todo: Add diagnostic log for the error scenario.
        throw new ActionExecutionResponseProcessorException("The 'userStore' field is missing in the " +
                "authentication extension response. This field is required for local user authentication.");
    }

    private User resolveLocalUserFromUserStore(String userId, AuthenticatedUserData.UserStore userStore)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager = resolveUserStoreManager(userStore.getName());
        try {
            return userStoreManager.getUser(userId, null);
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            // Todo: Add diagnostic log for the error scenario.
            throw new ActionExecutionResponseProcessorException("An error occurred while resolving the local user " +
                    "from the userStore BY the provided userId", e);
        }
    }

    private Map<ClaimMapping, String> resolveUserNameAndClaimsFromResponse() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        for (AuthenticatedUserData.Claim claim : userFromResponse.getUser().getClaims()) {
            userAttributes.put(buildClaimMapping(claim.getUri()), claim.getValue());
            if (USERNAME_CLAIM.equals(claim.getUri())) {
                usernameFromResponse = claim.getValue();
            }
        }
        return userAttributes;
    }

    private void resolveUsernameForFederatedUser() {

        if (usernameFromResponse.isEmpty() && LOG.isDebugEnabled()) {
            LOG.debug("The username for the federated user is missing in the authentication response.");
        }
        authenticatedUser.setUserName(usernameFromResponse);
    }

    private void validateUsernameForLocalUser(User resolvedUser) throws ActionExecutionResponseProcessorException {

        if (!resolvedUser.getUsername().equals(usernameFromResponse)) {
            // Todo: Add diagnostic log for the error scenario.
            throw new ActionExecutionResponseProcessorException("The provided username for the local user in the " +
                    "authentication response does not match the resolved username from the user store.");
        }
    }

    private ClaimMapping buildClaimMapping(String claimUri) {

        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
    }

    private AbstractUserStoreManager resolveUserStoreManager(String userStoreDomain)
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
            throw new ActionExecutionResponseProcessorException(String.format("An error occurred while retrieving " +
                    "the userStore manager for the given userStore domain: %s.", userStoreDomain), e);
        }
        if (userStoreManager == null) {
            throw new ActionExecutionResponseProcessorException(String.format("No userStore is found for the given " +
                    "userStore domain name: %s.", userStoreDomain));
        }

        return userStoreManager;
    }
}
