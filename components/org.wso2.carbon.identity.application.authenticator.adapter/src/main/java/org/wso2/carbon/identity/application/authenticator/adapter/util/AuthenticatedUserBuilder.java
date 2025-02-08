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
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationActionExecutionResult;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationActionExecutionResult.Availability;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationActionExecutionResult.Validity;
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
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants.GROUP_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants.USERNAME_CLAIM;
import static org.wso2.carbon.user.core.UserCoreConstants.DOMAIN_SEPARATOR;

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
        resolveGroupsForFederatedUser(attributeMap);
        authenticatedUser.setUserAttributes(attributeMap);
        setUsernameForFederatedUser();
        authenticatedUser.setTenantDomain(context.getTenantDomain());
        authenticatedUser.setFederatedUser(true);
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

        authenticatedUser = AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(
                localUserFromUserStore.getUserStoreDomain() + DOMAIN_SEPARATOR + localUserFromUserStore.getUsername());
        authenticatedUser.setUserAttributes(resolveUserNameAndClaimsFromResponse());

        Map<ClaimMapping, String> attributeMap = resolveUserNameAndClaimsFromResponse();
        resolveUsernameForLocalUser(localUserFromUserStore);
        attributeMap.put(buildClaimMapping(USERNAME_CLAIM), localUserFromUserStore.getUsername());
        authenticatedUser.setUserAttributes(attributeMap);
        authenticatedUser.setTenantDomain(context.getTenantDomain());
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
        String errorMessage = "The userId field is missing in the authentication action response.";
        DiagnosticLogger.logSuccessResponseDataValidationError(new AuthenticationActionExecutionResult("userId",
                Availability.UNAVAILABLE, Validity.INVALID, errorMessage));
        throw new ActionExecutionResponseProcessorException(errorMessage);
    }

    private AuthenticatedUserData.UserStore resolveUserStoreForLocalUser() {

        if (userFromResponse.getUser().getUserStore() != null) {
            return userFromResponse.getUser().getUserStore();
        }
        DiagnosticLogger.logSuccessResponseWithDefaultsForMissingData(
                new AuthenticationActionExecutionResult("userStore",
                Availability.UNAVAILABLE, Validity.VALID, "The userStore field is missing in the " +
                "authentication action response, hence the default userStore domain is applied."));
        return null;
    }

    private User resolveLocalUserFromUserStore(String userId, AuthenticatedUserData.UserStore userStore)
            throws ActionExecutionResponseProcessorException {

        User userFromUserStore;
        AbstractUserStoreManager userStoreManager = resolveUserStoreManager(userStore);
        try {
            userFromUserStore = userStoreManager.getUser(userId, null);
            if (userFromUserStore != null && StringUtils.isNotBlank(userFromUserStore.getUsername()) &&
                    userStoreManager.isExistingUser(userFromUserStore.getUsername())) {
                return userFromUserStore;
            }
        } catch (org.wso2.carbon.user.core.UserStoreException e) {
            String errorMessage = "An error occurred while resolving the user from the userStore by the " +
                    "provided userId: " + userId;
            DiagnosticLogger.logSuccessResponseDataValidationError(new AuthenticationActionExecutionResult("userId",
                    Availability.AVAILABLE, Validity.INVALID, errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage, e);
        }
        String errorMessage = "No user is found for the given userId: " + userId;
        DiagnosticLogger.logSuccessResponseDataValidationError(new AuthenticationActionExecutionResult("userId",
                Availability.AVAILABLE, Validity.INVALID, errorMessage));
        throw new ActionExecutionResponseProcessorException(errorMessage);
    }

    private Map<ClaimMapping, String> resolveUserNameAndClaimsFromResponse() {

        Map<ClaimMapping, String> userAttributes = new HashMap<>();
        for (AuthenticatedUserData.Claim claim : userFromResponse.getUser().getClaims()) {
            if (GROUP_CLAIM.equals(claim.getUri())) {
                continue;
            }
            userAttributes.put(buildClaimMapping(claim.getUri()), claim.getValue());
            if (USERNAME_CLAIM.equals(claim.getUri())) {
                usernameFromResponse = claim.getValue();
            }
        }
        return userAttributes;
    }

    private void resolveGroupsForFederatedUser(Map<ClaimMapping, String> claimMappings) {

        if (userFromResponse.getUser().getGroups() != null) {
            claimMappings.put(buildClaimMapping(GROUP_CLAIM), String.join(",", userFromResponse.getUser().getGroups()));
        }
    }

    private void setUsernameForFederatedUser() {

        if (StringUtils.isBlank(usernameFromResponse) && LOG.isDebugEnabled()) {
            LOG.debug("The username for the federated user is missing in the authentication response.");
        }
        authenticatedUser.setUserName(usernameFromResponse);
    }

    private void resolveUsernameForLocalUser(User resolvedUser) throws ActionExecutionResponseProcessorException {

        if (usernameFromResponse != null && !resolvedUser.getUsername().equals(usernameFromResponse)) {
            String errorMessage = "The provided username for the user in the authentication response does " +
                    "not match the resolved username from the userStore.";
            DiagnosticLogger.logSuccessResponseDataValidationError(
                    new AuthenticationActionExecutionResult("claims/" + USERNAME_CLAIM,
                    Availability.AVAILABLE, Validity.INVALID, errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }
        DiagnosticLogger.logSuccessResponseWithDefaultsForMissingData(
                new AuthenticationActionExecutionResult("userStore",
                Availability.UNAVAILABLE, Validity.VALID, "The username claim is not provided in the " +
                "authentication action response, hence setting username resolved from the userStore."));
        authenticatedUser.setUserName(resolvedUser.getUsername());
    }

    private ClaimMapping buildClaimMapping(String claimUri) {

        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
    }

    private AbstractUserStoreManager resolveUserStoreManager(AuthenticatedUserData.UserStore userStore)
            throws ActionExecutionResponseProcessorException {

        AbstractUserStoreManager userStoreManager;
        try {
            RealmService realmService = AuthenticatorAdapterDataHolder.getInstance().getRealmService();
            int tenantId = IdentityTenantUtil.getTenantId(context.getTenantDomain());
            UserRealm userRealm = (UserRealm) realmService.getTenantUserRealm(tenantId);
            if (userStore != null && StringUtils.isNotBlank(userStore.getName())) {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager()
                        .getSecondaryUserStoreManager(userStore.getName());
            } else {
                userStoreManager = (AbstractUserStoreManager) userRealm.getUserStoreManager();
            }
        } catch (UserStoreException e) {
            if (userStore != null && StringUtils.isNotBlank(userStore.getName())) {
                String errorMessage = "An error occurred while retrieving the userStore manager for the given " +
                        "userStore domain: " + userStore.getName();
                DiagnosticLogger.logSuccessResponseDataValidationError(
                        new AuthenticationActionExecutionResult("userStore",
                        Availability.AVAILABLE, Validity.INVALID, errorMessage));
                throw new ActionExecutionResponseProcessorException(errorMessage, e);
            }
            throw new ActionExecutionResponseProcessorException("An error occurred while fetching the userStore " +
                    "manager for the default userStore domain.", e);
        }
        if (userStoreManager == null) {
            String errorMessage = "No userStore is found for the given userStore domain name: " +
                    userStore.getName();
            DiagnosticLogger.logSuccessResponseDataValidationError(new AuthenticationActionExecutionResult("userStore",
                    Availability.AVAILABLE, Validity.INVALID, errorMessage));
            throw new ActionExecutionResponseProcessorException(errorMessage);
        }

        return userStoreManager;
    }
}
