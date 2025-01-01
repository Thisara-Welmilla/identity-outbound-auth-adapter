/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.application.authenticator.adapter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.IdentityConstants;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * This class holds the external custom authentication.
 */
public abstract class AbstractAuthenticatorAdapter extends AbstractApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(AbstractAuthenticatorAdapter.class);
    protected String authenticatorName = AuthenticatorAdapterConstants.AUTHENTICATOR_NAME;
    protected String friendlyName = AuthenticatorAdapterConstants.AUTHENTICATOR_FRIENDLY_NAME;;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return false;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException {

        if (context.isLogoutRequest()){
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        Map<String, Object> eventContext = new HashMap<>();
        eventContext.put(AuthenticatorAdapterConstants.AUTH_REQUEST, request);
        eventContext.put(AuthenticatorAdapterConstants.AUTH_CONTEXT, context);

        ActionExecutionStatus executionStatus = executeAction(context, eventContext, context.getTenantDomain());

        return resolveAuthenticatorFlowStatus(executionStatus);
    }

    private AuthenticatorFlowStatus resolveAuthenticatorFlowStatus(ActionExecutionStatus executionStatus) {

        if (executionStatus.getStatus() == ActionExecutionStatus.Status.SUCCESS) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (executionStatus.getStatus() == ActionExecutionStatus.Status.INCOMPLETE) {
            return AuthenticatorFlowStatus.INCOMPLETE;
        }
        return AuthenticatorFlowStatus.FAIL_COMPLETED;
    }

    private ActionExecutionStatus executeAction(AuthenticationContext context, Map<String, Object> eventContext,
                                                String tenantDomain) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String actionId = authenticatorProperties.get(AuthenticatorAdapterConstants.ACTION_ID_CONFIG);

        try {
            ActionExecutionStatus executionStatus =
                    AuthenticatorAdapterDataHolder.getInstance().getActionExecutorService()
                            .execute(ActionType.AUTHENTICATION, eventContext, tenantDomain);
            if (log.isDebugEnabled()) {
                log.debug(String.format(
                        "Invoked authentication action for Authentication flow ID: %s. Status: %s",
                        eventContext.get(AuthenticatorAdapterConstants.FLOW_ID),
                        Optional.ofNullable(executionStatus).isPresent() ? executionStatus.getStatus() : "NA"));
            }
            return executionStatus;
        } catch (ActionExecutionException e) {
            throw new AuthenticationFailedException("Error while executing authentication action", e);
        }
    }

    @Override
    public String getFriendlyName() {

        return friendlyName;
    }

    @Override
    public String getName() {

        return authenticatorName;
    }

    @Override
    public String getClaimDialectURI() {

        return AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT ;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        // Reference to corresponding Action.
        Property actionId = new Property();
        actionId.setName(AuthenticatorAdapterConstants.ACTION_ID_CONFIG);
        actionId.setDisplayName("Action Id");
        actionId.setRequired(true);
        actionId.setDescription("Enter action reference here.");
        actionId.setType("Action");
        actionId.setDisplayOrder(1);
        configProperties.add(actionId);

        // User type.
        Property authUserType = new Property();
        authUserType.setName(AuthenticatorAdapterConstants.AUTH_USER_TYPE);
        authUserType.setDisplayName("Authenticating user type");
        authUserType.setRequired(true);
        authUserType.setDescription("Enter the whether authenticating user is being maintained; LOCAL, FEDERATED.");
        authUserType.setType("String");
        // Add regex validation.
        authUserType.setDisplayOrder(1);
        configProperties.add(authUserType);

        return configProperties;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        throw new UnsupportedOperationException();
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        throw new UnsupportedOperationException();
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        String state = request.getParameter("state");
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    @Override
    public String getI18nKey() {

        return AuthenticatorAdapterConstants.AUTHENTICATOR_NAME;
    }
}
