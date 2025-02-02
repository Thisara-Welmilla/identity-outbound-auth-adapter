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
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.base.AuthenticatorPropertyConstants;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class holds the external custom authentication.
 */
public abstract class AbstractAuthenticatorAdapter extends AbstractApplicationAuthenticator {

    private static final Log LOG = LogFactory.getLog(AbstractAuthenticatorAdapter.class);
    protected String authenticatorName;
    protected String friendlyName;

    @Override
    public boolean canHandle(HttpServletRequest request) {

        return true;
    }

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        }

        /* TODO: Catch AuthenticationFailedException error and continue with super.process, and handle error at
            processAuthenticationResponse method. */
        context.removeProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME);
        Map<String, Object> eventContext = new HashMap<>();
        eventContext.put(AuthenticatorAdapterConstants.AUTH_REQUEST, request);
        eventContext.put(AuthenticatorAdapterConstants.AUTH_RESPONSE, response);
        eventContext.put(AuthenticatorAdapterConstants.AUTH_CONTEXT, context);
        ActionExecutionStatus executionStatus = executeAction(context, eventContext, context.getTenantDomain());
        context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME, executionStatus);

        if (executionStatus.getStatus() == ActionExecutionStatus.Status.INCOMPLETE) {
            context.setCurrentAuthenticator(getName());
            context.setRetrying(false);
            return AuthenticatorFlowStatus.INCOMPLETE;
        }

        return super.process(request, response, context);
    }

    private ActionExecutionStatus executeAction(AuthenticationContext context, Map<String, Object> eventContext,
                                                String tenantDomain) throws AuthenticationFailedException {

        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String actionId = authenticatorProperties.get(AuthenticatorAdapterConstants.ACTION_ID_CONFIG);

        try {
            ActionExecutionStatus executionStatus =
                    AuthenticatorAdapterDataHolder.getInstance().getActionExecutorService()
                            .execute(ActionType.AUTHENTICATION, actionId, eventContext, tenantDomain);
            if (LOG.isDebugEnabled()) {
                LOG.debug(String.format(
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

        return AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT;
    }

    @Override
    public List<Property> getConfigurationProperties() {

        return new ArrayList<>();
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        throw new UnsupportedOperationException();
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        ActionExecutionStatus executionStatus = (ActionExecutionStatus)
                context.getProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME);
        if (executionStatus.getStatus() == ActionExecutionStatus.Status.FAILED ||
                executionStatus.getStatus() == ActionExecutionStatus.Status.ERROR) {
            /* TODO: Improve AuthenticationFailedException error messages and description with specific error content
                from the authentication action execution. */
            throw new AuthenticationFailedException("An error occurred while authenticating with user the " +
                    " external authentication authentication service.");
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {

        return request.getParameter("flowId");
    }

    @Override
    public String getI18nKey() {

        return AuthenticatorAdapterConstants.AUTHENTICATOR_NAME;
    }

    @Override
    protected boolean retryAuthenticationEnabled() {

        /* The external server must handle the retry at authentication failure and after authentication with external
         service completed call back to the IS. */
        return false;
    }

    @Override
    public AuthenticatorPropertyConstants.DefinedByType getDefinedByType() {

        return AuthenticatorPropertyConstants.DefinedByType.USER;
    }
}
