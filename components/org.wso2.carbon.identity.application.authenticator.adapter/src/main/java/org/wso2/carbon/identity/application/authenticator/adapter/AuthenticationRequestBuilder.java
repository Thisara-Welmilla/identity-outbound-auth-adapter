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
import org.wso2.carbon.identity.action.execution.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.model.*;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AllowedOperationBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationRequestEvent.AuthenticatedStep;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatingUser;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

/**
 * This is a builder class which is responsible for building authentication request payload which will be sent to the
 * external authentication service.
 */
public class AuthenticationRequestBuilder implements ActionExecutionRequestBuilder {

    private static final Log LOG = LogFactory.getLog(AuthenticationRequestBuilder.class);

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public ActionExecutionRequest buildActionExecutionRequest(Map<String, Object> eventContext)
            throws ActionExecutionRequestBuilderException {

        HttpServletRequest request = (HttpServletRequest) eventContext.get(AuthenticatorAdapterConstants.AUTH_REQUEST);
        AuthenticationContext context = (AuthenticationContext) eventContext.get(
                AuthenticatorAdapterConstants.AUTH_CONTEXT);

        ActionExecutionRequest.Builder actionRequestBuilder = new ActionExecutionRequest.Builder();
        actionRequestBuilder.flowId((String) eventContext.get(AuthenticatorAdapterConstants.FLOW_ID));
        actionRequestBuilder.actionType(getSupportedActionType());
        actionRequestBuilder.event(getEvent(request, context));
        AllowedOperationBuilder allowedOperationBuilder = new AllowedOperationBuilder();
        actionRequestBuilder.allowedOperations(allowedOperationBuilder.getAllowedOperations());

        return actionRequestBuilder.build();
    }

    private Event getEvent(HttpServletRequest request, AuthenticationContext context)
            throws ActionExecutionRequestBuilderException {

        AuthenticatedUser lastAuthenticatedUser = context.getLastAuthenticatedUser();
        String tenantDomain = context.getTenantDomain();

        AuthenticationRequestEvent.Builder eventBuilder = new AuthenticationRequestEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(IdentityTenantUtil.getTenantId(tenantDomain)), tenantDomain));
        if (lastAuthenticatedUser != null) {
            eventBuilder.user(getUserForEventBuilder(lastAuthenticatedUser));
            eventBuilder.organization(getOrganizationForEventBuilder(lastAuthenticatedUser));
            eventBuilder.userStore(new UserStore(lastAuthenticatedUser.getUserStoreDomain()));
        }
        eventBuilder.application(new Application(context.getServiceProviderResourceId(),
                context.getServiceProviderName()));
        eventBuilder.currentStepIndex(context.getCurrentStep());
        eventBuilder.authenticatedSteps(getAuthenticatedStepsForEventBuilder(context));
        eventBuilder.request(getRequest(request));
        return eventBuilder.build();
    }

    private User getUserForEventBuilder(AuthenticatedUser authenticatedUser)
            throws ActionExecutionRequestBuilderException {

        try {
            return new AuthenticatingUser(authenticatedUser.getUserId(), authenticatedUser);
        } catch (UserIdNotFoundException e) {
            throw new ActionExecutionRequestBuilderException("User ID not found for current authenticated user.", e);
        }
    }

    private Organization getOrganizationForEventBuilder(AuthenticatedUser authenticatedUser) throws ActionExecutionRequestBuilderException {

        String organizationId = authenticatedUser.getUserResidentOrganization();
        try {
            if (organizationId != null && !organizationId.isEmpty()) {
                String organizationName = AuthenticatorAdapterDataHolder.getInstance().getOrganizationManager()
                        .getOrganizationNameById(authenticatedUser.getUserResidentOrganization());
                return new Organization(authenticatedUser.getUserResidentOrganization(), organizationName);
            }
        } catch (OrganizationManagementException e) {
            LOG.debug("Error occurred while retrieving organization name of the authorized user: " + organizationId, e);
            return null;
        }

        LOG.debug("The organization id is not set for the authorized user with username: "
                + authenticatedUser.getUserName());
        return null;
    }

    private AuthenticatedStep[] getAuthenticatedStepsForEventBuilder(AuthenticationContext context) {

        ArrayList<AuthenticatedStep> authenticatedSteps = new ArrayList<>();
        int stepIndex = 1;
        for (AuthHistory step: context.getAuthenticationStepHistory()) {
            authenticatedSteps.add(new AuthenticatedStep(stepIndex, step));
            stepIndex += 1;
        }

        return authenticatedSteps.toArray(new AuthenticatedStep[0]);
    }

    private Request getRequest(HttpServletRequest request) {

        List<Header> additionalHeaders = new ArrayList<>();
        List<Param> additionalParams = new ArrayList<>();

        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String headerElement = headers.nextElement();
            Header header = new Header(headerElement, new String[]{request.getHeader(headerElement)});
            additionalHeaders.add(header);
        }

        Enumeration<String> requestParameters = request.getParameterNames();
        while (requestParameters.hasMoreElements()) {
            String paramElement = requestParameters.nextElement();
            Param param = new Param(paramElement, new String[]{request.getParameter(paramElement)});
            additionalParams.add(param);
        }

        return new AuthenticationRequest(additionalHeaders,additionalParams);
    }
}
