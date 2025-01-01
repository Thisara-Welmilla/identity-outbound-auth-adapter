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

import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.*;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.EventContextBuilder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

import java.util.ArrayList;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

@WithCarbonHome
public class AuthenticationResponseProcessorTest {

    private AuthenticationResponseProcessor authenticationResponseProcessor;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private Map<String, Object> eventContextForLocalUser;
    private ActionExecutionRequest authenticationRequest;

    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static final String FLOW_ID = "flow-id";
    Map<String, String> headers = Map.of("header-1", "value-1", "header-2", "value-2");
    Map<String, String> parameters = Map.of("param-1", "value-1", "param-2", "value-2");
    ArrayList<AuthHistory> authHistory;

    @BeforeClass
    public void setUp() throws ActionExecutionRequestBuilderException {

        authenticationResponseProcessor = new AuthenticationResponseProcessor();
        authHistory = EventContextBuilder.buildAuthHistory();

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        AuthenticatedUser localUser = AuthenticatedTestUserBuilder.createAuthenticatedUser(
                AuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        eventContextForLocalUser = new EventContextBuilder(
                FLOW_ID, localUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory)
                .getEventContext();

        authenticationRequest = new AuthenticationRequestBuilder().buildActionExecutionRequest(eventContextForLocalUser);
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationResponseProcessor.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    @Test
    public void testProcessFailedResponse()
            throws ActionExecutionResponseProcessorException {
        ActionInvocationFailureResponse failureResponse = new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason("failure-1")
                .failureDescription("failure description").build();

        ActionExecutionStatus<Failure> executionStatus = authenticationResponseProcessor.processFailureResponse(
                eventContextForLocalUser, authenticationRequest.getEvent(), failureResponse);

        Assert.assertEquals(executionStatus.getStatus(), ActionExecutionStatus.Status.FAILED);
        Assert.assertEquals(executionStatus.getResponse().getFailureReason(), failureResponse.getFailureReason());
        Assert.assertEquals(
                executionStatus.getResponse().getFailureDescription(), failureResponse.getFailureDescription());
    }

    @Test
    public void testProcessErrorResponse()
            throws ActionExecutionResponseProcessorException {
        ActionInvocationErrorResponse errorResponse = new ActionInvocationErrorResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.ERROR)
                .errorMessage("error-1")
                .errorDescription("error description").build();

        ActionExecutionStatus<Error> executionStatus = authenticationResponseProcessor.processErrorResponse(
                eventContextForLocalUser, authenticationRequest.getEvent(), errorResponse);

        Assert.assertEquals(executionStatus.getStatus(), ActionExecutionStatus.Status.ERROR);
        Assert.assertEquals(executionStatus.getResponse().getErrorMessage(), errorResponse.getErrorMessage());
        Assert.assertEquals(executionStatus.getResponse().getErrorDescription(), errorResponse.getErrorDescription());
    }
}
