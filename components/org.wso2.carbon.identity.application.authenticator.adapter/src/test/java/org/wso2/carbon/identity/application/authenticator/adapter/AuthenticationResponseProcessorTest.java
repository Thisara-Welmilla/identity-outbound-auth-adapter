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

import com.fasterxml.jackson.core.JsonProcessingException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.model.Success;
import org.wso2.carbon.identity.action.execution.model.UserStore;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestActionInvocationResponseBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestEventContextBuilder;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.mock;
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
    private static final Map<String, String> headers = Map.of("header-1", "value-1", "header-2", "value-2");
    private static final Map<String, String> parameters = Map.of("param-1", "value-1", "param-2", "value-2");
    private static ArrayList<AuthHistory> authHistory;

    @Mock
    private RealmService realmService;

    @BeforeClass
    public void setUp() throws ActionExecutionRequestBuilderException {

        authenticationResponseProcessor = new AuthenticationResponseProcessor();
        authHistory = TestEventContextBuilder.buildAuthHistory();

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        realmService = mock(RealmService.class);
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(realmService);

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        AuthenticatedUser localUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        eventContextForLocalUser = new TestEventContextBuilder(
                localUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory)
                .getEventContext();
        authenticationRequest = new AuthenticationRequestBuilder()
                .buildActionExecutionRequest(eventContextForLocalUser);
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationResponseProcessor.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    @DataProvider
    public Object[][] getSuccessResponse() throws JsonProcessingException {

        ExternallyAuthenticatedUser authenticatedUser = new ExternallyAuthenticatedUser();
        authenticatedUser.setUserStore(new UserStore("PRIMARY"));
        ActionInvocationSuccessResponse authSuccessResponse = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(new ArrayList<>(), null);

        return new Object[][] {
                {eventContextForLocalUser, authenticationRequest, authSuccessResponse, authenticatedUser}
        };
    }

    //@Test(dataProvider = "getSuccessResponse")
    public void testProcessSuccessResponse(Map<String, Object> eventContext, ActionExecutionRequest authRequest,
            ActionInvocationSuccessResponse successResponse, ExternallyAuthenticatedUser expectedUser)
            throws ActionExecutionResponseProcessorException, UserIdNotFoundException {

        ActionExecutionStatus<Success> executionStatus = authenticationResponseProcessor.processSuccessResponse(
                eventContext, authRequest.getEvent(), successResponse);

        Assert.assertEquals(executionStatus.getStatus(), ActionExecutionStatus.Status.SUCCESS);
        assertAuthenticationContext(eventContext, expectedUser);
    }

    @DataProvider
    public Object[][] getSuccessStatusResponseForProcessorExceptions() throws JsonProcessingException {

        ExternallyAuthenticatedUser authenticatedUser = new ExternallyAuthenticatedUser();

        // Authenticator success response with no data.
        ActionInvocationSuccessResponse authResponseWithNoData =
                TestActionInvocationResponseBuilder.buildAuthenticationSuccessResponse(new ArrayList<>(), null);

        // Authenticator success response with operations.
        ActionInvocationSuccessResponse authResponseWithOperation =
                TestActionInvocationResponseBuilder.buildAuthenticationSuccessResponse(
                        new ArrayList<>(buildRedirectPerformableOperation("https://dummy-url")),
                        null);

        // Authenticator success response with no user id in user data
        authenticatedUser.setId(null);
        String dataWithNoUserId = authenticatedUser.covertJsonString();
        ActionInvocationSuccessResponse authResponseWithNoUserId = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(new ArrayList<>(), null);

        // Authenticator success response with invalid user claims in user data
        String dataWithInvalidClaims = new ExternallyAuthenticatedUser().covertJsonString()
                .replace("\"name\":\"claim-1\",", "");
        ActionInvocationSuccessResponse authResponseWithInvalidClaims = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(new ArrayList<>(), null);

        return new Object[][] {
                {eventContextForLocalUser, authenticationRequest, authResponseWithNoData, "The data field in the " +
                        "SUCCESS action invocation status must not be empty for the AUTHENTICATION action type."},
                {eventContextForLocalUser, authenticationRequest, authResponseWithOperation, "The list of performable" +
                        " operations must be empty for the SUCCESS action invocation status for the AUTHENTICATION " +
                        "action type."},
                {eventContextForLocalUser, authenticationRequest, authResponseWithNoUserId,
                        "User Id is not found in the authenticated user data."},
                {eventContextForLocalUser, authenticationRequest, authResponseWithInvalidClaims, "The provided data " +
                        "cannot be cast to an AuthenticatedUserData object:" + dataWithInvalidClaims}
        };
    }

    private void assertAuthenticationContext(Map<String, Object> eventContext,
                                             ExternallyAuthenticatedUser expectedUser) throws UserIdNotFoundException {

        Object context = eventContext.get(AuthenticatorAdapterConstants.AUTH_CONTEXT);
        Assert.assertNotNull(context);
        Assert.assertTrue(context instanceof AuthenticationContext);
        AuthenticationContext authContext = (AuthenticationContext) context;
        assertAuthenticatedUser(authContext.getLastAuthenticatedUser(), expectedUser);

        // assert other values are not changed.
    }

    private void assertAuthenticatedUser(AuthenticatedUser authenticatedUser, ExternallyAuthenticatedUser expectedUser)
            throws UserIdNotFoundException {

        Assert.assertNotNull(authenticatedUser);
        Assert.assertEquals(authenticatedUser.getUserId(), expectedUser.getId());
        for (AuthenticatedUserData.Claim claim : expectedUser.getClaims()) {
            //Assert.assertEquals(authenticatedUser.getUserAttributes().get(claim.getName()), claim.getValue());
        }
    }

    @Test
    public void testProcessFailedResponse()
            throws ActionExecutionResponseProcessorException {
        ActionInvocationFailureResponse failureResponse =
                TestActionInvocationResponseBuilder.buildActionInvocationFailureResponse();

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
        ActionInvocationErrorResponse errorResponse =
                TestActionInvocationResponseBuilder.buildActionInvocationErrorResponse();

        ActionExecutionStatus<Error> executionStatus = authenticationResponseProcessor.processErrorResponse(
                eventContextForLocalUser, authenticationRequest.getEvent(), errorResponse);

        Assert.assertEquals(executionStatus.getStatus(), ActionExecutionStatus.Status.ERROR);
        Assert.assertEquals(executionStatus.getResponse().getErrorMessage(), errorResponse.getErrorMessage());
        Assert.assertEquals(executionStatus.getResponse().getErrorDescription(), errorResponse.getErrorDescription());
    }

    public static List<PerformableOperation> buildRedirectPerformableOperation(String redirectUrl) {

        PerformableOperation operation = new PerformableOperation();
        operation.setOp(Operation.REDIRECT);
        operation.setUrl(redirectUrl);

        return new ArrayList<>(List.of(operation));
    }
}
