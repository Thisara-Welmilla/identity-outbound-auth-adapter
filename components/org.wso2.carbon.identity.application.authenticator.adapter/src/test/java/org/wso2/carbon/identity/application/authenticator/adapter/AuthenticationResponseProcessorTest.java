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
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.IncompleteStatus;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.model.SuccessStatus;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestActionInvocationResponseBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestEventContextBuilder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

public class AuthenticationResponseProcessorTest {

    private FederatedAuthenticatorAdapter federatedAuthenticatorAdapter;
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private AuthenticationContext authContextForNoUser;
    private AuthenticationContext authContextForLocalUser;
    private AuthenticationContext authContextForFedUser;
    private AuthenticatedUser localUser;
    private AuthenticatedUser fedUser;
    private AuthenticatedUser expectedAuthenticatedUser;

    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private ActionExecutorService mockedActionExecutorService;

    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static ArrayList<AuthHistory> authHistory;

    private RealmService mockedRealmService;

    private AuthenticationResponseProcessor authenticationResponseProcessor;
    private Map<String, Object> eventContextForLocalUser;
    private ActionExecutionRequest authenticationRequest;

    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static final Map<String, String> headers = Map.of("header-1", "value-1", "header-2", "value-2");
    private static final Map<String, String> parameters = Map.of("param-1", "value-1", "param-2", "value-2");
    private static ArrayList<AuthHistory> authHistory;

    @BeforeClass
    public void setUp() throws Exception {

        authenticationResponseProcessor = new AuthenticationResponseProcessor();
        authHistory = TestEventContextBuilder.buildAuthHistory();

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        mockedRealmService = mock(RealmService.class);
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(mockedRealmService);

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        AuthenticatedUser localUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        eventContextForLocalUser = new TestEventContextBuilder().buildEventContext(
                localUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory);
        authenticationRequest = new AuthenticationRequestBuilder()
                .buildActionExecutionRequest(eventContextForLocalUser);

        authHistory = TestEventContextBuilder.buildAuthHistory();
        buildEventContext();

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        mockStatic(AuthenticatedUser.class);
        AuthenticatedUser mockUser = new AuthenticatedUser();
        mockUser.setUserId(TestAuthenticationAdapterConstants.AuthenticatingUserConstants.USERID);
        mockUser.setUserName(TestAuthenticationAdapterConstants.AuthenticatingUserConstants.USERNAME);
        when(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(mockUser);
        when(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(mockUser);

        mockedActionExecutorService = mock(ActionExecutorService.class);
        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(mockedActionExecutorService);

        expectedAuthenticatedUser = new AuthenticatedUser();
        expectedAuthenticatedUser.setUserId(TestAuthenticationAdapterConstants.AuthenticatingUserConstants.USERID);
        expectedAuthenticatedUser.setUserStoreDomain(TestAuthenticationAdapterConstants.AuthenticatingUserConstants.USER_STORE_NAME);
        expectedAuthenticatedUser.setUserName(TestAuthenticationAdapterConstants.AuthenticatingUserConstants.USERNAME);

    }


    @AfterClass
    public void tearDown() {

        identityTenantUtilMockedStatic.close();
    }

    public void buildEventContext() {

        IdentityProvider idp = new IdentityProvider();
        idp.setIdentityProviderName("testIdp");

        // Custom authenticator engaging in 1st step of authentication flow.
        authContextForNoUser = new TestEventContextBuilder().buildAuthenticationContext(
                null, SUPER_TENANT_DOMAIN_NAME, new ArrayList<AuthHistory>());
        authContextForNoUser.setExternalIdP(new ExternalIdPConfig(idp));

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        localUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        authContextForLocalUser = new TestEventContextBuilder().buildAuthenticationContext(
                localUser, SUPER_TENANT_DOMAIN_NAME, authHistory);
        authContextForLocalUser.setExternalIdP(new ExternalIdPConfig(idp));

        // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
        fedUser = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        authContextForFedUser = new TestEventContextBuilder().buildAuthenticationContext(
                fedUser, SUPER_TENANT_DOMAIN_NAME, authHistory);
        authContextForFedUser.setExternalIdP(new ExternalIdPConfig(idp));
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationResponseProcessor.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    @Test
    public void testProcessFailedResponse() throws Exception {

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
    public void testProcessErrorResponse() throws Exception {
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

    @DataProvider
    public Object[][] getAuthContexts() {

        return new Object[][] {
                {authContextForNoUser},
                {authContextForLocalUser},
                {authContextForFedUser},
        };
    }

    @Test(dataProvider = "getAuthContexts")
    public void testIncompleteAuthenticationRequestProcess(AuthenticationContext context) throws Exception {

        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new IncompleteStatus.Builder().responseContext(new HashMap<>()).build());
        AuthenticatorFlowStatus authStatus = federatedAuthenticatorAdapter.process(request, response, context);

        Assert.assertEquals(authStatus, AuthenticatorFlowStatus.INCOMPLETE);
    }

    @Test(dataProvider = "getAuthContexts")
    public void testFailureAuthenticationRequestProcess(AuthenticationContext context) throws Exception {

        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new FailedStatus(new Failure("failureResponse.getFailureReason()",
                        "failureResponse.getFailureDescription()")));
        //AuthenticatorFlowStatus authStatus = federatedAuthenticatorAdapter.process(request, response, context);

        //Assert.assertEquals(authStatus, AuthenticatorFlowStatus.FAIL_COMPLETED);
    }

    @DataProvider
    public Object[][] getSuccessValidResponsesForLocalUsers() {

        TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser authUser = new TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser();

        // Valid user data with userId, userStore and userName claim.
        ActionInvocationSuccessResponse authSuccessResponseWithAuthUser = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUser));

        // Valid user data with userId and without userStore, userName claim.
        TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser authUserNoUserStore = new TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser();
        authUserNoUserStore.setUserStore(null);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserStore = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserStore));

        return new Object[][] {
                {authContextForFedUser, authSuccessResponseWithAuthUser,
                        expectedAuthenticatedUser},
                {authContextForFedUser, authSuccessResponseWithoutUserStore,
                        expectedAuthenticatedUser}
        };
    }

    @Test(dataProvider = "getSuccessValidResponsesForLocalUsers")
    public void testProcessSuccessResponseWithValidResponsesForLocalUsers(AuthenticationContext context,
            ActionInvocationSuccessResponse successResponse, AuthenticatedUser expectedUser)
            throws Exception {

        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                null, SUPER_TENANT_DOMAIN_NAME, new HashMap<>(), new HashMap<>(), authHistory);
        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new SuccessStatus.Builder().setResponseContext(eventContext).build());
        context.setCurrentStep(2);
        context.setProperty(AuthenticatorAdapterConstants.AUTHENTICATED_USER_DATA, successResponse.getData());
        context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME,
                ActionExecutionStatus.Status.SUCCESS);

        AuthenticatorFlowStatus status = federatedAuthenticatorAdapter.process(request, response, context);

        Assert.assertEquals(status, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
        // Assert authenticated user set in the context.
        assertAuthenticationContext(context, expectedUser);
    }

    @DataProvider
    public Object[][] getSuccessInvalidResponsesForLocalUsers() {

        // Invalid user data without userId.
        TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser authUserNoUserId = new TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser();
        authUserNoUserId.setId(null);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserStore = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserId));

        // Invalid user data with userId, userStore and mismatching userName claim.
        TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser authUserMissMatchUserName = new TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser();
        ActionInvocationSuccessResponse authSuccessResponseWithMissMatchUserName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserMissMatchUserName));


        // Valid user data with userId, userStore and without userName claim.
        TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser authUserNoUserName = new TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser();
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserName));

        return new Object[][] {
                {authContextForLocalUser, authSuccessResponseWithoutUserStore},
                {authContextForLocalUser, authSuccessResponseWithMissMatchUserName}
        };
    }

    @Test(dataProvider = "getSuccessInvalidResponsesForLocalUsers")
    public void testProcessSuccessResponseWithInvalidResponsesForLocalUsers(
            Map<String, Object> eventContext,
            ActionInvocationSuccessResponse successResponse, TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser expectedUser)
            throws Exception {

        federatedAuthenticatorAdapter.process(request, response, authContextForFedUser);
    }

    private void assertAuthenticationContext(AuthenticationContext context,
                                             AuthenticatedUser expectedUser) throws UserIdNotFoundException {

        Assert.assertNotNull(context);
        AuthenticatedUser subject = context.getSubject();
        assertAuthenticatedUser(subject, expectedUser);
    }

    private void assertAuthenticatedUser(AuthenticatedUser authenticatedUser, AuthenticatedUser expectedUser)
            throws UserIdNotFoundException {

        Assert.assertNotNull(authenticatedUser);
        Assert.assertEquals(authenticatedUser.getUserId(), expectedUser.getUserId());
        Assert.assertEquals(authenticatedUser.getUserStoreDomain(), expectedUser.getUserStoreDomain());
        Assert.assertEquals(authenticatedUser.getUserName(), expectedUser.getUserName());
        Assert.assertEquals(authenticatedUser.isFederatedUser(), expectedUser.isFederatedUser());
        Assert.assertEquals(authenticatedUser.getFederatedIdPName(), expectedUser.getFederatedIdPName());
        Assert.assertEquals(authenticatedUser.getTenantDomain(), expectedUser.getTenantDomain());
        for (Map.Entry<ClaimMapping, String> claim : expectedUser.getUserAttributes().entrySet()) {
            Assert.assertEquals(authenticatedUser.getUserAttributes().get(claim.getKey()), claim.getValue());
        }
    }
}
