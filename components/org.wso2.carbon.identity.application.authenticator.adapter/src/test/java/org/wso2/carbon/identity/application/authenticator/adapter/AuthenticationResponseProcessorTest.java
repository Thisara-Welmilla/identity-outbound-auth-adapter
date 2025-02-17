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
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationIncompleteResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.Incomplete;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.model.Success;
import org.wso2.carbon.identity.action.execution.model.SuccessStatus;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticationResponseProcessor;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.component.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.constant.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.model.AuthenticatedUserData;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestActionInvocationResponseBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticationAdapterConstants.AuthenticatingUserConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestEventContextBuilder;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.base.AuthenticatorPropertyConstants.AuthenticationType;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

public class AuthenticationResponseProcessorTest {

    private final HttpServletRequest request = spy(HttpServletRequest.class);
    private HttpServletResponse response = spy(HttpServletResponse.class);
    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static ArrayList<AuthHistory> authHistory;
    private static IdentityProvider fedIdp;
    private static IdentityProvider localIdp;
    private static PerformableOperation redirectOperation;
    private static final String NON_EXISTING_USERID = "non-existing-user-id";
    private static final List<String> groups = new ArrayList<>();

    private AuthenticationContext authContextWithNoUser;
    private AuthenticationContext authContextWithLocalUserFromFirstStep;
    private AuthenticationContext authContextWithFedUserFromFirstStep;
    private AuthenticatedUser localUserFromFirstStep;
    private AuthenticatedUser fedUserFromFirstStep;
    private User userFromUserStore;
    private AuthenticatedUser expectedLocalAuthenticatedUser;
    private AuthenticatedUser expectedFedAuthenticatedUser;

    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private ActionExecutorService mockedActionExecutorService;
    private RealmService mockedRealmService;
    private UserRealm mockedUserRealm;
    private AbstractUserStoreManager abstractUserStoreManager;
    private UserStoreManager mockedUserStoreManager;
    private AuthenticationResponseProcessor authenticationResponseProcessor;
    private MockedStatic<LoggerUtils> loggerUtils;
    private MockedStatic<FrameworkUtils> frameworkUtils;

    @BeforeClass
    public void setUp() throws Exception {

        authenticationResponseProcessor = new AuthenticationResponseProcessor();

        buildEventContexts();
        buildPerformableOperation();
        createExpectedAuthenticatedUsers();
        mockServices();
    }

    @AfterClass
    public void tearDown() {

        identityTenantUtilMockedStatic.close();
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationResponseProcessor.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    @DataProvider
    public Object[][] getEventContext() {

        return new Object[][] {
                {authContextWithNoUser, AuthenticationType.IDENTIFICATION},
                {authContextWithLocalUserFromFirstStep, AuthenticationType.IDENTIFICATION},
                {authContextWithLocalUserFromFirstStep, AuthenticationType.VERIFICATION},
                {authContextWithFedUserFromFirstStep, AuthenticationType.IDENTIFICATION},
                {authContextWithFedUserFromFirstStep, AuthenticationType.VERIFICATION},
        };
    }

    @Test(dataProvider = "getEventContext")
    public void testFailureAuthenticationRequestProcess(AuthenticationContext context,
                                                        AuthenticationType authType) throws Exception {

        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, authType);
        ActionInvocationFailureResponse failureResponse =
                TestActionInvocationResponseBuilder.buildActionInvocationFailureResponse();

        ActionExecutionStatus<Failure> executionStatus = authenticationResponseProcessor.processFailureResponse(
                eventContext, null, failureResponse);

        Assert.assertEquals(executionStatus.getStatus(), ActionExecutionStatus.Status.FAILED);
        Assert.assertEquals
                (context.getProperty(FrameworkConstants.AUTH_ERROR_CODE), failureResponse.getFailureReason());
        Assert.assertEquals(
                context.getProperty(FrameworkConstants.AUTH_ERROR_MSG), failureResponse.getFailureDescription());

        context.removeProperty(FrameworkConstants.AUTH_ERROR_CODE);
        context.removeProperty(FrameworkConstants.AUTH_ERROR_MSG);
    }

    @Test(dataProvider = "getEventContext")
    public void testProcessErrorResponse(AuthenticationContext context,
                                         AuthenticationType authType) throws Exception {

        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, authType);
        ActionInvocationErrorResponse errorResponse =
                TestActionInvocationResponseBuilder.buildActionInvocationErrorResponse();

        ActionExecutionStatus<Error> executionStatus = authenticationResponseProcessor.processErrorResponse(
                eventContext, null, errorResponse);

        Assert.assertEquals(executionStatus.getStatus(), ActionExecutionStatus.Status.ERROR);
        Assert.assertNull(context.getProperty(FrameworkConstants.AUTH_ERROR_CODE));
        Assert.assertNull(context.getProperty(FrameworkConstants.AUTH_ERROR_MSG));

        context.removeProperty(FrameworkConstants.AUTH_ERROR_CODE);
        context.removeProperty(FrameworkConstants.AUTH_ERROR_MSG);
    }

    @Test(dataProvider = "getEventContext")
    public void testIncompleteAuthenticationRequestProcess(AuthenticationContext context,
                                                           AuthenticationType authType) throws Exception {

        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, authType);
        ActionInvocationIncompleteResponse incompleteResponse =
                TestActionInvocationResponseBuilder.buildAuthenticationRedirectResponse(
                        new ArrayList<>(List.of(redirectOperation)));

        ActionExecutionStatus<Incomplete> status = authenticationResponseProcessor.processIncompleteResponse(
                eventContext, null, incompleteResponse);

        Assert.assertEquals(status.getStatus(), ActionExecutionStatus.Status.INCOMPLETE);
        verify(response).sendRedirect(redirectOperation.getUrl());

        response = spy(HttpServletResponse.class);
    }

    @DataProvider
    public Object[][] getSuccessValidResponsesForLocalUsers() {

        ExternallyAuthenticatedUser authUser = new ExternallyAuthenticatedUser();
        authUser.setGroups(groups);

        // Valid user data with userId, userStore and userName claim.
        ActionInvocationSuccessResponse authSuccessResponseWithAuthUser = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUser));

        // Valid user data with userId, userStore and without userName claim.
        ExternallyAuthenticatedUser authUserNoUserName =
                new ExternallyAuthenticatedUser();
        authUserNoUserName.getClaims().removeIf(
                claim -> AuthenticatorAdapterConstants.USERNAME_CLAIM.equals(claim.getUri()));
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserName));

        // Valid user data with userId, userStore and without userName claim.
        ExternallyAuthenticatedUser authUserNoUserStore = new ExternallyAuthenticatedUser();
        authUserNoUserStore.setUserStore(null);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserStore = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserStore));

        ActionInvocationSuccessResponse authSuccessResponseWithNoUser = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(), null);

        return new Object[][] {
                {authContextWithNoUser, authSuccessResponseWithAuthUser, AuthenticationType.IDENTIFICATION},
                {authContextWithNoUser, authSuccessResponseWithAuthUser, AuthenticationType.VERIFICATION},
                {authContextWithNoUser, authSuccessResponseWithoutUserName, AuthenticationType.IDENTIFICATION},
                {authContextWithNoUser, authSuccessResponseWithoutUserName, AuthenticationType.VERIFICATION},
                {authContextWithNoUser, authSuccessResponseWithoutUserStore, AuthenticationType.IDENTIFICATION},
                {authContextWithNoUser, authSuccessResponseWithoutUserStore, AuthenticationType.VERIFICATION},
                {authContextWithNoUser, authSuccessResponseWithNoUser, AuthenticationType.VERIFICATION},

                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithAuthUser,
                        AuthenticationType.IDENTIFICATION},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithAuthUser,
                        AuthenticationType.VERIFICATION},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserName,
                        AuthenticationType.IDENTIFICATION},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserName,
                        AuthenticationType.VERIFICATION},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserStore,
                        AuthenticationType.IDENTIFICATION},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserStore,
                        AuthenticationType.VERIFICATION},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithNoUser, AuthenticationType.VERIFICATION},

                {authContextWithFedUserFromFirstStep, authSuccessResponseWithAuthUser,
                        AuthenticationType.IDENTIFICATION},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithAuthUser,
                        AuthenticationType.VERIFICATION},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithoutUserName,
                        AuthenticationType.IDENTIFICATION},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithoutUserName,
                        AuthenticationType.VERIFICATION},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithoutUserStore,
                        AuthenticationType.IDENTIFICATION},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithoutUserStore,
                        AuthenticationType.VERIFICATION},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithNoUser, AuthenticationType.VERIFICATION},
        };
    }

    @Test(dataProvider = "getSuccessValidResponsesForLocalUsers")
    public void testProcessSuccessResponseWithValidResponsesForLocalUsers(AuthenticationContext context,
            ActionInvocationSuccessResponse actionInvocationSuccessResponse, AuthenticationType authType)
            throws Exception {

        if (actionInvocationSuccessResponse.getData() != null) {
            mockUserStoreManager(
                    ((AuthenticatedUserData) actionInvocationSuccessResponse.getData()).getUser().getUserStore());
        }
        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, authType);
        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new SuccessStatus.Builder().setResponseContext(eventContext).build());
        context.setCurrentStep(2);
        context.setExternalIdP(new ExternalIdPConfig(localIdp));
        context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME,
                ActionExecutionStatus.Status.SUCCESS);

        ActionExecutionStatus<Success> status = authenticationResponseProcessor.processSuccessResponse(
                eventContext, null, actionInvocationSuccessResponse);

        Assert.assertEquals(status.getStatus(), ActionExecutionStatus.Status.SUCCESS);
        assertAuthenticationContext(context, expectedLocalAuthenticatedUser);
    }

    @DataProvider
    public Object[][] getSuccessInvalidResponsesForLocalUsers() {

        // No user data without userId.
        ExternallyAuthenticatedUser authUserNoUserId = new ExternallyAuthenticatedUser();
        authUserNoUserId.setId(null);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserId = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserId));
        String errorMessageForMissingUserId = "The userId field is missing in the authentication action response.";

        // Invalid user data without userId.
        ExternallyAuthenticatedUser authUserNonExistingUserId = new ExternallyAuthenticatedUser();
        authUserNonExistingUserId.setId(NON_EXISTING_USERID);
        ActionInvocationSuccessResponse authSuccessResponseWithNonExistingUserId = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNonExistingUserId));
        String errorMessageForNonExistingUserId = "No user is found for the given userId: non-existing-user-id";

        // Invalid user data with userId, userStore and mismatching userName claim.
        ExternallyAuthenticatedUser authUserMissMatchUserName = new ExternallyAuthenticatedUser();
        authUserMissMatchUserName.setUserName("mismatchingUserName");
        ActionInvocationSuccessResponse authSuccessResponseWithMissMatchUserName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserMissMatchUserName));
        String errorMessageForMissingMissMatchUserName = "The provided username for the user in the " +
                "authentication response does not match the resolved username from the userStore.";

        ActionInvocationSuccessResponse authSuccessResponseWithNoUser = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(), null);
        String errorMessageForNoUserDate = "The user field is missing in the authentication action " +
                "response. This field is required for IDENTIFICATION authentication.";

        return new Object[][] {
                {authContextWithNoUser, authSuccessResponseWithoutUserId,
                        errorMessageForMissingUserId},
                {authContextWithNoUser, authSuccessResponseWithMissMatchUserName,
                        errorMessageForMissingMissMatchUserName},
                {authContextWithNoUser, authSuccessResponseWithNonExistingUserId,
                        errorMessageForNonExistingUserId},
                {authContextWithNoUser, authSuccessResponseWithNoUser,
                        errorMessageForNoUserDate},

                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserId,
                        errorMessageForMissingUserId},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithMissMatchUserName,
                        errorMessageForMissingMissMatchUserName},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithNonExistingUserId,
                        errorMessageForNonExistingUserId},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithNoUser,
                        errorMessageForNoUserDate},

                {authContextWithFedUserFromFirstStep, authSuccessResponseWithoutUserId,
                        errorMessageForMissingUserId},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithMissMatchUserName,
                        errorMessageForMissingMissMatchUserName},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithNonExistingUserId,
                        errorMessageForNonExistingUserId},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithNoUser,
                        errorMessageForNoUserDate}
        };
    }

    @Test(dataProvider = "getSuccessInvalidResponsesForLocalUsers")
    public void testProcessSuccessResponseWithInvalidResponsesForLocalUsers(AuthenticationContext context,
            ActionInvocationSuccessResponse actionInvocationSuccessResponse, String errorMessage)
            throws Exception {

        if (actionInvocationSuccessResponse.getData() != null) {
            mockUserStoreManager(
                    ((AuthenticatedUserData) actionInvocationSuccessResponse.getData()).getUser().getUserStore());
        }
        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, AuthenticationType.IDENTIFICATION);
        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new SuccessStatus.Builder().setResponseContext(eventContext).build());
        context.setCurrentStep(2);
        context.setExternalIdP(new ExternalIdPConfig(localIdp));
        context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME,
                ActionExecutionStatus.Status.SUCCESS);

        ActionExecutionResponseProcessorException exception =
                assertThrows(ActionExecutionResponseProcessorException.class, () -> { authenticationResponseProcessor
                        .processSuccessResponse(eventContext, null, actionInvocationSuccessResponse);
        });

        Assert.assertEquals(exception.getMessage(), errorMessage);
    }

    @DataProvider
    public Object[][] getSuccessValidResponsesForFederatedUsers() {

        ExternallyAuthenticatedUser authUser = new ExternallyAuthenticatedUser();
        authUser.setGroups(groups);

        // Valid user data with userId, userStore and userName claim.
        ActionInvocationSuccessResponse authSuccessResponseWithAuthUser = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUser));

        // Valid user data with userId and without userStore.
        ExternallyAuthenticatedUser authUserNoUserStore =
                new ExternallyAuthenticatedUser();
        authUserNoUserStore.setUserStore(null);
        authUserNoUserStore.setGroups(groups);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserStore = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserStore));

        return new Object[][] {
                {authContextWithNoUser, authSuccessResponseWithAuthUser},
                {authContextWithNoUser, authSuccessResponseWithoutUserStore},

                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithAuthUser},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserStore},

                {authContextWithFedUserFromFirstStep, authSuccessResponseWithAuthUser},
                {authContextWithFedUserFromFirstStep, authSuccessResponseWithoutUserStore}
        };
    }

    @Test(dataProvider = "getSuccessValidResponsesForFederatedUsers")
    public void getSuccessValidResponsesForFederatedUsers(AuthenticationContext context,
            ActionInvocationSuccessResponse actionInvocationSuccessResponse)
            throws Exception {

        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, AuthenticationType.IDENTIFICATION);
        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new SuccessStatus.Builder().setResponseContext(eventContext).build());
        context.setCurrentStep(2);
        context.setExternalIdP(new ExternalIdPConfig(fedIdp));
        context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME,
                ActionExecutionStatus.Status.SUCCESS);

        ActionExecutionStatus<Success> status = authenticationResponseProcessor.processSuccessResponse(
                eventContext, null, actionInvocationSuccessResponse);

        Assert.assertEquals(status.getStatus(), ActionExecutionStatus.Status.SUCCESS);
        assertAuthenticationContext(context, expectedFedAuthenticatedUser);
    }

    @DataProvider
    public Object[][] getSuccessInvalidResponsesForFederatedUsers() {

        // Invalid user data without userId.
        ExternallyAuthenticatedUser authUserNoUserId = new ExternallyAuthenticatedUser();
        authUserNoUserId.setId(null);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserId = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserId));
        String errorMessageForMissingUserId = "The userId field is missing in the authentication action response.";

        ExternallyAuthenticatedUser authUserWithInvalidGroupName = new ExternallyAuthenticatedUser();
        authUserWithInvalidGroupName.setGroups(new ArrayList<>(List.of("group,1", "group2")));
        ActionInvocationSuccessResponse authSuccessResponseWithInvalidGroupName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(), new AuthenticatedUserData(authUserWithInvalidGroupName));
        String errorMessageForNoInvalidGroupName = String.format("The character %s is not allowed in names of groups," +
                " as it is used internally to separate multiple groups.", FrameworkUtils.getMultiAttributeSeparator());

        return new Object[][] {
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithoutUserId,
                        errorMessageForMissingUserId},
                {authContextWithLocalUserFromFirstStep, authSuccessResponseWithInvalidGroupName,
                        errorMessageForNoInvalidGroupName}
        };
    }

    @Test(dataProvider = "getSuccessInvalidResponsesForFederatedUsers")
    public void testProcessSuccessResponseWithInvalidResponsesForFederatedUsers(AuthenticationContext context,
            ActionInvocationSuccessResponse actionInvocationSuccessResponse, String errorMessage)
            throws Exception {

        Map<String, Object> eventContext = new TestEventContextBuilder().buildEventContext(
                request, response, context, AuthenticationType.IDENTIFICATION);
        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new SuccessStatus.Builder().setResponseContext(eventContext).build());
        context.setCurrentStep(2);
        context.setExternalIdP(new ExternalIdPConfig(fedIdp));
        context.setProperty(AuthenticatorAdapterConstants.EXECUTION_STATUS_PROP_NAME,
                ActionExecutionStatus.Status.SUCCESS);

        ActionExecutionResponseProcessorException exception =
                assertThrows(ActionExecutionResponseProcessorException.class, () -> { authenticationResponseProcessor
                        .processSuccessResponse(eventContext, null, actionInvocationSuccessResponse);
                });

        Assert.assertEquals(exception.getMessage(), errorMessage);
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

    private void buildEventContexts() {

        fedIdp = new IdentityProvider();
        fedIdp.setIdentityProviderName("testIdp");

        localIdp = new IdentityProvider();
        localIdp.setIdentityProviderName("LOCAL");

        authHistory = TestEventContextBuilder.buildAuthHistory();

        // Custom authenticator engaging in 1st step of authentication flow.
        authContextWithNoUser = new TestEventContextBuilder().buildAuthenticationContext(
                null, SUPER_TENANT_DOMAIN_NAME, new ArrayList<AuthHistory>());

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        localUserFromFirstStep = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        authContextWithLocalUserFromFirstStep = new TestEventContextBuilder().buildAuthenticationContext(
                localUserFromFirstStep, SUPER_TENANT_DOMAIN_NAME, authHistory);

        // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
        fedUserFromFirstStep = TestAuthenticatedTestUserBuilder.createAuthenticatedUser(
                TestAuthenticatedTestUserBuilder.AuthenticatedUserConstants.LOCAL_USER_PREFIX,
                SUPER_TENANT_DOMAIN_NAME);
        authContextWithFedUserFromFirstStep = new TestEventContextBuilder().buildAuthenticationContext(
                fedUserFromFirstStep, SUPER_TENANT_DOMAIN_NAME, authHistory);
    }

    private void mockServices() throws Exception {

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        mockedRealmService = mock(RealmService.class);
        mockedUserRealm = mock(UserRealm.class);
        abstractUserStoreManager = mock(AbstractUserStoreManager.class);
        mockedUserStoreManager = mock(UserStoreManager.class);
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(mockedRealmService);
        when(mockedRealmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString()))
                .thenReturn(abstractUserStoreManager);
        when(abstractUserStoreManager.getUser(AuthenticatingUserConstants.USERID, null)).thenReturn(userFromUserStore);
        when(abstractUserStoreManager.getUser(NON_EXISTING_USERID, null)).thenReturn(null);
        when(abstractUserStoreManager.isExistingUser(AuthenticatingUserConstants.USERNAME)).thenReturn(true);

        mockedActionExecutorService = mock(ActionExecutorService.class);
        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(mockedActionExecutorService);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);

        frameworkUtils = mockStatic(FrameworkUtils.class);
        frameworkUtils.when(FrameworkUtils::getMultiAttributeSeparator).thenReturn(",");
    }

    private void createExpectedAuthenticatedUsers() {

        groups.add("group-1");
        groups.add("group-2");

        userFromUserStore = new User();
        userFromUserStore.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        userFromUserStore.setUserStoreDomain(AuthenticatingUserConstants.USER_STORE_NAME);
        userFromUserStore.setUsername(AuthenticatingUserConstants.USERNAME);
        userFromUserStore.setUserID(AuthenticatingUserConstants.USERID);

        Map<ClaimMapping, String> claimsForLocalUser = new HashMap<>();
        claimsForLocalUser.put(ClaimMapping.build("claim-1", "claim-1", null, false),
                "value-1");
        expectedLocalAuthenticatedUser = new AuthenticatedUser();
        expectedLocalAuthenticatedUser.setUserId(AuthenticatingUserConstants.USERID);
        expectedLocalAuthenticatedUser.setUserStoreDomain(AuthenticatingUserConstants.USER_STORE_NAME);
        expectedLocalAuthenticatedUser.setUserName(AuthenticatingUserConstants.USERNAME);
        expectedLocalAuthenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        expectedLocalAuthenticatedUser.setUserAttributes(claimsForLocalUser);

        Map<ClaimMapping, String> claimsForFedUser = new HashMap<>();
        claimsForFedUser.put(ClaimMapping.build("claim-1", "claim-1", "value-1", false),
                "value-1");
        claimsForFedUser.put(ClaimMapping.build(AuthenticatorAdapterConstants.GROUP_CLAIM,
                        AuthenticatorAdapterConstants.GROUP_CLAIM, null, false),
                String.join(",", groups));
        expectedFedAuthenticatedUser = new AuthenticatedUser();
        expectedFedAuthenticatedUser.setUserId(AuthenticatingUserConstants.USERID);
        expectedFedAuthenticatedUser.setUserStoreDomain(AuthenticatingUserConstants.USER_STORE_NAME);
        expectedFedAuthenticatedUser.setUserName(AuthenticatingUserConstants.USERNAME);
        expectedFedAuthenticatedUser.setFederatedUser(true);
        expectedFedAuthenticatedUser.setTenantDomain(SUPER_TENANT_DOMAIN_NAME);
        expectedFedAuthenticatedUser.setUserAttributes(claimsForFedUser);

        mockStatic(AuthenticatedUser.class);
        when(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(expectedLocalAuthenticatedUser);
        when(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(expectedLocalAuthenticatedUser);
    }

    private void buildPerformableOperation() {

        redirectOperation = new PerformableOperation();
        redirectOperation.setOp(Operation.REDIRECT);
        redirectOperation.setUrl("http://redirect.url");
    }

    private void mockUserStoreManager(AuthenticatedUserData.UserStore userStore) throws Exception {

        if (userStore == null) {
            when(mockedUserRealm.getUserStoreManager()).thenReturn(abstractUserStoreManager);
        } else {
            when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
            when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString())).thenReturn(abstractUserStoreManager);
        }
    }
}
