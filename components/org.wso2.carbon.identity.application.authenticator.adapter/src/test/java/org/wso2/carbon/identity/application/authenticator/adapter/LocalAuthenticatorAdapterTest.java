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

import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.IncompleteStatus;
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
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestActionInvocationResponseBuilder.ExternallyAuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestAuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.TestEventContextBuilder;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants.USERNAME_CLAIM;

public class LocalAuthenticatorAdapterTest {

    private static final String AUTHENTICATOR_NAME = "LocalAuthenticatorAdapter";
    private static final String FRIENDLY_NAME = "Local Authenticator Adapter";

    private FederatedAuthenticatorAdapter federatedAuthenticatorAdapter;
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private AuthenticationContext authContextForNoUser;
    private AuthenticationContext authContextForLocalUser;
    private AuthenticationContext authContextForFedUser;
    private AuthenticatedUser localUser;
    private AuthenticatedUser fedUser;
    private User localUserFromUserStore;

    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private ActionExecutorService mockedActionExecutorService;
    private UserRealm mockedUserRealm;
    private JDBCUserStoreManager mockedAbstractUserStoreManager;
    private UserStoreManager mockedUserStoreManager;

    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    private static ArrayList<AuthHistory> authHistory;

    private AuthenticatedUser expectedAuthenticatedUser;
    private final AuthenticatedUserData.Claim userNameClaim =
            new AuthenticatedUserData.Claim(USERNAME_CLAIM, "DummyUserName");
    private final AuthenticatedUserData.Claim mismatchUserNameClaim =
            new AuthenticatedUserData.Claim(USERNAME_CLAIM, "mismatched-username");

    @Mock
    private RealmService realmService;

    @BeforeClass
    public void setUp() throws Exception {

        authHistory = TestEventContextBuilder.buildAuthHistory();
        buildEventContext();

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        localUserFromUserStore = new User();
        localUserFromUserStore.setUsername(TestConstants.AuthenticatingUserConstants.USERNAME);
        realmService = mock(RealmService.class);
        mockedUserRealm = mock(UserRealm.class);
        mockedUserStoreManager = mock(UserStoreManager.class);
        mockedAbstractUserStoreManager = mock(JDBCUserStoreManager.class);
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(realmService);
        when(realmService.getTenantUserRealm(anyInt())).thenReturn(mockedUserRealm);
        when(mockedUserRealm.getUserStoreManager()).thenReturn(mockedUserStoreManager);
        when(mockedUserStoreManager.getSecondaryUserStoreManager(anyString()))
                .thenReturn(mockedAbstractUserStoreManager);
        when(mockedAbstractUserStoreManager.getUser(any(), any())).thenReturn(localUserFromUserStore);

        mockStatic(AuthenticatedUser.class);
        AuthenticatedUser mockUser = new AuthenticatedUser();
        mockUser.setUserId(TestConstants.AuthenticatingUserConstants.USERID);
        mockUser.setUserName(TestConstants.AuthenticatingUserConstants.USERNAME);
        when(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(mockUser);
        when(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(anyString()))
                .thenReturn(mockUser);

        mockedActionExecutorService = mock(ActionExecutorService.class);
        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(mockedActionExecutorService);

        expectedAuthenticatedUser = new AuthenticatedUser();
        expectedAuthenticatedUser.setUserId(TestConstants.AuthenticatingUserConstants.USERID);
        expectedAuthenticatedUser.setUserStoreDomain(TestConstants.AuthenticatingUserConstants.USER_STORE_NAME);
        expectedAuthenticatedUser.setUserName(TestConstants.AuthenticatingUserConstants.USERNAME);

        FederatedAuthenticatorConfig fedConfig = new FederatedAuthenticatorConfig();
        fedConfig.setName(AUTHENTICATOR_NAME);
        fedConfig.setDisplayName(FRIENDLY_NAME);
        federatedAuthenticatorAdapter = new FederatedAuthenticatorAdapter(fedConfig);
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
    public void testGetFriendlyName() {

        Assert.assertEquals(federatedAuthenticatorAdapter.getFriendlyName(), FRIENDLY_NAME);
    }

    @Test
    public void testGetName() {

        Assert.assertEquals(federatedAuthenticatorAdapter.getName(), AUTHENTICATOR_NAME);
    }

    @Test
    public void testClaimDialectURI() {

        Assert.assertEquals(federatedAuthenticatorAdapter.getClaimDialectURI(),
                AuthenticatorAdapterConstants.WSO2_CLAIM_DIALECT);
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

        ExternallyAuthenticatedUser authUser = new ExternallyAuthenticatedUser();

        // Valid user data with userId, userStore and userName claim.
        ActionInvocationSuccessResponse authSuccessResponseWithAuthUser = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUser));

        // Valid user data with userId and without userStore, userName claim.
        ExternallyAuthenticatedUser authUserNoUserStore = new ExternallyAuthenticatedUser();
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
        ExternallyAuthenticatedUser authUserNoUserId = new ExternallyAuthenticatedUser();
        authUserNoUserId.setId(null);
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserStore = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserId));

        // Invalid user data with userId, userStore and mismatching userName claim.
        ExternallyAuthenticatedUser authUserMissMatchUserName = new ExternallyAuthenticatedUser();
        ActionInvocationSuccessResponse authSuccessResponseWithMissMatchUserName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserMissMatchUserName));


        // Valid user data with userId, userStore and without userName claim.
        ExternallyAuthenticatedUser authUserNoUserName = new ExternallyAuthenticatedUser();
        ActionInvocationSuccessResponse authSuccessResponseWithoutUserName = TestActionInvocationResponseBuilder
                .buildAuthenticationSuccessResponse(
                        new ArrayList<>(),
                        new AuthenticatedUserData(authUserNoUserName));

        return new Object[][] {
                {authContextForLocalUser, authSuccessResponseWithoutUserStore},
                {authContextForLocalUser, authSuccessResponseWithMissMatchUserName}
        };
    }

    //@Test(dataProvider = "getSuccessInvalidResponsesForLocalUsers")
    public void testProcessSuccessResponseWithInvalidResponsesForLocalUsers(
            Map<String, Object> eventContext,
            ActionInvocationSuccessResponse successResponse, ExternallyAuthenticatedUser expectedUser)
            throws Exception {

        AuthenticatorFlowStatus status = federatedAuthenticatorAdapter
                .process(request, response, authContextForFedUser);
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
    }
}
