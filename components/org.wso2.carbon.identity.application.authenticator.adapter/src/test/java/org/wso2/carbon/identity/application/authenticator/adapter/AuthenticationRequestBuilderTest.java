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
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionRequestBuilderException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionRequest;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.model.Application;
import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.Header;
import org.wso2.carbon.identity.action.execution.model.Organization;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.Param;
import org.wso2.carbon.identity.action.execution.model.Request;
import org.wso2.carbon.identity.action.execution.model.Tenant;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.exception.UserIdNotFoundException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationRequestEvent;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatedTestUserBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.util.EventContextBuilder;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatedTestUserBuilder.AuthenticatedUserConstants;
import static org.wso2.carbon.base.MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;

public class AuthenticationRequestBuilderTest {

    private AuthenticationRequestBuilder authenticationRequestBuilder;
    private MockedStatic<IdentityTenantUtil> identityTenantUtilMockedStatic;
    private MockedStatic<LoggerUtils> loggerUtils;

    private static final String TENANT_DOMAIN_TEST = "carbon.super";
    private static final int TENANT_ID_TEST = -1234;
    Map<String, String> headers = Map.of("header-1", "value-1", "header-2", "value-2");
    Map<String, String> parameters = Map.of("param-1", "value-1", "param-2", "value-2");
    ArrayList<AuthHistory> authHistory;

    @BeforeClass
    public void setUp() throws OrganizationManagementException {

        authenticationRequestBuilder = new AuthenticationRequestBuilder();
        authHistory = EventContextBuilder.buildAuthHistory();

        OrganizationManager organizationManager = mock(OrganizationManager.class);
        when(organizationManager.getOrganizationNameById(anyString())).thenReturn(AuthenticatedUserConstants.ORG_NAME);
        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(organizationManager);

        identityTenantUtilMockedStatic = mockStatic(IdentityTenantUtil.class);
        identityTenantUtilMockedStatic.when(() -> IdentityTenantUtil.getTenantId(TENANT_DOMAIN_TEST))
                .thenReturn(TENANT_ID_TEST);

        loggerUtils = mockStatic(LoggerUtils.class);
        loggerUtils.when(() -> LoggerUtils.isDiagnosticLogsEnabled()).thenReturn(true);
    }

    @AfterClass
    public void tearDown() {

        identityTenantUtilMockedStatic.close();
        loggerUtils.close();
    }

    @Test
    public void testGetSupportedActionType() {

        Assert.assertEquals(authenticationRequestBuilder.getSupportedActionType(), ActionType.AUTHENTICATION);
    }

    @DataProvider
    public Object[][] eventContextDataProvider() throws UserIdNotFoundException {

        // Custom authenticator engaging in 1st step of authentication flow.
        Map<String, Object> eventContextForNoUser = new EventContextBuilder(
                 null, SUPER_TENANT_DOMAIN_NAME, headers, parameters, new ArrayList<>())
                .getEventContext();
        AuthenticationRequestEvent expectedEventForNoUser = getExpectedEvent(null);

        // Custom authenticator engaging in 2nd step of authentication flow with Local authenticated user.
        AuthenticatedUser localUser = AuthenticatedTestUserBuilder.createAuthenticatedUser(
                AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        Map<String, Object> eventContextForLocalUser = new EventContextBuilder(
                localUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory)
                .getEventContext();
        AuthenticationRequestEvent expectedEventForLocalUser = getExpectedEvent(localUser);

        // Custom authenticator engaging in 2nd step of authentication flow with federated authenticated user.
        AuthenticatedUser fedUser = AuthenticatedTestUserBuilder.createAuthenticatedUser(
                AuthenticatedUserConstants.LOCAL_USER_PREFIX, SUPER_TENANT_DOMAIN_NAME);
        Map<String, Object> eventContextForFedUser = new EventContextBuilder(
                fedUser, SUPER_TENANT_DOMAIN_NAME, headers, parameters, authHistory)
                .getEventContext();
        AuthenticationRequestEvent expectedEventForFedUser = getExpectedEvent(fedUser);

        return new Object[][]{
                {eventContextForNoUser, expectedEventForNoUser},
                {eventContextForLocalUser, expectedEventForLocalUser},
                {eventContextForFedUser, expectedEventForFedUser}};
    }

    @Test(dataProvider = "eventContextDataProvider")
    public void testBuildActionExecutionRequest(Map<String, Object> eventContext,
            AuthenticationRequestEvent expectedEvent) throws ActionExecutionRequestBuilderException {

        ActionExecutionRequest actionExecutionRequest =
                authenticationRequestBuilder.buildActionExecutionRequest(eventContext);
        Assert.assertNotNull(actionExecutionRequest);
        Assert.assertEquals(actionExecutionRequest.getFlowId(), EventContextBuilder.FLOW_ID);
        Assert.assertEquals(actionExecutionRequest.getActionType(), ActionType.AUTHENTICATION);
        assertEvent(actionExecutionRequest.getEvent(), expectedEvent);
        assertAllowedOperations(actionExecutionRequest.getAllowedOperations());
    }

    private void assertEvent(Event actualEvent, AuthenticationRequestEvent expectedEvent) {

        Assert.assertTrue(actualEvent instanceof AuthenticationRequestEvent);
        AuthenticationRequestEvent actualAuthenticationEvent = (AuthenticationRequestEvent) actualEvent;

        assertRequest(actualAuthenticationEvent.getRequest(), expectedEvent.getRequest());
        Assert.assertEquals(actualAuthenticationEvent.getTenant().getId(), expectedEvent.getTenant().getId());
        Assert.assertEquals(actualAuthenticationEvent.getApplication().getId(), expectedEvent.getApplication().getId());
        Assert.assertEquals(actualAuthenticationEvent.getApplication().getName(),
                expectedEvent.getApplication().getName());

        if (expectedEvent.getUser() == null) {
            Assert.assertNull(actualAuthenticationEvent.getUser() );
            Assert.assertNull(actualAuthenticationEvent.getUserStore());
            Assert.assertNull(actualAuthenticationEvent.getOrganization());
            Assert.assertEquals(actualAuthenticationEvent.getCurrentStepIndex(), 1);
            Assert.assertEquals(actualAuthenticationEvent.getAuthenticatedSteps().length, 0);
            return;
        }

        Assert.assertTrue(actualAuthenticationEvent.getUser() instanceof AuthenticatingUser);
        AuthenticatingUser actualAuthenticatingUser = (AuthenticatingUser) actualAuthenticationEvent.getUser();
        AuthenticatingUser expectedUser = (AuthenticatingUser) expectedEvent.getUser();
        Assert.assertEquals(actualAuthenticatingUser.getId(), expectedUser.getId());
        Assert.assertEquals(actualAuthenticatingUser.getIdp(), expectedUser.getIdp());
        Assert.assertEquals(actualAuthenticatingUser.getSub(), expectedUser.getSub());
        Assert.assertEquals(actualAuthenticatingUser.getUserClaims().size(), expectedUser.getUserClaims().size());
        Assert.assertEquals(actualAuthenticationEvent.getOrganization().getId(), AuthenticatedUserConstants.ORG_ID);
        Assert.assertEquals(actualAuthenticationEvent.getUserStore().getName(), "PRIMARY");
        Assert.assertEquals(actualAuthenticationEvent.getCurrentStepIndex(), authHistory.size() + 1);
        Assert.assertEquals(actualAuthenticationEvent.getAuthenticatedSteps().length, authHistory.size());
    }

    private static void assertRequest(Request actualRequest, Request expectedRequest) {

        Assert.assertTrue(actualRequest instanceof AuthenticationRequest);
        AuthenticationRequest actualAuthRequest = (AuthenticationRequest) actualRequest;

        Assert.assertEquals(actualAuthRequest.getAdditionalHeaders().size(), expectedRequest.getAdditionalHeaders().size());
        for (int i = 0; i < expectedRequest.getAdditionalHeaders().size(); i++) {
            Header actualAdditionalHeader = actualAuthRequest.getAdditionalHeaders().get(i);
            Header expectedAdditionalHeader = expectedRequest.getAdditionalHeaders().get(i);
            Assert.assertEquals(actualAdditionalHeader.getName(), expectedAdditionalHeader.getName());
            Assert.assertEquals(actualAdditionalHeader.getValue(), expectedAdditionalHeader.getValue());
        }
        Assert.assertEquals(actualAuthRequest.getAdditionalParams().size(), expectedRequest.getAdditionalParams().size());
        for (int i = 0; i < expectedRequest.getAdditionalParams().size(); i++) {
            Param actualAdditionalParam = actualAuthRequest.getAdditionalParams().get(i);
            Param expectedAdditionalParam = expectedRequest.getAdditionalParams().get(i);
            Assert.assertEquals(actualAdditionalParam.getName(), expectedAdditionalParam.getName());
            Assert.assertEquals(actualAdditionalParam.getValue(), expectedAdditionalParam.getValue());
        }
    }

    private void assertAllowedOperations(List<AllowedOperation> allowedOperationList) {

        Assert.assertEquals(allowedOperationList.size(), 1);
        Assert.assertEquals(Operation.REDIRECT, allowedOperationList.get(0).getOp());
    }

    private AuthenticationRequestEvent getExpectedEvent(AuthenticatedUser user) throws UserIdNotFoundException {

        AuthenticationRequestEvent.Builder eventBuilder = new AuthenticationRequestEvent.Builder();
        eventBuilder.tenant(new Tenant(String.valueOf(TENANT_ID_TEST), TENANT_DOMAIN_TEST));
        eventBuilder.application(new Application(EventContextBuilder.SP_ID, EventContextBuilder.SP_NAME));
        eventBuilder.organization(
                new Organization(AuthenticatedUserConstants.ORG_ID, AuthenticatedUserConstants.ORG_NAME));
        List<Header> headers = new ArrayList<>();
        this.headers.forEach((key, value) -> headers.add(new Header(key, new String[]{value})));
        List<Param> params = new ArrayList<>();
        this.parameters.forEach((key, value) -> params.add(new Param(key, new String[]{value})));
        eventBuilder.request(new AuthenticationRequest(headers, params));
        if (user != null) {
            eventBuilder.user(createAuthenticatingUser(user));
        }

        return eventBuilder.build();
    }

    private static AuthenticatingUser createAuthenticatingUser(AuthenticatedUser user) throws UserIdNotFoundException {

        AuthenticatingUser authenticatingUser = new AuthenticatingUser(user.getUserId());
        if (user.isFederatedUser()) {
            authenticatingUser.setIdp(AuthenticatorAdapterConstants.FED_IDP);
        } else {
            authenticatingUser.setIdp(AuthenticatorAdapterConstants.LOCAL_IDP);
        }
        authenticatingUser.setSub(user.getAuthenticatedSubjectIdentifier());
        return authenticatingUser;
    }
}
