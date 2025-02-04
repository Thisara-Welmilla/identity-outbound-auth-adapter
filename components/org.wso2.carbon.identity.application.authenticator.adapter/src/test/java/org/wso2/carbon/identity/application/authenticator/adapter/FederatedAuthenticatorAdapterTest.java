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

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.model.IncompleteStatus;
import org.wso2.carbon.identity.action.execution.model.SuccessStatus;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.util.HashMap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FederatedAuthenticatorAdapterTest {

    private static final String AUTHENTICATOR_NAME = "FederatedAuthenticatorAdapter";
    private static final String FRIENDLY_NAME = "Federated Authenticator Adapter";

    private ActionExecutorService mockedActionExecutorService;

    private FederatedAuthenticatorAdapter federatedAuthenticatorAdapter;

    @BeforeClass
    public void setUp() {

        FederatedAuthenticatorConfig fedConfig = new FederatedAuthenticatorConfig();
        fedConfig.setName(AUTHENTICATOR_NAME);
        fedConfig.setDisplayName(FRIENDLY_NAME);
        federatedAuthenticatorAdapter = new FederatedAuthenticatorAdapter(fedConfig);

        mockedActionExecutorService = mock(ActionExecutorService.class);
        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(mockedActionExecutorService);
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

    @Test
    public void testSuccessAuthenticationRequestProcess(HttpServletRequest request, HttpServletResponse response,
                                                        AuthenticationContext context) throws Exception {

        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new SuccessStatus.Builder().setResponseContext(new HashMap<>()).build());
        AuthenticatorFlowStatus authStatus = federatedAuthenticatorAdapter.process(request, response, context);

        Assert.assertEquals(authStatus, AuthenticatorFlowStatus.SUCCESS_COMPLETED);
    }

    @Test
    public void testIncompleteAuthenticationRequestProcess(HttpServletRequest request, HttpServletResponse response,
                                                           AuthenticationContext context) throws Exception {

        when(mockedActionExecutorService.execute(any(), any(), any(), any())).thenReturn(
                new IncompleteStatus.Builder().responseContext(new HashMap<>()).build());
        AuthenticatorFlowStatus authStatus = federatedAuthenticatorAdapter.process(request, response, context);

        Assert.assertEquals(authStatus, AuthenticatorFlowStatus.INCOMPLETE);
    }
}
