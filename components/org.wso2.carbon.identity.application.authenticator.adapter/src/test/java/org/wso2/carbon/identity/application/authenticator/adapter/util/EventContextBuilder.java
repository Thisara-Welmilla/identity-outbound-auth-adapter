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

package org.wso2.carbon.identity.application.authenticator.adapter.util;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EventContextBuilder {

    Map<String, Object> eventContext = new HashMap<>();
    public static final String SP_ID = "spId";
    public static final String SP_NAME = "spName";
    public static final String FLOW_ID = "flow-id";

    /**
     * Constructor for EventContextBuilder.
     *
     * @param authenticatedUser Authenticated user.
     * @param headers           Headers.
     * @param parameters        Parameters.
     */
    public EventContextBuilder(AuthenticatedUser authenticatedUser, String tenantDomain,
                               Map<String, String> headers, Map<String, String> parameters,
                               ArrayList<AuthHistory> authHistory) {

        eventContext.put(AuthenticatorAdapterConstants.AUTH_REQUEST, buildAuthenticationRequest(headers, parameters));
        eventContext.put(AuthenticatorAdapterConstants.AUTH_CONTEXT, buildAuthenticationContext(authenticatedUser,
                tenantDomain, authHistory));
    }

    /**
     * Get event context.
     *
     * @return Event context.
     */
    public Map<String, Object> getEventContext() {

        return eventContext;
    }

    /**
     * Set request.
     *
     * @param request Request.
     */
    public void setRequest(HttpServletRequest request) {

        eventContext.put(AuthenticatorAdapterConstants.AUTH_REQUEST, request);
    }

    /**
     * Set authentication context.
     *
     * @param context Authentication context.
     */
    public void setAuthenticationContext(AuthenticationContext context) {

        eventContext.put(AuthenticatorAdapterConstants.AUTH_CONTEXT, context);
    }

    /**
     * Set flow ID.
     *
     * @param flowId Flow ID.
     */
    public void setFlowId(String flowId) {

        eventContext.put(AuthenticatorAdapterConstants.FLOW_ID, flowId);
    }

    public static ArrayList<AuthHistory> buildAuthHistory() {

        ArrayList<AuthHistory> authHistory = new ArrayList<>();
        AuthHistory authStep1 = new AuthHistory("authenticator-1", "LOCAL");
        authHistory.add(authStep1);
        AuthHistory authStep2 = new AuthHistory("authenticator-2", "GOOGLE");
        authHistory.add(authStep2);
        return authHistory;
    }

    private AuthenticationContext buildAuthenticationContext(AuthenticatedUser authenticatedUser, String tenantDomain,
                                                             ArrayList<AuthHistory> authHistory) {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setContextIdentifier(FLOW_ID);
        authenticationContext.setSubject(authenticatedUser);
        authenticationContext.setTenantDomain(tenantDomain);
        authHistory.forEach(authenticationContext::addAuthenticationStepHistory);
        authenticationContext.setCurrentStep(authHistory.size() + 1);
        authenticationContext.setServiceProviderName(SP_NAME);
        authenticationContext.setServiceProviderResourceId(SP_ID);
        return authenticationContext;
    }

    /**
     * Build authentication request.
     *
     * @param headers    Headers.
     * @param parameters Parameters.
     * @return HttpServletRequest.
     */
    public HttpServletRequest buildAuthenticationRequest(Map<String, String> headers, Map<String, String> parameters) {

        HttpServletRequest request = mock(HttpServletRequest.class);
        Enumeration<String> headerEnumeration = Collections.enumeration(headers.keySet());
        Enumeration<String> parameterEnumeration = Collections.enumeration(parameters.keySet());
        when(request.getHeaderNames()).thenReturn(headerEnumeration);
        when(request.getParameterNames()).thenReturn(parameterEnumeration);
        headers.forEach((key, value) -> when(request.getHeader(key)).thenReturn(value));
        parameters.forEach((key, value) -> when(request.getParameter(key)).thenReturn(value));
        return request;
    }
}
