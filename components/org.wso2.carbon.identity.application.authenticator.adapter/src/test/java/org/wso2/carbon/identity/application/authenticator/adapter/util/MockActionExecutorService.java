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

import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionException;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.Success;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticationResponseProcessor;
import org.wso2.carbon.identity.application.authenticator.adapter.internal.AuthenticatorAdapterDataHolder;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MockActionExecutorService {

    AuthenticationResponseProcessor responseProcessor = new AuthenticationResponseProcessor();

    /**
     * Mock the ActionExecutorService for a successful response.
     *
     * @param eventContext     Event context.
     * @param actionEvent      Action event.
     * @param successResponse  Success response.
     * @throws ActionExecutionException
     * @throws ActionExecutionResponseProcessorException
     */
    public void mockActionExecutorServiceForSuccessResponse(Map<String, Object> eventContext, Event actionEvent,
                                                            ActionInvocationSuccessResponse successResponse)
            throws ActionExecutionException, ActionExecutionResponseProcessorException {

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.execute(any(), any(), any()))
                .thenReturn(actionExecutionForAuthSuccess(eventContext, actionEvent, successResponse));

        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(actionExecutorService);
    }

    private ActionExecutionStatus<Success> actionExecutionForAuthSuccess(Map<String, Object> eventContext,
            Event actionEvent, ActionInvocationSuccessResponse successResponse)
            throws ActionExecutionResponseProcessorException {

        return responseProcessor.processSuccessResponse(eventContext, actionEvent, successResponse);
    }

    /**
     * Mock the ActionExecutorService for a failure response.
     *
     * @param eventContext     Event context.
     * @param actionEvent      Action event.
     * @param failureResponse  Failure response.
     * @throws ActionExecutionException
     * @throws ActionExecutionResponseProcessorException
     */
    public void mockActionExecutorServiceForFailureResponse(Map<String, Object> eventContext, Event actionEvent,
                                                            ActionInvocationFailureResponse failureResponse)
            throws ActionExecutionException, ActionExecutionResponseProcessorException {

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.execute(any(), any(), any()))
                .thenReturn(actionExecutionForAuthFailure(eventContext, actionEvent, failureResponse));

        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(actionExecutorService);
    }

    private ActionExecutionStatus<Failure> actionExecutionForAuthFailure(
            Map<String, Object> eventContext, Event actionEvent, ActionInvocationFailureResponse failureResponse)
            throws ActionExecutionResponseProcessorException {

        return responseProcessor.processFailureResponse(eventContext, actionEvent, failureResponse);
    }

    /**
     * Mock the ActionExecutorService for an error response.
     *
     * @param eventContext     Event context.
     * @param actionEvent      Action event.
     * @param errorResponse    Error response.
     * @throws ActionExecutionException
     * @throws ActionExecutionResponseProcessorException
     */
    public void mockActionExecutorServiceForErrorResponse(Map<String, Object> eventContext, Event actionEvent,
                                                            ActionInvocationErrorResponse errorResponse)
            throws ActionExecutionException, ActionExecutionResponseProcessorException {

        ActionExecutorService actionExecutorService = mock(ActionExecutorService.class);
        when(actionExecutorService.execute(any(), any(), any()))
                .thenReturn(actionExecutionForAuthFailure(eventContext, actionEvent, errorResponse));

        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(actionExecutorService);
    }

    private ActionExecutionStatus<Error> actionExecutionForAuthFailure(
            Map<String, Object> eventContext, Event actionEvent, ActionInvocationErrorResponse errorResponse)
            throws ActionExecutionResponseProcessorException {

        return responseProcessor.processErrorResponse(eventContext, actionEvent, errorResponse);
    }
}
