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

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.ActionExecutionStatus;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationErrorResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationFailureResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationIncompleteResponse;
import org.wso2.carbon.identity.action.execution.model.ActionInvocationSuccessResponse;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.action.execution.model.ErrorStatus;
import org.wso2.carbon.identity.action.execution.model.Event;
import org.wso2.carbon.identity.action.execution.model.FailedStatus;
import org.wso2.carbon.identity.action.execution.model.Failure;
import org.wso2.carbon.identity.action.execution.model.Incomplete;
import org.wso2.carbon.identity.action.execution.model.IncompleteStatus;
import org.wso2.carbon.identity.action.execution.model.Operation;
import org.wso2.carbon.identity.action.execution.model.PerformableOperation;
import org.wso2.carbon.identity.action.execution.model.Success;
import org.wso2.carbon.identity.action.execution.model.SuccessStatus;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.adapter.util.AuthenticatorAdapterConstants;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

/**
 * This is responsible for processing authentication response from the external authentication service.
 */
public class AuthenticationResponseProcessor implements ActionExecutionResponseProcessor {

    private static final Log LOG = LogFactory.getLog(AuthenticationResponseProcessor.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public ActionExecutionStatus<Success> processSuccessResponse(Map<String, Object> eventContext, Event event,
            ActionInvocationSuccessResponse actionInvocationSuccessResponse)
            throws ActionExecutionResponseProcessorException {

        /* TODO: 1. Validate whether authenticated user data are present in the action invocation response for the
            IDENTIFIER local authenticators and Federated authenticators.
            2. Move this code logic to the processAuthenticationResponse method in the AbstractAuthenticatorAdapter.
         */
        AuthenticationContext context = (AuthenticationContext) eventContext.get(
                AuthenticatorAdapterConstants.AUTH_CONTEXT);
        context.setProperty(AuthenticatorAdapterConstants.AUTHENTICATED_USER_DATA,
                actionInvocationSuccessResponse.getData());

        return new SuccessStatus.Builder().setResponseContext(eventContext).build();
    }

    @Override
    public ActionExecutionStatus<Incomplete> processIncompleteResponse(Map<String, Object> eventContext, Event event,
            ActionInvocationIncompleteResponse actionInvocationIncompleteResponse)
            throws ActionExecutionResponseProcessorException {

        HttpServletResponse response = (HttpServletResponse) eventContext
                .get(AuthenticatorAdapterConstants.AUTH_RESPONSE);

        List<PerformableOperation> operationsToPerform = actionInvocationIncompleteResponse.getOperations();
        validateOperationForIncompleteStatus(operationsToPerform);

        String url = operationsToPerform.get(0).getUrl();
        try {
            response.sendRedirect(operationsToPerform.get(0).getUrl());
            return new IncompleteStatus.Builder().responseContext(eventContext).build();
        } catch (IOException e) {
            throw new ActionExecutionResponseProcessorException(String.format(
                    "Error while redirecting to the URL: %s", url), e);
        }
    }

    private void validateOperationForIncompleteStatus(List<PerformableOperation> operationsToPerform)
            throws ActionExecutionResponseProcessorException {

        if (operationsToPerform == null) {
            throw new ActionExecutionResponseProcessorException(String.format("The list of performable operations is " +
                    "empty. For the INCOMPLETE action invocation status, there must be a REDIRECTION operation " +
                    "defined for the %s action type.", getSupportedActionType()));
        }

        if (operationsToPerform.size() != 1) {
            throw new ActionExecutionResponseProcessorException(String.format("The list of performable operations " +
                    "must contain only one operation for the INCOMPLETE action invocation status for the %s " +
                    "action type.", getSupportedActionType()));
        }

        if (!Operation.REDIRECT.equals(operationsToPerform.get(0).getOp())) {
            throw new ActionExecutionResponseProcessorException(String.format("The operation defined for the " +
                    "INCOMPLETE action invocation status must be a REDIRECTION operation for the %s action type.",
                    getSupportedActionType()));
        }

        if (operationsToPerform.get(0).getUrl() == null) {
            throw new ActionExecutionResponseProcessorException(String.format("The REDIRECTION operation defined " +
                    "for the INCOMPLETE action invocation status must have a valid URL for the %s action type.",
                    getSupportedActionType()));
        }
    }

    @Override
    public ActionExecutionStatus<Failure> processFailureResponse(Map<String, Object> eventContext,
                                                      Event actionEvent,
                                                      ActionInvocationFailureResponse failureResponse) throws
            ActionExecutionResponseProcessorException {

        return new FailedStatus(new Failure(failureResponse.getFailureReason(),
                failureResponse.getFailureDescription()));
    }

    @Override
    public ActionExecutionStatus<Error> processErrorResponse(Map<String, Object> eventContext,
                                                             Event actionEvent,
                                                             ActionInvocationErrorResponse errorResponse) throws
            ActionExecutionResponseProcessorException {

        return new ErrorStatus(new Error(errorResponse.getErrorMessage(), errorResponse.getErrorDescription()));
    }
}

