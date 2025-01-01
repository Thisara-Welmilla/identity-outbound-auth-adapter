/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.action.execution.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.exception.ActionExecutionResponseProcessorException;
import org.wso2.carbon.identity.action.execution.model.*;
import org.wso2.carbon.identity.action.execution.model.Error;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatingUser;
import org.wso2.carbon.identity.application.authenticator.adapter.model.UserClaim;
import org.wso2.carbon.identity.application.authenticator.adapter.util.OperationExecutionResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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

        AuthenticationContext context = (AuthenticationContext) eventContext.get(
                AuthenticatorAdapterConstants.AUTH_CONTEXT);
        ActionInvocationResponse.Status actionStatus = actionInvocationSuccessResponse.getActionStatus();
        Map<String, OperationExecutionResult> operationExecutionResults = new HashMap<>();
        AuthenticatedUserBuilder authenticatedUserBuilder = new AuthenticatedUserBuilder();

        List<PerformableOperation> operationsToPerform = actionInvocationSuccessResponse.getOperations();
        try {
            AuthenticatingUser authenticatingUser = new AuthenticatingUser(StringUtils.EMPTY);
            UserStore userStore = new UserStore(StringUtils.EMPTY);
            if (operationsToPerform != null) {

                // Check whether any of operation have redirection. If so return execution state as INCOMPLETE.
                ActionExecutionStatus status = handleRedirection(operationsToPerform, eventContext);
                if (status != null) {
                    return status;
                }

                for (PerformableOperation operation : operationsToPerform) {
                    performOperation(operation, authenticatingUser, userStore, operationExecutionResults);
                }
            }
            authenticatedUserBuilder.setAuthenticatingUser(authenticatingUser);
            authenticatedUserBuilder.setOperationExecutionResult(operationExecutionResults);
            context.setSubject(authenticatedUserBuilder.createAuthenticateduser(
                    authenticatingUser, context, userStore));
        } finally {
            logOperationExecutionResults(getSupportedActionType(),
                    new ArrayList<>(authenticatedUserBuilder.getOperationExecutionResult().values()));
        }
        return new SuccessStatus.Builder().setResponseContext(eventContext).build();
    }

    private ActionExecutionStatus<Success> handleRedirection(List<PerformableOperation> operationsToPerform,
                                                    Map<String, Object> eventContext ) {

        for (PerformableOperation operation : operationsToPerform) {
            if (Operation.REDIRECT.getValue().equals(operation.getOp())) {
                eventContext.put(AuthenticatorAdapterConstants.REDIRECTION_URL, operation.getValue());
                new SuccessStatus.Builder().setResponseContext(eventContext).build();
            }
        }

        return null;
    }

    @Override
    public ActionExecutionStatus<Failure> processFailureResponse(Map<String, Object> eventContext,
                                                      Event actionEvent,
                                                      ActionInvocationFailureResponse failureResponse) throws
            ActionExecutionResponseProcessorException {

        return new FailedStatus(new Failure(failureResponse.getFailureReason(),
                failureResponse.getFailureDescription()));
    }

    private void logOperationExecutionResults(ActionType actionType,
                                              List<OperationExecutionResult> operationExecutionResultList) {

        //TODO: need to add to diagnostic logs
        if (LOG.isDebugEnabled()) {
            ObjectMapper objectMapper = new ObjectMapper();
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
            objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
            try {
                String executionSummary = objectMapper.writeValueAsString(operationExecutionResultList);
                LOG.debug(String.format("Processed response for action type: %s. Results of operations performed: %s",
                        actionType, executionSummary));
            } catch (JsonProcessingException e) {
                LOG.debug("Error occurred while logging operation execution results.", e);
            }
        }
    }

    @Override
    public ActionExecutionStatus<Error> processErrorResponse(Map<String, Object> eventContext,
                                                             Event actionEvent,
                                                             ActionInvocationErrorResponse errorResponse) throws
            ActionExecutionResponseProcessorException {

        return new ErrorStatus(new Error(errorResponse.getErrorMessage(), errorResponse.getErrorDescription()));
    }

    /**
     * Validate the given performableOperation and apply it to the user attribute.
     *
     * @param performableOperation  PerformableOperation from the external authentication service response.
     */
    private void performOperation(PerformableOperation performableOperation, AuthenticatingUser authRequestUser,
                        UserStore userStoreDomain, Map<String, OperationExecutionResult> operationExecutionResults)
                        throws ActionExecutionResponseProcessorException {

        String operationPath = performableOperation.getPath();
        try {
            switch (operationPath) {
                case AuthenticatorAdapterConstants.AuthRequestEntityPaths.USER_ID_PATH:
                    authRequestUser.setId(castToString(performableOperation.getValue()));
                    operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation));
                    break;
                case AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_PATH:
                    authRequestUser.setExternalId(castToString(performableOperation.getValue()));
                    operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation));
                    break;
                case AuthenticatorAdapterConstants.AuthRequestEntityPaths.IDP_PATH:
                    authRequestUser.setIdp(castToString(performableOperation.getValue()));
                    operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation));
                    break;
                case AuthenticatorAdapterConstants.AuthRequestEntityPaths.SUB_PATH:
                    authRequestUser.setSub(castToString(performableOperation.getValue()));
                    operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation));
                    break;
                case AuthenticatorAdapterConstants.AuthRequestEntityPaths.USER_CLAIM_PATH:
                    UserClaim userClaim = castToClaim(performableOperation.getValue());
                    if (userClaim != null) {
                        authRequestUser.setUserClaims(userClaim);
                        operationExecutionResults.put(operationPath,
                                new OperationExecutionResult(performableOperation));
                    } else {
                        operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation,
                                OperationExecutionResult.Status.IGNORE, "Claim is ignored and will not set to " +
                                    "the authentication context as it is not in accepted format"));
                    }
                    break;
                case AuthenticatorAdapterConstants.AuthRequestEntityPaths.USER_STORE_NAME_PATH:
                    userStoreDomain.setName(castToString(performableOperation.getValue()));
                    operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation));
                    break;
                default:
                    operationExecutionResults.put(operationPath, new OperationExecutionResult(performableOperation));
                    break;
            }
        } catch (ActionExecutionResponseProcessorException e) {
            OperationExecutionResult result = new OperationExecutionResult(performableOperation,
                    OperationExecutionResult.Status.FAILURE,
                    "The input is not in valid format, unable to cast to String: " + performableOperation.getValue() );
            operationExecutionResults.put(operationPath, result);
            throw e;
        }
    }

    /**
     * Cast the given object to String.
     *
     * @param object    Object that need to cast.
     * @return String which cast to the String class.
     * @throws ActionExecutionResponseProcessorException If object cannot be cast to String.
     */
    private String castToString(Object object)
            throws ActionExecutionResponseProcessorException {

        try {
            return objectMapper.convertValue(object, String.class);
        } catch (IllegalArgumentException e) {
            throw new ActionExecutionResponseProcessorException("The provided value cannot be cast to a string:" +
                    object, e);
        }
    }

    /**
     * Cast the given object to a claim.
     *
     * @param object    Object that need to cast.
     * @return userClaim which casted to the UserClaim class.
     */
    private UserClaim castToClaim(Object object) {

        try {
            return objectMapper.convertValue(object, UserClaim.class);
        } catch (IllegalArgumentException e) {
            // Not throwing an error and ignore as this is just a claim.
            return null;
        }
    }
}

