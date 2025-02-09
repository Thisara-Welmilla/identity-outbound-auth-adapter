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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.action.execution.ActionExecutionLogConstants;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticationActionExecutionResult;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

/**
 * This class is responsible for logging diagnostic logs related to the authentication action response execution.
 */
public class DiagnosticLogger {

    /**
     * Logs the diagnostic log for the data validation error in the authentication action response with SUCCESS status.
     *
     * @param executionResult The authentication action response execution result.
     */
    public static void logSuccessResponseDataValidationError(
            AuthenticationActionExecutionResult executionResult) {

        logResponseExecutionResult(executionResult, DiagnosticLog.ResultStatus.FAILED,
                String.format("An error occurred while handling the authentication action " +
                        "response for the %s field.", executionResult.getFieldName()));
    }

    /**
     * Logs the diagnostic log for defaults for missing data in the authentication action response with SUCCESS status.
     *
     * @param executionResult The authentication action response execution result.
     */
    public static void logSuccessResponseWithDefaultsForMissingData(
            AuthenticationActionExecutionResult executionResult) {

        logResponseExecutionResult(executionResult, DiagnosticLog.ResultStatus.SUCCESS,
                String.format("Since the %s field is missing from the authentication action " +
                        "response, the default value is used.", executionResult.getFieldName()));
    }

    /**
     * Logs the diagnostic log for the ignored data in the authentication action response with SUCCESS status.
     *
     * @param executionResult The authentication action response execution result.
     * @param userType        The user type.
     */
    public static void logSuccessResponseWithIgnoredData(
            AuthenticationActionExecutionResult executionResult, String userType) {

        logResponseExecutionResult(executionResult, DiagnosticLog.ResultStatus.SUCCESS,
                String.format("The %s field in the authentication action response is not applicable for %s user. " +
                        "Hence, this field will be ignored.", executionResult.getFieldName(), userType));
    }

    /**
     * Logs the diagnostic log for the authentication action response executing with INCOMPLETE status.
     *
     * @param executionResult The authentication action response execution result.
     */
    public static void logIncompleteResponseExecutionResult(
            AuthenticationActionExecutionResult executionResult) {

        logResponseExecutionResult(executionResult, DiagnosticLog.ResultStatus.FAILED,
                "The authentication action response processing failed due to an invalid response " +
                        "for the INCOMPLETE status.");
    }

    private static void logResponseExecutionResult(AuthenticationActionExecutionResult executionResult,
                                                   DiagnosticLog.ResultStatus resultStatus, String message) {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {

            DiagnosticLog.DiagnosticLogBuilder diagLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    ActionExecutionLogConstants.ACTION_EXECUTION_COMPONENT_ID,
                    ActionExecutionLogConstants.ActionIDs.PROCESS_ACTION_RESPONSE);
            diagLogBuilder
                    .inputParam(StringUtils.EMPTY, executionResult)
                    .resultMessage(message)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(resultStatus)
                    .build();
            LoggerUtils.triggerDiagnosticLogEvent(diagLogBuilder);
        }
    }
}
