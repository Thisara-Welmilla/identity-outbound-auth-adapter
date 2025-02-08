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

package org.wso2.carbon.identity.application.authenticator.adapter.model;

/**
 * This class represents the result of the execution of an authentication action response.
 * It includes the field path of the item executed in the authentication action response, along with its availability,
 * validity, and a message.
 */
public class AuthenticationActionExecutionResult {

    private static final String FIELD_BASED_PATH = "data/user/";

    private final String fieldName;
    private final String message;
    private final Validity validity;
    private final Availability availability;

    public AuthenticationActionExecutionResult(String fieldName, Availability availability, Validity validity,
                                               String message) {

        this.fieldName = fieldName;
        this.validity = validity;
        this.message = message;
        this.availability = availability;
    }

    public String getFieldPath() {

        return FIELD_BASED_PATH + fieldName;
    }

    public Validity getValidity() {

        return validity;
    }

    public String getMessage() {

        return message;
    }

    public Availability getAvailability() {

        return availability;
    }

    public String getFieldName() {

        return fieldName;
    }

    /**
     * Enum to represent the validity of the field value in the authentication action response.
     */
    public enum Validity {
        VALID, INVALID
    }

    /**
     * Enum to represent the availability of the field in the authentication action response.
     */
    public enum Availability {
        AVAILABLE, UNAVAILABLE
    }
}
