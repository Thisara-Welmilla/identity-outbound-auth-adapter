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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.wso2.carbon.identity.action.execution.model.*;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;

import java.util.ArrayList;
import java.util.List;

public class ActionInvocationResponseBuilder {

    /**
     * Build an action invocation error response.
     *
     * @return ActionInvocationResponse
     */
    public static ActionInvocationErrorResponse buildActionInvocationErrorResponse() {

        return new ActionInvocationErrorResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.ERROR)
                .errorMessage("error-1")
                .errorDescription("error description").build();
    }

    /**
     * Build an action invocation failure response.
     *
     * @return ActionInvocationResponse
     */
    public static ActionInvocationFailureResponse buildActionInvocationFailureResponse() {

        return new ActionInvocationFailureResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.FAILED)
                .failureReason("failure-1")
                .failureDescription("failure description").build();
    }

    /**
     * Build an action invocation success response for success authentication with external service.
     *
     * @return ActionInvocationResponse
     */
    public static ActionInvocationSuccessResponse buildAuthenticationSuccessResponse(
            List<PerformableOperation> operations, ResponseData data) {

        return new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.SUCCESS)
                .operations(operations)
                .context(data)
                .build();
    }

    /**
     * Build an action invocation success response for redirection.
     *
     * @return ActionInvocationResponse
     */
    public static ActionInvocationSuccessResponse buildAuthenticationRedirectResponse(
            List<PerformableOperation> operations) {

        return new ActionInvocationSuccessResponse.Builder()
                .actionStatus(ActionInvocationResponse.Status.INCOMPLETE)
                .operations(operations)
                .build();
    }

    public static class ExternallyAuthenticatedUser {

        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticatedUserData.Claim claim1 = new AuthenticatedUserData.Claim("claim-1", "value-1");
        AuthenticatedUserData.Claim  claim2 = new AuthenticatedUserData.Claim ("claim-2", "value-2");

        private String id;
        private List<String> groups;
        private List<AuthenticatedUserData.Claim> claims;
        private UserStore userStore;

        public ExternallyAuthenticatedUser() {

            id = "default-id";
            groups = new ArrayList<>();
            claims = new ArrayList<>(List.of(claim1, claim2));
        }

        public void setId(String id) {

            this.id = id;
        }

        public void setGroups(List<String> groups) {

            this.groups = groups;
        }

        public void setClaims(List<AuthenticatedUserData.Claim> claims) {

            this.claims = claims;
        }

        public String getId() {

            return id;
        }

        public List<String> getGroups() {

            return groups;
        }

        public List<AuthenticatedUserData.Claim> getClaims() {

            return claims;
        }

        public void setUserStore(UserStore userStore) {

            this.userStore = userStore;
        }

        public UserStore getUserStore() {

            return userStore;
        }

        public String covertJsonString() throws JsonProcessingException {

            objectMapper.setSerializationInclusion((JsonInclude.Include.NON_NULL));
            return objectMapper.writeValueAsString(this);
        }
    }
}
