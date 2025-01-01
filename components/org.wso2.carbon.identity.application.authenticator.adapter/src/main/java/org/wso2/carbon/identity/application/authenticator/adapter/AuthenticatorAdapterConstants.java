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

/**
 * This class holds the constants related to the authentication adapter.
 */
public class AuthenticatorAdapterConstants {

    public static final String AUTHENTICATOR_NAME = "AbstractAuthenticatorAdapter";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "externalAuthenticator";
    public static final String WSO2_CLAIM_DIALECT = "http://wso2.org/claims";
    public static final String AUTH_REQUEST = "authenticationRequest";
    public static final String AUTH_CONTEXT = "authContext";
    public static final String FLOW_ID = "flowId";
    public static final String ACTION_ID_CONFIG = "ActionId";
    public static final String AUTH_USER_TYPE = "authUserType";
    public static final String REDIRECTION_URL = "redirectionURL";
    public static final String LOCAL_IDP = "LOCAL";
    public static final String FED_IDP = "FEDERATED";

    /**
     * This holds the paths of the entities in the payload that communicate with the external authentication service.
     */
    public static class AuthRequestEntityPaths {

        public static final String USER_PATH = "/user/";
        public static final String USER_CLAIM_PATH = "/user/claims";
        public static final String USER_STORE_NAME_PATH = "/userStore/name";
        public static final String USER_ID_PATH = "/user/id";
        public static final String EXTERNAL_ID_PATH = "/user/externalId";
        public static final String SUB_PATH = "/user/sub";
        public static final String IDP_PATH = "/user/idp";
        public static final String EXTERNAL_ID_CLAIM = "http://wso2.org/claims/externalID";

        /**
         * User Type of the authenticated user communicated with the external authentication service.
         */
        public enum UserType {
            LOCAL,
            FED
        }
    }
}
