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

package org.wso2.carbon.identity.application.authenticator.adapter.model;

import org.wso2.carbon.identity.action.execution.model.Header;
import org.wso2.carbon.identity.action.execution.model.Param;
import org.wso2.carbon.identity.action.execution.model.Request;

import java.util.List;

/**
 * This class holds the authentication request object which is communicated to the external authentication service.
 */
public class AuthenticationRequest extends Request {

    public AuthenticationRequest(List<Header> additionalHeaders, List<Param> additionalParams) {

        this.additionalHeaders = additionalHeaders;
        this.additionalParams  = additionalParams;
    }
}
