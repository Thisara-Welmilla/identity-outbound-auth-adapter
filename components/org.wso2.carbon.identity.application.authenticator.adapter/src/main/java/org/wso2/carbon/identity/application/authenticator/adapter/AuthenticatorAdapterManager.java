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

import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.LocalAuthenticatorConfig;

import java.util.ArrayList;
import java.util.List;

/**
 * This class is used to manage the authenticator adapters for user defined authenticators.
 */
public class AuthenticatorAdapterManager {

    private final List<FederatedAuthenticatorAdapter> federatedAuthenticatorAdapterList = new ArrayList<>();
    private final List<LocalAuthenticatorAdapter> localAuthenticatorAdapters = new ArrayList<>();

    public FederatedAuthenticatorAdapter getFederatedAuthenticatorAdapter(FederatedAuthenticatorConfig config) {

        for (FederatedAuthenticatorAdapter adapter : federatedAuthenticatorAdapterList) {
            if (adapter.getName().equals(config.getName())) {
                return adapter;
            }
        }
        FederatedAuthenticatorAdapter federatedAuthenticatorAdapter =  new FederatedAuthenticatorAdapter(config);
        federatedAuthenticatorAdapterList.add(federatedAuthenticatorAdapter);
        return federatedAuthenticatorAdapter;
    }

    public LocalAuthenticatorAdapter getLocalAuthenticatorAdapter(LocalAuthenticatorConfig config) {

        for (LocalAuthenticatorAdapter adapter : localAuthenticatorAdapters) {
            if (adapter.getName().equals(config.getName())) {
                return adapter;
            }
        }
        LocalAuthenticatorAdapter localAuthenticatorAdapter =  new LocalAuthenticatorAdapter(config);
        localAuthenticatorAdapters.add(localAuthenticatorAdapter);
        return localAuthenticatorAdapter;
    }
}
