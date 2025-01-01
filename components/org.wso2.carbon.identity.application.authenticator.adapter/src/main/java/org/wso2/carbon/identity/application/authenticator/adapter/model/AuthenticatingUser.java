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

import org.wso2.carbon.identity.action.execution.model.User;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticatorAdapterConstants;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * This class holds the authenticated user object which is communicated to the external authentication service.
 */
public class AuthenticatingUser extends User {

    private String id;
    private String idp;
    private String sub;
    private String externalId;
    private final List<UserClaim> userClaims =  new ArrayList<>();

    public AuthenticatingUser(String id){

        super(id);
    }

    public void setId(String id) {

        this.id = id;
    }

    public AuthenticatingUser(String id, AuthenticatedUser user) {

        super(id);
        sub = user.getAuthenticatedSubjectIdentifier();
        if (user.isFederatedUser()) {
            idp = AuthenticatorAdapterConstants.FED_IDP;
        } else {
            idp = AuthenticatorAdapterConstants.LOCAL_IDP;
        }

        Map<ClaimMapping, String> userAttributes = user.getUserAttributes();
        if (userAttributes != null) {
            for (ClaimMapping claimMap : userAttributes.keySet()) {
                String claimUri = claimMap.getLocalClaim().getClaimUri();
                if (AuthenticatorAdapterConstants.AuthRequestEntityPaths.EXTERNAL_ID_CLAIM.equals(claimUri)) {
                    externalId = userAttributes.get(claimMap);
                }
                userClaims.add(new UserClaim(claimUri, userAttributes.get(claimMap)));
            }
        }
    }

    public void setIdp(String idp) {
        this.idp = idp;
    }

    public String getIdp() {
        return idp;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getSub() {
        return sub;
    }

    public void setExternalId(String externalId) {
        this.externalId = externalId;
    }

    public String getExternalId() {
        return externalId;
    }

    public void setUserClaims(UserClaim userClaim) {
        userClaims.add(userClaim);
    }

    public List<UserClaim> getUserClaims() {
        return userClaims;
    }
}
