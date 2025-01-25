package org.wso2.carbon.identity.application.authenticator.adapter;

import org.wso2.carbon.identity.action.execution.ActionInvocationResponseClassProvider;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.ResponseData;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;

/**
 * This class extends the ResponseData of ActionInvocationSuccessResponse to deserialize the response payload
 * from the external service.
 */
public class AuthenticationInvocationResponseClassProvider implements ActionInvocationResponseClassProvider {

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    @Override
    public Class<? extends ResponseData> getSuccessResponseDataClass() {

        return AuthenticatedUserData.class;
    }
}
