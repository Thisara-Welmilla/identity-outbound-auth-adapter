package org.wso2.carbon.identity.application.authenticator.adapter;

import org.wso2.carbon.identity.action.execution.ActionInvocationResponseClassProvider;
import org.wso2.carbon.identity.action.execution.model.ActionType;
import org.wso2.carbon.identity.action.execution.model.ResponseData;
import org.wso2.carbon.identity.application.authenticator.adapter.model.AuthenticatedUserData;

public class AuthenticationInvocationResponseDeserializer implements ActionInvocationResponseClassProvider {

    @Override
    public ActionType getSupportedActionType() {

        return ActionType.AUTHENTICATION;
    }

    /**
     * Deserialize the action invocation response.
     *
     * @return The JsonDeserializer.
     */
    @Override
    public Class<? extends ResponseData> getSuccessResponseContextClass() {

        return AuthenticatedUserData.class;
    }
}
