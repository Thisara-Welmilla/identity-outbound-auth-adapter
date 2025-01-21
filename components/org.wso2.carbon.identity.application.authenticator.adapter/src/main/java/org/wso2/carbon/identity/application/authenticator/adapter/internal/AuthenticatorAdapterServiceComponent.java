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

package org.wso2.carbon.identity.application.authenticator.adapter.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.action.execution.ActionExecutionRequestBuilder;
import org.wso2.carbon.identity.action.execution.ActionExecutionResponseProcessor;
import org.wso2.carbon.identity.action.execution.ActionExecutorService;
import org.wso2.carbon.identity.action.execution.ActionInvocationResponseClassProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorAdapterService;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticationAdapterServiceImp;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticationInvocationResponseDeserializer;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticationRequestBuilder;
import org.wso2.carbon.identity.application.authenticator.adapter.AuthenticationResponseProcessor;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.application.authenticator.adapter",
        immediate = true
)
public class AuthenticatorAdapterServiceComponent {

    private static final Log log = LogFactory.getLog(AuthenticatorAdapterServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            ctxt.getBundleContext().registerService(AuthenticatorAdapterService.class,
                    new AuthenticationAdapterServiceImp(), null);
            ctxt.getBundleContext().registerService(ActionExecutionRequestBuilder.class,
                    new AuthenticationRequestBuilder(), null);
            ctxt.getBundleContext().registerService(ActionExecutionResponseProcessor.class,
                    new AuthenticationResponseProcessor(), null);
            ctxt.getBundleContext().registerService(ActionInvocationResponseClassProvider.class,
                    new AuthenticationInvocationResponseDeserializer(), null);

            if (log.isDebugEnabled()) {
                log.debug("Authentication adapter bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating Authentication adapter.", e);
        }
    }

    @Reference(
            name = "action.execution.service",
            service = ActionExecutorService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unregisterActionExecutorService"
    )
    protected void registerActionExecutionService(ActionExecutorService actionExecutorService) {

        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(actionExecutorService);
        log.debug("Registering the ActionExecutorService in AuthenticatorAdapterServiceComponent.");
    }

    protected void unregisterActionExecutorService(ActionExecutorService actionExecutorService) {

        AuthenticatorAdapterDataHolder.getInstance().setActionExecutorService(null);
        log.debug("Unregistering the ActionExecutorService in AuthenticatorAdapterServiceComponent.");
    }

    @Reference(
            name = "organization.service",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(organizationManager);
        log.debug("Set the organization management service in AuthenticatorAdapterServiceComponent.");
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        AuthenticatorAdapterDataHolder.getInstance().setOrganizationManager(null);
        log.debug("Unset organization management service in AuthenticatorAdapterServiceComponent.");
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service in AuthenticatorAdapterServiceComponent.");
        }
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the Realm Service in AuthenticatorAdapterServiceComponent.");
        }
        AuthenticatorAdapterDataHolder.getInstance().setRealmService(null);
    }
}
