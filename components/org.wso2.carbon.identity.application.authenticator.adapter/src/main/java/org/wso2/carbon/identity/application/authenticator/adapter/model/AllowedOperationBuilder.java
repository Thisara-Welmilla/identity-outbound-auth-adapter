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

import org.wso2.carbon.identity.action.execution.model.AllowedOperation;
import org.wso2.carbon.identity.action.execution.model.Operation;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * This class holds the operations that allowed to perform on the AuthenticationContext object and communicate to the
 * external authentication service.
 */
public class AllowedOperationBuilder {

    private final AllowedOperation redirectOperations;

    public AllowedOperationBuilder() {

        redirectOperations = redirectOperations();
    }

    private AllowedOperation redirectOperations() {

        return createAllowedOperation(Operation.REDIRECT, null);
    }

    private AllowedOperation createAllowedOperation(Operation op, List<String> paths) {

        AllowedOperation operation = new AllowedOperation();
        operation.setOp(op);
        if (paths != null) {
            operation.setPaths(new ArrayList<>(paths));
        }
        return operation;
    }

    /**
     * Get allowed operations for the external authentication service based on the current authentication context.
     *
     * @return ActionExecutorService instance.
     */
    public List<AllowedOperation> getAllowedOperations() {

        return Collections.singletonList(redirectOperations);
    }
}
