/*
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

package org.kie.server.client.impl;

import static org.kie.server.api.rest.RestURI.DMN_URI;
import static org.kie.server.api.rest.RestURI.CONTAINER_ID;
import static org.kie.server.api.rest.RestURI.build;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.MathContext;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.kie.dmn.api.core.DMNContext;
import org.kie.dmn.api.core.DMNDecisionResult;
import org.kie.dmn.api.core.DMNResult;
import org.kie.server.api.KieServerConstants;
import org.kie.server.api.commands.CommandScript;
import org.kie.server.api.commands.DescriptorCommand;
import org.kie.server.api.marshalling.MarshallingFormat;
import org.kie.server.api.model.KieServerCommand;
import org.kie.server.api.model.ServiceResponse;
import org.kie.server.api.model.Wrapped;
import org.kie.server.api.model.dmn.DMNContextKS;
import org.kie.server.api.model.dmn.DMNModelInfoList;
import org.kie.server.api.model.dmn.DMNResultKS;
import org.kie.server.client.DMNServicesClient;
import org.kie.server.client.KieServicesConfiguration;

public class DMNServicesClientImpl extends AbstractKieServicesClientImpl implements DMNServicesClient {

        public DMNServicesClientImpl(KieServicesConfiguration config) {
            super(config);
        }

        public DMNServicesClientImpl(KieServicesConfiguration config, ClassLoader classLoader) {
            super(config, classLoader);
        }
        
        @Override
        public ServiceResponse<DMNModelInfoList> getModels(String containerId) {
            ServiceResponse<DMNModelInfoList> result = null;
            if( config.isRest() ) {
                Map<String, Object> valuesMap = new HashMap<String, Object>();
                valuesMap.put(CONTAINER_ID, containerId);
                
                result = (ServiceResponse<DMNModelInfoList>)(ServiceResponse<?>)
                        makeHttpGetRequestAndCreateServiceResponse(build(loadBalancer.getUrl(), DMN_URI, valuesMap), DMNModelInfoList.class);

            } else {
                CommandScript script = new CommandScript( Collections.singletonList(
                        (KieServerCommand) new DescriptorCommand("DMNService", "getModels", new Object[]{containerId})) );
                result = (ServiceResponse<DMNModelInfoList>) executeJmsCommand( script, DescriptorCommand.class.getName(), KieServerConstants.CAPABILITY_DMN, containerId ).getResponses().get(0);

                throwExceptionOnFailure( result );
                if (shouldReturnWithNullResponse(result)) {
                    return null;
                }
            }
            
            return result;
        }
        
        @Override
        public ServiceResponse<DMNResult> evaluateAll(String containerId, DMNContext dmnContext) {
            return evaluateAll(containerId, null, null, dmnContext);
        }

        @Override
        public ServiceResponse<DMNResult> evaluateAll(String containerId, String namespace, String modelName, DMNContext dmnContext) {
            DMNContextKS payload = new DMNContextKS(namespace, modelName, dmnContext.getAll()); 
            return evaluateDecisions(containerId, payload);
        }
        
        @Override
        public ServiceResponse<DMNResult> evaluateDecisionByName(String containerId, String namespace, String modelName, String decisionName, DMNContext dmnContext) {
            Objects.requireNonNull(decisionName, "Parameter decisionName cannot be null; method evaluateAllDecisions() can be used to avoid the need of supplying decisionName");
            DMNContextKS payload = new DMNContextKS(namespace, modelName, dmnContext.getAll()); 
            payload.setDecisionNames(Collections.singletonList(decisionName));
            return evaluateDecisions(containerId, payload);
        }

        @Override
        public ServiceResponse<DMNResult> evaluateDecisionById(String containerId, String namespace, String modelName, String decisionId, DMNContext dmnContext) {
            Objects.requireNonNull(decisionId, "Parameter decisionId cannot be null; method evaluateAllDecisions() can be used to avoid the need of supplying decisionId");
            DMNContextKS payload = new DMNContextKS(namespace, modelName, dmnContext.getAll()); 
            payload.setDecisionIds(Collections.singletonList(decisionId));
            return evaluateDecisions(containerId, payload);
        }

        /**
         * Please notice this method is NOT exposed to the API interface.
         */
        // DO NOT ADD @Override
        public ServiceResponse<DMNResult> evaluateDecisions(String containerId, DMNContextKS payload) {
            ServiceResponse<DMNResult> result = null;
            if( config.isRest() ) {
                Map<String, Object> valuesMap = new HashMap<String, Object>();
                valuesMap.put(CONTAINER_ID, containerId);
                
                result = (ServiceResponse<DMNResult>)(ServiceResponse<?>) makeHttpPostRequestAndCreateServiceResponse(
                        build(loadBalancer.getUrl(), DMN_URI, valuesMap), payload, DMNResultKS.class);

            } else {
                CommandScript script = new CommandScript( Collections.singletonList(
                        (KieServerCommand) new DescriptorCommand("DMNService", "evaluateDecisions", serialize(payload), marshaller.getFormat().getType(), new Object[]{containerId})) );
                result = (ServiceResponse<DMNResult>) executeJmsCommand( script, DescriptorCommand.class.getName(), KieServerConstants.CAPABILITY_DMN, containerId ).getResponses().get(0);

                throwExceptionOnFailure( result );
                if (shouldReturnWithNullResponse(result)) {
                    return null;
                }
            }

            if (result instanceof Wrapped) {
                return (ServiceResponse<DMNResult>) ((Wrapped) result).unwrap();
            }
            ServiceResponse<DMNResult> result2 = (ServiceResponse<DMNResult>) result;
            
            // coerce numbers to BigDecimal as per DMN spec.
            // alternative to the below will require instructing special config of kie-server JSONMarshaller
            // to manage scalar values when deserializing from JSON always as a BigDecimal instead of default Jackson NumberDeserializers
            if ( config.getMarshallingFormat() == MarshallingFormat.JSON ) {
                recurseAndModifyByCoercingNumbers(result2.getResult().getContext());
                for ( DMNDecisionResult dr : result2.getResult().getDecisionResults() ) {
                    recurseAndModifyByCoercingNumbers( dr.getResult() );
                }
            }
            
            return result2;
        }
        
        private static Object recurseAndModifyByCoercingNumbers(Object result) {
            if ( result instanceof DMNContext ) {
                DMNContext ctx = (DMNContext) result;
                ctx.getAll().replaceAll( (k, v) -> recurseAndModifyByCoercingNumbers(v) );
                return ctx;
            } else if ( result instanceof Map<?, ?> ) {
                ((Map) result).replaceAll( (k, v) -> recurseAndModifyByCoercingNumbers(v) );
            } else if ( result instanceof List<?> ) {
                ((List<Object>) result).replaceAll( DMNServicesClientImpl::recurseAndModifyByCoercingNumbers );
                return result;
            } else if ( result instanceof Set<?> ) {
                Set<?> originalSet = (Set<?>) result;
                Collection mappedSet = originalSet.stream().map( DMNServicesClientImpl::recurseAndModifyByCoercingNumbers ).collect(Collectors.toSet());
                originalSet.clear();
                originalSet.addAll(mappedSet);
                return result;
            } else if ( result instanceof Number ) {
                return coerceNumber(result);
            }
            return result;
        }

        @Override
        public DMNContext newContext() {
            // in order to leverage the already existing client inner private class
            return new DMNResultKS().getContext();
        }
        
        // copied from DMN FEEL utils
        private static BigDecimal getBigDecimalOrNull(Object value) {
            if ( !(value instanceof Number || value instanceof String) ) {
                return null;
            }
            if ( !BigDecimal.class.isAssignableFrom( value.getClass() ) ) {
                if ( value instanceof Long || value instanceof Integer || value instanceof Short || value instanceof Byte ||
                     value instanceof AtomicLong || value instanceof AtomicInteger ) {
                    value = new BigDecimal( ((Number) value).longValue(), MathContext.DECIMAL128 );
                } else if ( value instanceof BigInteger ) {
                    value = new BigDecimal( ((BigInteger) value).toString(), MathContext.DECIMAL128 );
                } else if ( value instanceof String ) {
                    // we need to remove leading zeros to prevent octal conversion
                    value = new BigDecimal( ((String) value).replaceFirst("^0+(?!$)", ""), MathContext.DECIMAL128 );
                } else {
                    value = new BigDecimal( ((Number) value).doubleValue(), MathContext.DECIMAL128 );
                }
            }
            return (BigDecimal) value;
        }
        // copied from DMN FEEL utils
        private static Object coerceNumber(Object value) {
            if ( value instanceof Number && !(value instanceof BigDecimal) ) {
                return getBigDecimalOrNull( value );
            } else {
                return value;
            }
        }

}
