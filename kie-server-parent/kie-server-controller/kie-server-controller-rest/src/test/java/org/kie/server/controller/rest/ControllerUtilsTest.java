/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kie.server.controller.rest;

import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.kie.server.api.marshalling.MarshallingFormat;
import org.kie.server.api.model.KieContainerStatus;
import org.kie.server.api.model.KieScannerStatus;
import org.kie.server.api.model.ReleaseId;
import org.kie.server.controller.api.model.spec.Capability;
import org.kie.server.controller.api.model.spec.ContainerConfig;
import org.kie.server.controller.api.model.spec.ContainerSpec;
import org.kie.server.controller.api.model.spec.ProcessConfig;
import org.kie.server.controller.api.model.spec.RuleConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class ControllerUtilsTest {

    private static final Logger LOGGER = LoggerFactory.getLogger(ControllerUtilsTest.class);

    @Parameterized.Parameter
    public MarshallingFormat marshallingFormat;

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{{MarshallingFormat.JAXB}, {MarshallingFormat.JSON}});
    }

    @Test
    public void testContainerSpecSerialization() {
        final ContainerSpec spec = new ContainerSpec();
        spec.setId("id");
        spec.setContainerName("name");
        spec.setStatus(KieContainerStatus.STARTED);
        spec.setReleasedId(new ReleaseId("groupId",
                                         "artifactId",
                                         "1.0"));
        final ProcessConfig processConfig = new ProcessConfig("runtimeStrategy",
                                                              "kBase",
                                                              "kSession",
                                                              "mergeMode");
        spec.addConfig(Capability.PROCESS,
                       processConfig);
        final RuleConfig ruleConfig = new RuleConfig(1l,
                                                     KieScannerStatus.SCANNING);
        spec.addConfig(Capability.RULE,
                       ruleConfig);
        final String specContent = ControllerUtils.marshal(marshallingFormat.getType(),
                                                           spec);
        LOGGER.info("{} content\n{}", marshallingFormat.getType(), specContent);
        final ContainerSpec specResult = ControllerUtils.unmarshal(specContent,
                                                                   marshallingFormat.getType(),
                                                                   ContainerSpec.class);

        assertNotNull(specResult);
        assertEquals(spec,
                     specResult);
        assertEquals(spec.getId(),
                     specResult.getId());
        assertEquals(spec.getStatus(),
                     specResult.getStatus());
        assertEquals(spec.getContainerName(),
                     specResult.getContainerName());
        assertEquals(spec.getConfigs(),
                     specResult.getConfigs());
        assertEquals(spec.getReleasedId(),
                     specResult.getReleasedId());
        assertNotNull(specResult.getConfigs());
        final ContainerConfig processConfigResult = specResult.getConfigs().get(Capability.PROCESS);
        assertNotNull(processConfigResult);
        assertTrue(processConfigResult instanceof ProcessConfig);
        assertEquals(processConfig,
                     processConfigResult);
        final ContainerConfig ruleConfigResult = specResult.getConfigs().get(Capability.RULE);
        assertNotNull(ruleConfigResult);
        assertTrue(ruleConfigResult instanceof RuleConfig);
        assertEquals(ruleConfig,
                     ruleConfigResult);
    }
}
