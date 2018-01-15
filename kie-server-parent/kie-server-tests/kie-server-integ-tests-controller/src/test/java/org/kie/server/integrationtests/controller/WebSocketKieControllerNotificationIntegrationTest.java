/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates.
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

package org.kie.server.integrationtests.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.concurrent.Executors;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.kie.server.api.model.KieContainerStatus;
import org.kie.server.api.model.ReleaseId;
import org.kie.server.client.KieServicesClient;
import org.kie.server.controller.api.model.spec.ContainerSpec;
import org.kie.server.controller.api.model.spec.ServerTemplate;
import org.kie.server.controller.api.model.spec.ServerTemplateList;
import org.kie.server.controller.client.KieServerControllerClient;
import org.kie.server.controller.client.KieServerControllerClientFactory;
import org.kie.server.controller.client.event.EventHandler;
import org.kie.server.integrationtests.config.TestConfig;
import org.kie.server.integrationtests.shared.KieServerAssert;
import org.kie.server.integrationtests.shared.KieServerDeployer;
import org.kie.server.integrationtests.shared.KieServerExecutor;
import org.kie.server.integrationtests.shared.basetests.KieServerBaseIntegrationTest;
import org.mockito.InOrder;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

public class WebSocketKieControllerNotificationIntegrationTest extends KieServerBaseIntegrationTest {

    private static final ReleaseId releaseId = new ReleaseId("org.kie.server.testing",
                                                             "stateless-session-kjar",
                                                             "1.0.0");

    private static final String CONTAINER_ID = "kie-concurrent";
    private static final String CONTAINER_NAME = "containerName";

    KieServerControllerClient controllerClient;

    EventHandler eventHandler;

    @BeforeClass
    public static void initialize() throws Exception {
        KieServerDeployer.buildAndDeployCommonMavenParent();
        KieServerDeployer.buildAndDeployMavenProject(ClassLoader.class.getResource("/kjars-sources/stateless-session-kjar").getFile());
    }

    @Override
    protected KieServicesClient createDefaultClient() {
        return null;
    }

    @Before
    @Override
    public void setup() throws Exception {
        super.setup();
        disposeAllContainers();
        disposeAllServerInstances();
        eventHandler = mock(EventHandler.class);
        if (TestConfig.isLocalServer()) {
            controllerClient = KieServerControllerClientFactory.newWebSocketClient(TestConfig.getControllerWebSocketManagementUrl(),
                                                                                   null,
                                                                                   null,
                                                                                   eventHandler);
        } else {
            controllerClient = KieServerControllerClientFactory.newWebSocketClient(TestConfig.getControllerWebSocketManagementUrl(),
                                                                                   TestConfig.getUsername(),
                                                                                   TestConfig.getPassword(),
                                                                                   eventHandler);
        }
    }

    @After
    public void closeControllerClient() {
        if (controllerClient != null) {
            try {
                logger.info("Closing Kie Server Management Controller client");
                controllerClient.close();
            } catch (IOException e) {
                logger.error("Error trying to close Kie Server Management Controller Client: {}",
                             e.getMessage(),
                             e);
            }
        }
    }

    @Test(timeout = 30 * 1000)
    public void testServerTemplateEvents() throws Exception {
        runAsync(() -> {
            // Check that there are no kie servers deployed in controller.
            ServerTemplateList instanceList = controllerClient.listServerTemplates();
            assertNotNull(instanceList);
            KieServerAssert.assertNullOrEmpty("Active kie server instance found!",
                                              instanceList.getServerTemplates());

            // Create new server template
            ServerTemplate template = new ServerTemplate("notification-int-test",
                                                         "Notification Test Server");
            controllerClient.saveServerTemplate(template);

            // Check that kie server is registered in controller.
            instanceList = controllerClient.listServerTemplates();
            assertNotNull(instanceList);
            assertEquals(1,
                         instanceList.getServerTemplates().length);

            // Delete server template
            controllerClient.deleteServerTemplate(template.getId());
        });

        InOrder inOrder = inOrder(eventHandler);
        inOrder.verify(eventHandler).onServerTemplateUpdated(any());
        inOrder.verify(eventHandler).onServerTemplateDeleted(any());

        verifyNoMoreInteractions(eventHandler);
    }

    @Test(timeout = 60 * 1000)
    public void testKieServerEvents() throws Exception {
        runAsync(() -> {
            // Check that there are no kie servers deployed in controller.
            ServerTemplateList instanceList = controllerClient.listServerTemplates();
            assertNotNull(instanceList);
            KieServerAssert.assertNullOrEmpty("Active kie server instance found!",
                                              instanceList.getServerTemplates());

            // Turn on new kie server.
            server = new KieServerExecutor();
            server.startKieServer();

            // Check that kie server is registered in controller.
            instanceList = controllerClient.listServerTemplates();
            assertNotNull(instanceList);
            assertEquals(1,
                         instanceList.getServerTemplates().length);

            ServerTemplate template = instanceList.getServerTemplates()[0];

            //Deploy container to Kie Server
            ContainerSpec containerSpec = new ContainerSpec(CONTAINER_ID,
                                                            CONTAINER_NAME,
                                                            template,
                                                            releaseId,
                                                            KieContainerStatus.STOPPED,
                                                            new HashMap());
            controllerClient.saveContainerSpec(template.getId(),
                                               containerSpec);
            controllerClient.startContainer(containerSpec);

            controllerClient.stopContainer(containerSpec);

            controllerClient.deleteContainerSpec(template.getId(),
                                                 containerSpec.getId());

            server.stopKieServer();
        });

        InOrder inOrder = inOrder(eventHandler);
        //Connect
        inOrder.verify(eventHandler).onServerTemplateUpdated(any());
        inOrder.verify(eventHandler).onServerInstanceUpdated(any());
        inOrder.verify(eventHandler).onServerInstanceConnected(any());

        //Create container
        inOrder.verify(eventHandler).onServerTemplateUpdated(any());

        //Start and stop container
        inOrder.verify(eventHandler,
                       times(2)).onContainerSpecUpdated(any());

        //Delete container
        inOrder.verify(eventHandler).onServerTemplateUpdated(any());

        //Disconnect
        inOrder.verify(eventHandler).onServerInstanceDeleted(any());
        inOrder.verify(eventHandler).onServerTemplateUpdated(any());
        inOrder.verify(eventHandler).onServerInstanceDisconnected(any());

        verifyNoMoreInteractions(eventHandler);
    }

    protected void runAsync(final Runnable runnable) throws Exception {
        Executors.newSingleThreadExecutor().submit(runnable).get();
    }
}
