/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates.
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

package org.kie.server.controller.service;

import java.util.ServiceLoader;

import org.kie.server.controller.api.service.NotificationService;
import org.kie.server.controller.api.service.NotificationServiceFactory;
import org.kie.server.controller.api.service.PersistingServerTemplateStorageService;
import org.kie.server.controller.rest.RestKieServerControllerImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StandaloneKieServerControllerImpl extends RestKieServerControllerImpl {

    private static Logger logger = LoggerFactory.getLogger(StandaloneKieServerControllerImpl.class);

    public StandaloneKieServerControllerImpl() {
        super();
        ServiceLoader<PersistingServerTemplateStorageService> storageServices = ServiceLoader.load(PersistingServerTemplateStorageService.class);
        
        if (storageServices != null && storageServices.iterator().hasNext()) {
            PersistingServerTemplateStorageService storageService = storageServices.iterator().next();
            this.setTemplateStorage(storageService.getTemplateStorage());

            logger.debug("Server template storage for standalone kie server controller is {}",
                         storageService.getTemplateStorage().toString());
        } else {
            logger.warn("No server template storage defined. Default storage: InMemoryKieServerTemplateStorage will be used");
        }

        ServiceLoader<NotificationServiceFactory> notificationServiceLoader = ServiceLoader.load(NotificationServiceFactory.class);
        if (notificationServiceLoader != null && notificationServiceLoader.iterator().hasNext()) {
            final NotificationService notificationService = notificationServiceLoader.iterator().next().getNotificationService();
            this.setNotificationService(notificationService);

            logger.debug("Notification service for standalone kie server controller is {}",
                         notificationService.toString());
        } else {
            logger.warn("Notification service not defined. Default notification: LoggingNotificationService will be used");
        }
    }

}
