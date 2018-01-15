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

package org.kie.server.controller.websocket.common;

import java.util.function.Consumer;
import javax.websocket.EndpointConfig;
import javax.websocket.Session;

import org.kie.server.controller.api.model.events.KieServerControllerEvent;
import org.kie.server.controller.websocket.common.handlers.KieServerControllerNotificationMessageHandler;

public class KieServerControllerNotificationWebSocketClient extends WebSocketClientImpl<KieServerControllerNotificationMessageHandler> {

    private Consumer<KieServerControllerEvent> eventConsumer;

    public KieServerControllerNotificationWebSocketClient() {
        super();
    }

    public KieServerControllerNotificationWebSocketClient(final Consumer<KieServerControllerEvent> eventConsumer,
                                                          final Consumer<WebSocketClient> onReconnect) {
        super(onReconnect);
        this.eventConsumer = eventConsumer;
    }

    public KieServerControllerNotificationWebSocketClient(final Consumer<KieServerControllerEvent> eventConsumer) {
        super();
        this.eventConsumer = eventConsumer;
    }

    @Override
    public void onOpen(final Session session,
                       final EndpointConfig config) {
        this.messageHandler = new KieServerControllerNotificationMessageHandler(notification -> eventConsumer.accept(notification.getEvent()));
        super.onOpen(session,
                     config);
    }
}
