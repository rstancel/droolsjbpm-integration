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

package org.kie.server.controller.websocket.common.decoder;

import javax.websocket.DecodeException;
import javax.websocket.Decoder;
import javax.websocket.EndpointConfig;

import org.kie.server.controller.api.model.notification.KieServerControllerNotification;
import org.kie.server.controller.websocket.common.WebSocketUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KieServerControllerNotificationDecoder implements Decoder.Text<KieServerControllerNotification> {

    private static final Logger LOGGER = LoggerFactory.getLogger(KieServerControllerNotificationDecoder.class);

    @Override
    public KieServerControllerNotification decode(final String content) throws DecodeException {
        LOGGER.debug("Content received for decoding: {}",
                     content);
        return WebSocketUtils.unmarshal(content,
                                        KieServerControllerNotification.class);
    }

    @Override
    public boolean willDecode(final String content) {
        return content != null;
    }

    @Override
    public void init(final EndpointConfig config) {

    }

    @Override
    public void destroy() {

    }
}
