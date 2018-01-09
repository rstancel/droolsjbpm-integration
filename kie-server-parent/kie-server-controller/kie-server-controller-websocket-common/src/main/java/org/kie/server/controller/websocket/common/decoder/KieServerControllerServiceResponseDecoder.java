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

package org.kie.server.controller.websocket.common.decoder;

import javax.websocket.DecodeException;
import javax.websocket.Decoder;
import javax.websocket.EndpointConfig;

import org.kie.server.controller.api.model.KieServerControllerServiceResponse;
import org.kie.server.controller.websocket.common.WebSocketUtils;

public class KieServerControllerServiceResponseDecoder implements Decoder.Text<KieServerControllerServiceResponse> {

    @Override
    public KieServerControllerServiceResponse decode(final String content) throws DecodeException {
        return WebSocketUtils.unmarshal(content,
                                        KieServerControllerServiceResponse.class);
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
