package org.kie.springboot.kieserver.autoconfigure.extensions;

import org.kie.server.services.api.KieServerExtension;
import org.kie.server.services.dmn.DMNKieServerExtension;
import org.kie.server.services.impl.KieServerImpl;
import org.kie.springboot.kieserver.autoconfigure.KieServerProperties;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnClass({KieServerImpl.class})
@AutoConfigureAfter({DroolsKieServerAutoConfiguration.class})
@EnableConfigurationProperties(KieServerProperties.class)
public class DMNKieServerAutoConfiguration {

    private KieServerProperties properties;

    public DMNKieServerAutoConfiguration(KieServerProperties properties) {
        this.properties = properties;
    }

    @Bean
    @ConditionalOnMissingBean(name = "dmnServerExtension")
    @ConditionalOnProperty(name = "kieserver.dmn.enabled")
    public KieServerExtension dmnServerExtension() {

        return new DMNKieServerExtension();
    }
}
