package org.engine.security;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

@Order(102)
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.cors()
        .and()
          .authorizeRequests()
            .antMatchers(HttpMethod.GET, "/user/info", "/api/foos/**")
              .hasAuthority("SCOPE_read")
            .antMatchers(HttpMethod.POST, "/api/foos")
              .hasAuthority("SCOPE_write")
            .anyRequest()
              .authenticated()
        .and()
          .oauth2ResourceServer()
            .jwt();
	}

	@Bean
	JwtDecoder jwtDecoder(OAuth2ResourceServerProperties properties) {
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(properties.getJwt().getJwkSetUri()).build();
		jwtDecoder.setClaimSetConverter(new OrganizationSubClaimAdapter());
		return jwtDecoder;
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

}
