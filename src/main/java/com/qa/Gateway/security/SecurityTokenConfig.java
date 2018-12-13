package com.qa.Gateway.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private JwtConfig jwtConfig;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				// make sure we use stateless session; session won't be used to store user's
				// state.
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				// handle an authorized attempts
				.exceptionHandling()
				.authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)).and()
				// Add a filter to validate the tokens with every request
				.addFilterAfter(new JwtTokenAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class)
				// authorization requests config
				.authorizeRequests()
				// allow all who are accessing "auth" service
				.antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
				// must be an admin if trying to access admin area (authentication is also
				// required here)
				.antMatchers("/tm**").hasRole("ROLE_TRAINING_MANAGER")
				.antMatchers("/trainee/update/{id}").authenticated()
				.antMatchers("/trainee/create").permitAll()
				.antMatchers("/trainee/delete/{id}").hasRole("ROLE_TRAINING_MANAGER")
				.antMatchers("/trainee/deleteCV/{cvID}").authenticated()
				.antMatchers("/trainee/uploadFile/{id}").authenticated()
				.antMatchers("/trainee/getCVByUsername/{username}").hasAnyRole("ROLE_TRAINER","ROLE_TRAINING_MANAGER")
				.antMatchers("/trainee/getCVByUsername/{username}").authenticated()
				.antMatchers("/trainee/getCVByID/{id}").hasAnyRole("ROLE_TRAINER","ROLE_TRAINING_MANAGER")
				.antMatchers("/trainee/getCVByID/{id}").authenticated()
				.antMatchers("/trainee/getTraineeByUsername/{username}").hasAnyRole("ROLE_TRAINER","ROLE_TRAINING_MANAGER")
				.antMatchers("/trainee/getAllTrainees").hasAnyRole("ROLE_TRAINER","ROLE_TRAINING_MANAGER")
				.antMatchers("/trainer/create").hasRole("ROLE_TRAINING_MANAGER")
				.antMatchers("/trainer/deleteByID/{id}").hasRole("ROLE_TRAINING_MANAGER")
				.antMatchers("/trainer/update/{id}").authenticated()
				.antMatchers("/trainer/getByID/{id}").hasRole("ROLE_TRAINING_MANAGER")
				.antMatchers("/trainer/getByID/{id}").authenticated()
				// Any other request must be authenticated
				.anyRequest().authenticated();
	}

	@Bean
	public JwtConfig jwtConfig() {
		return new JwtConfig();
	}

}
