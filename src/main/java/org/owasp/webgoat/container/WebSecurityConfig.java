package org.owasp.webgoat.container;

import org.owasp.webgoat.container.users.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/** Security configuration for WebGoat. */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  private final UserService userDetailsService;

  public WebSecurityConfig(UserService userDetailsService) {
      this.userDetailsService = userDetailsService;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry security =
        http.authorizeRequests()
            .antMatchers(
                "/css/**",
                "/images/**",
                "/js/**",
                "fonts/**",
                "/plugins/**",
                "/registration",
                "/register.mvc",
                "/actuator/**")
            .permitAll()
            .anyRequest()
            .authenticated();
    security
        .and()
        .formLogin()
        .loginPage("/login")
        .defaultSuccessUrl("/welcome.mvc", true)
        .usernameParameter("username")
        .passwordParameter("password")
        .permitAll();
    security.and().logout().deleteCookies("JSESSIONID").invalidateHttpSession(true);
    security.and().csrf().disable();

    http.headers().cacheControl().disable();
    http.exceptionHandling().authenticationEntryPoint(new AjaxAuthenticationEntryPoint("/login"));
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
  }

  @Override
  @Bean
  public UserDetailsService userDetailsServiceBean() throws Exception {
    return userDetailsService;
  }

  @Override
  @Bean
  protected AuthenticationManager authenticationManager() throws Exception {
    return super.authenticationManager();
  }

  @Bean
  public BCryptPasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
