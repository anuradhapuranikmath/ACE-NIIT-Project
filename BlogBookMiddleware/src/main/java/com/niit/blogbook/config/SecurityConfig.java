package com.niit.blogbook.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	DataSource dataSource;
	@Autowired
	public void configAuthentication(AuthenticationManagerBuilder auth) throws Exception {
             System.out.println("Inside the configauthentication");
             System.out.println("data source:"+dataSource);
	  auth.jdbcAuthentication().dataSource(dataSource)
		.usersByUsernameQuery(
			"select username,password,enabled from userdetail where username=?")
		.authoritiesByUsernameQuery(
			"select u1.username, u2.role from userdetail u1 where u1.username =?");
	}
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		 System.out.println("Inside the configure");
	  http.authorizeRequests()
		.antMatchers("/user/**").access("hasRole('admin')")
		.and()
		  .formLogin().loginPage("/checkLogin").loginProcessingUrl("/j_spring_security_check").defaultSuccessUrl("/").failureUrl("/log?error").usernameParameter("username").passwordParameter("password")
		.and()
		  .logout().logoutSuccessUrl("/log?logout")
		.and()
		  .exceptionHandling().accessDeniedPage("/403")
		.and()
		  .csrf();
	  http.authorizeRequests()
		.antMatchers("/admin/**").access("hasRole('student')")
		.and()
		  .formLogin().loginPage("/login").loginProcessingUrl("/j_spring_security_check").defaultSuccessUrl("/").failureUrl("/log?error").usernameParameter("username").passwordParameter("password")
		.and()
		  .logout().logoutSuccessUrl("/log?logout")
		.and()
		  .exceptionHandling().accessDeniedPage("/403")
		.and()
		  .csrf();
	  
	  System.out.println("endof configure");
	}

}
