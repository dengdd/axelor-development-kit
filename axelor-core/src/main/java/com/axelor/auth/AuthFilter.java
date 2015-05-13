/**
 * Axelor Business Solutions
 *
 * Copyright (C) 2005-2014 Axelor (<http://axelor.com>).
 *
 * This program is free software: you can redistribute it and/or  modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.axelor.auth;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.filter.PathMatchingFilter;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;

import com.axelor.db.Query;
import com.axelor.meta.db.MetaFilterChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.Injector;
import com.google.inject.Key;

public class AuthFilter extends FormAuthenticationFilter {

	@Inject
	@Named("app.loginUrl")
	private String loginUrl;
	
	@Inject
	private Injector injector;

	@Override
	public String getLoginUrl() {
		if (loginUrl != null) {
			return loginUrl;
		}
		return super.getLoginUrl();
	}
	
	@Override
	public boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
		List<MetaFilterChain> filterChains = Query.of(MetaFilterChain.class).cacheable().order("sortOrder").fetch();
		if (filterChains != null && !filterChains.isEmpty()) {
			for (MetaFilterChain chain : filterChains) {
				if (pathsMatch(chain.getPattern(), request)) {
					PathMatchingFilter filter = (PathMatchingFilter) injector.getInstance(Key.get(Class.forName(chain.getType())));
					Method method = filter.getClass().getDeclaredMethod("onPreHandle", ServletRequest.class, ServletResponse.class, Object.class);
					method.setAccessible(true);
					return (boolean) method.invoke(filter, request, response, mappedValue);
				}
			}
		}
		return super.onPreHandle(request, response, mappedValue);
	}

	@Override
	public void doFilterInternal(ServletRequest request, ServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		if (isLoginRequest(request, response) && SecurityUtils.getSubject().isAuthenticated()) {
			WebUtils.issueRedirect(request, response, "/");
		}
		super.doFilterInternal(request, response, chain);
	}

	@Override
	protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {

		if (isXHR(request)) {
			if (isLoginRequest(request, response) && isLoginSubmission(request, response)) {
				return doLogin(request, response);
			}
			((HttpServletResponse) response).setStatus(401);
			return false;
		}
		return super.onAccessDenied(request, response);
	}

	@SuppressWarnings("unchecked")
	private boolean doLogin(ServletRequest request, ServletResponse response) throws Exception {

		ObjectMapper mapper = new ObjectMapper();
		Map<String, String> data = mapper.readValue(request.getInputStream(), Map.class);

		String username = data.get("username");
		String password = data.get("password");

		AuthenticationToken token = createToken(username, password, request, response);

		try {
			Subject subject = getSubject(request, response);
			subject.login(token);
			return onLoginSuccess(token, subject, request, response);
		} catch (AuthenticationException e) {
		}
		return false;
	}

	private boolean isXHR(ServletRequest request) {
		return "XMLHttpRequest".equals(((HttpServletRequest) request).getHeader("X-Requested-With"));
	}
}
