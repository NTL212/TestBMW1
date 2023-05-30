package com.handler.filter;

import java.io.IOException;
import java.text.Normalizer;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.text.StringEscapeUtils;
import org.owasp.encoder.Encode;

public class XSSFilter implements Filter {

    class XSSRequestWrapper extends HttpServletRequestWrapper {

        private Map<String, String[]> sanitizedParameterMap;

        public XSSRequestWrapper(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getParameter(String name) {
            return stripXSS(super.getParameter(name));
        }

        @Override
        public String[] getParameterValues(String name) {
            String[] values = super.getParameterValues(name);
            if (values != null) {
                for (int i = 0; i < values.length; i++) {
                    values[i] = stripXSS(values[i]);
                }
            }
            return values;
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            if (sanitizedParameterMap == null) {
                Map<String, String[]> originalParameterMap = super.getParameterMap();
                Map<String, String[]> sanitizedMap = new HashMap<>(originalParameterMap.size());

                for (Map.Entry<String, String[]> entry : originalParameterMap.entrySet()) {
                    String[] originalValues = entry.getValue();
                    String[] sanitizedValues = new String[originalValues.length];
                    for (int i = 0; i < originalValues.length; i++) {
                        sanitizedValues[i] = stripXSS(originalValues[i]);
                    }
                    sanitizedMap.put(entry.getKey(), sanitizedValues);
                }

                sanitizedParameterMap = sanitizedMap;
            }
            return sanitizedParameterMap;
        }

        private String stripXSS(String value) {
            if (value != null) {
                value = Normalizer.normalize(value, Normalizer.Form.NFD);

				// Avoid null characters
				value = value.replaceAll("\0", "");
				
				// Avoid anything between script tags
				Pattern scriptPattern = Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE);
				value = scriptPattern.matcher(value).replaceAll("");
		 
				// Avoid anything in a src='...' type of expression
				scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\'(.*?)\\\'", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
				value = scriptPattern.matcher(value).replaceAll("");

				scriptPattern = Pattern.compile("src[\r\n]*=[\r\n]*\\\"(.*?)\\\"", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
				value = scriptPattern.matcher(value).replaceAll("");
				
				// Remove any lonesome </script> tag
				scriptPattern = Pattern.compile("</script>", Pattern.CASE_INSENSITIVE);
				value = scriptPattern.matcher(value).replaceAll("");

				// Remove any lonesome <script ...> tag
				scriptPattern = Pattern.compile("<script(.*?)>", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
				value = scriptPattern.matcher(value).replaceAll("");

				// Avoid eval(...) expressions
				scriptPattern = Pattern.compile("eval\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
				value = scriptPattern.matcher(value).replaceAll("");
				
				// Avoid expression(...) expressions
				scriptPattern = Pattern.compile("expression\\((.*?)\\)", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
				value = scriptPattern.matcher(value).replaceAll("");
				
				// Avoid javascript:... expressions
				scriptPattern = Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE);
				value = scriptPattern.matcher(value).replaceAll("");
				
				// Avoid vbscript:... expressions
				scriptPattern = Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE);
				value = scriptPattern.matcher(value).replaceAll("");
				
				// Avoid onload= expressions
				scriptPattern = Pattern.compile("onload(.*?)=", Pattern.CASE_INSENSITIVE | Pattern.MULTILINE | Pattern.DOTALL);
				value = scriptPattern.matcher(value).replaceAll("");
                // Remove malicious characters/strings
                String specialCharacters = "[\\\\{}]";
                value = value.replaceAll(specialCharacters, "");
                value = value.replaceAll("<script>", "");
                // Add more replacements as needed
                value = value.replaceAll("<", "&lt;").replaceAll(">", "&gt;");
                value = value.replaceAll("\\(", "&#40;").replaceAll("\\)", "&#41;");
                value = value.replaceAll("'", "&#39;");
                value = value.replaceAll("eval\\((.*)\\)", "");
                value = value.replaceAll("[\\\"\\\'][\\s]*javascript:(.*)[\\\"\\\']", "\"\"");
                value = value.replaceAll("script", "");
                // Escape HTML and encode for JavaScript
                value = StringEscapeUtils.escapeHtml4(value);
                value = Encode.forJavaScript(value);
            }
            return value;
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        // Initialization code here
    	System.out.print("Filter start");
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        XSSRequestWrapper wrapper = new XSSRequestWrapper(httpRequest);
        chain.doFilter(wrapper, httpResponse);
    }

    @Override
    public void destroy() {
        // Cleanup code here
    }
}
