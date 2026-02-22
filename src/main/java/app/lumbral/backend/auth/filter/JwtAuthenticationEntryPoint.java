package app.lumbral.backend.auth.filter;

import app.lumbral.backend.common.errors.ApiError;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private static final String PROBLEM_BASE = ApiError.PROBLEM_BASE;
    private static final String TRACE_ID_MDC = "traceId";

    private final ObjectMapper objectMapper;

    public JwtAuthenticationEntryPoint(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        ApiError body = ApiError.of(
                PROBLEM_BASE + "invalid-token",
                "Invalid token",
                401,
                "Authentication required.",
                request.getRequestURI(),
                getTraceId());

        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private static String getTraceId() {
        String traceId = MDC.get(TRACE_ID_MDC);
        return traceId != null ? traceId : "";
    }
}
