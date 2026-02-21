package app.lumbral.backend.observability.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Sets traceId (from X-Trace-Id header or generated), tenantId/userId placeholders in MDC,
 * and X-Trace-Id response header. Clears MDC after request.
 */
@Component
public class TraceIdFilter extends OncePerRequestFilter implements Ordered {

	private static final String TRACE_ID_HEADER = "X-Trace-Id";
	private static final String MDC_TRACE_ID = "traceId";
	private static final String MDC_TENANT_ID = "tenantId";
	private static final String MDC_USER_ID = "userId";

	@Override
	protected void doFilterInternal(@NonNull HttpServletRequest request,
			@NonNull HttpServletResponse response,
			@NonNull FilterChain filterChain) throws ServletException, IOException {
		String traceId = request.getHeader(TRACE_ID_HEADER);
		if (traceId == null || traceId.isBlank()) {
			traceId = UUID.randomUUID().toString();
		}
		MDC.put(MDC_TRACE_ID, traceId);
		MDC.put(MDC_TENANT_ID, ""); // set by auth filter when authenticated
		MDC.put(MDC_USER_ID, "");   // set by auth filter when authenticated
		try {
			response.setHeader(TRACE_ID_HEADER, traceId);
			filterChain.doFilter(request, response);
		} finally {
			MDC.clear();
		}
	}

	@Override
	public int getOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}
}
