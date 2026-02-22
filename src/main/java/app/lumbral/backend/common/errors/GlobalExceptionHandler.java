package app.lumbral.backend.common.errors;

import app.lumbral.backend.auth.service.AuthException;
import app.lumbral.backend.auth.service.InvalidTokenException;
import app.lumbral.backend.auth.service.RefreshTokenReusedException;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final String PROBLEM_BASE = "https://api.lumbral.app/problems/";
	private static final String TRACE_ID_MDC = "traceId";
	private static final String REFRESH_PATH = "/api/v1/auth/refresh";

	@Value("${app.jwt.refresh-cookie-secure}")
	private boolean cookieSecure;

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, WebRequest request) {
		List<FieldError> errors = ex.getBindingResult().getFieldErrors().stream()
				.map(fe -> new FieldError(fe.getField(), fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "Invalid"))
				.collect(Collectors.toList());
		ApiError body = ApiError.of(
				PROBLEM_BASE + "validation-error",
				"Validation error",
				HttpStatus.BAD_REQUEST.value(),
				"One or more fields are invalid.",
				extractPath(request),
				getTraceId(),
				errors);
		return buildErrorResponse(body, HttpStatus.BAD_REQUEST.value(), request);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<ApiError> handleBadRequest(IllegalArgumentException ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + "bad-request",
				"Bad request",
				HttpStatus.BAD_REQUEST.value(),
				ex.getMessage() != null ? ex.getMessage() : "Invalid request.",
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, HttpStatus.BAD_REQUEST.value(), request);
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiError> handleForbidden(AccessDeniedException ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + "forbidden",
				"Forbidden",
				HttpStatus.FORBIDDEN.value(),
				"Access denied.",
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, HttpStatus.FORBIDDEN.value(), request);
	}

	@ExceptionHandler(AuthException.class)
	public ResponseEntity<ApiError> handleAuth(AuthException ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + ex.getProblemType(),
				ex.getTitle(),
				ex.getHttpStatus(),
				ex.getMessage(),
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, ex.getHttpStatus(), request);
	}

	@ExceptionHandler(RefreshTokenReusedException.class)
	public ResponseEntity<ApiError> handleTokenReuse(RefreshTokenReusedException ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + "token-reuse-detected",
				"Token reuse detected",
				HttpStatus.UNAUTHORIZED.value(),
				"Refresh token reuse detected.",
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, HttpStatus.UNAUTHORIZED.value(), request, true);
	}

	@ExceptionHandler(InvalidTokenException.class)
	public ResponseEntity<ApiError> handleInvalidToken(InvalidTokenException ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + "invalid-token",
				"Invalid token",
				HttpStatus.UNAUTHORIZED.value(),
				ex.getMessage(),
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, HttpStatus.UNAUTHORIZED.value(), request);
	}

	@ExceptionHandler(ServletRequestBindingException.class)
	public ResponseEntity<ApiError> handleBinding(ServletRequestBindingException ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + "bad-request",
				"Bad request",
				HttpStatus.BAD_REQUEST.value(),
				ex.getMessage(),
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, HttpStatus.BAD_REQUEST.value(), request);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleGeneric(Exception ex, WebRequest request) {
		ApiError body = ApiError.of(
				PROBLEM_BASE + "internal-error",
				"Internal server error",
				HttpStatus.INTERNAL_SERVER_ERROR.value(),
				"An unexpected error occurred.",
				extractPath(request),
				getTraceId());
		return buildErrorResponse(body, HttpStatus.INTERNAL_SERVER_ERROR.value(), request);
	}

	private ResponseEntity<ApiError> buildErrorResponse(ApiError body, int status, WebRequest request) {
		return buildErrorResponse(body, status, request, false);
	}

	private ResponseEntity<ApiError> buildErrorResponse(ApiError body, int status, WebRequest request,
														boolean alwaysClearCookie) {
		String path = extractPath(request);
		boolean shouldClear = alwaysClearCookie || (status == 401 && REFRESH_PATH.equals(path));

		ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
		if (shouldClear) {
			builder.header(HttpHeaders.SET_COOKIE, buildClearRefreshCookie().toString());
		}
		return builder.body(body);
	}

	private ResponseCookie buildClearRefreshCookie() {
		return ResponseCookie.from("refresh_token", "")
				.httpOnly(true)
				.secure(cookieSecure)
				.sameSite("Lax")
				.path("/api/v1/auth")
				.maxAge(0)
				.build();
	}

	private static String extractPath(WebRequest request) {
		return request.getDescription(false).replace("uri=", "");
	}

	private static String getTraceId() {
		String traceId = MDC.get(TRACE_ID_MDC);
		return traceId != null ? traceId : "";
	}
}
