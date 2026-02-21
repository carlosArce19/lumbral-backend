package app.lumbral.backend.common.errors;

import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import java.util.List;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final String PROBLEM_BASE = "https://api.lumbral.app/problems/";
	private static final String TRACE_ID_MDC = "traceId";

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiError> handleValidation(MethodArgumentNotValidException ex, WebRequest request) {
		List<FieldError> errors = ex.getBindingResult().getFieldErrors().stream()
				.map(fe -> new FieldError(fe.getField(), fe.getDefaultMessage() != null ? fe.getDefaultMessage() : "Invalid"))
				.collect(Collectors.toList());
		String traceId = getTraceId();
		ApiError body = ApiError.of(
				PROBLEM_BASE + "validation-error",
				"Validation error",
				HttpStatus.BAD_REQUEST.value(),
				"One or more fields are invalid.",
				request.getDescription(false).replace("uri=", ""),
				traceId,
				errors);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
	}

	@ExceptionHandler(IllegalArgumentException.class)
	public ResponseEntity<ApiError> handleBadRequest(IllegalArgumentException ex, WebRequest request) {
		String traceId = getTraceId();
		ApiError body = ApiError.of(
				PROBLEM_BASE + "bad-request",
				"Bad request",
				HttpStatus.BAD_REQUEST.value(),
				ex.getMessage() != null ? ex.getMessage() : "Invalid request.",
				request.getDescription(false).replace("uri=", ""),
				traceId);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
	}

	@ExceptionHandler(AccessDeniedException.class)
	public ResponseEntity<ApiError> handleForbidden(AccessDeniedException ex, WebRequest request) {
		String traceId = getTraceId();
		ApiError body = ApiError.of(
				PROBLEM_BASE + "forbidden",
				"Forbidden",
				HttpStatus.FORBIDDEN.value(),
				"Access denied.",
				request.getDescription(false).replace("uri=", ""),
				traceId);
		return ResponseEntity.status(HttpStatus.FORBIDDEN).body(body);
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<ApiError> handleGeneric(Exception ex, WebRequest request) {
		String traceId = getTraceId();
		ApiError body = ApiError.of(
				PROBLEM_BASE + "internal-error",
				"Internal server error",
				HttpStatus.INTERNAL_SERVER_ERROR.value(),
				"An unexpected error occurred.",
				request.getDescription(false).replace("uri=", ""),
				traceId);
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
	}

	private static String getTraceId() {
		String traceId = MDC.get(TRACE_ID_MDC);
		return traceId != null ? traceId : "";
	}
}
