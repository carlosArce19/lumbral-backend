package app.lumbral.backend.common.errors;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.Collections;
import java.util.List;

/**
 * RFC 7807–like error response. All non-2xx responses use this shape.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public record ApiError(
		String type,
		String title,
		int status,
		String detail,
		String instance,
		String traceId,
		List<FieldError> errors
) {
	public static ApiError of(String type, String title, int status, String detail, String instance, String traceId) {
		return new ApiError(type, title, status, detail, instance, traceId, null);
	}

	public static ApiError of(String type, String title, int status, String detail, String instance, String traceId,
			List<FieldError> errors) {
		return new ApiError(type, title, status, detail, instance, traceId,
				errors != null ? List.copyOf(errors) : Collections.emptyList());
	}
}
