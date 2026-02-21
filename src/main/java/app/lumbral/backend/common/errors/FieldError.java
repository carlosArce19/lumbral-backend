package app.lumbral.backend.common.errors;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.ALWAYS)
public record FieldError(String field, String message) {}
