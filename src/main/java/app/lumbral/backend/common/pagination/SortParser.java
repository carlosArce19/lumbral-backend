package app.lumbral.backend.common.pagination;

import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Order;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Parses sort=field:direction query parameter into Spring Sort.
 * Direction must be asc or desc; field must be in the allowlist.
 */
public final class SortParser {

	private SortParser() {}

	/**
	 * Parse a single sort spec (e.g. "createdAt:desc") into a Sort.Order, or null if invalid.
	 */
	public static Order parseOne(String sortSpec, Set<String> allowedFields) {
		if (sortSpec == null || sortSpec.isBlank() || allowedFields == null || allowedFields.isEmpty()) {
			return null;
		}
		String[] parts = sortSpec.trim().split(":");
		if (parts.length != 2) return null;
		String property = parts[0].trim();
		String direction = parts[1].trim().toLowerCase();
		if (!allowedFields.contains(property)) return null;
		if ("asc".equals(direction)) return Order.asc(property);
		if ("desc".equals(direction)) return Order.desc(property);
		return null;
	}

	/**
	 * Parse sort parameter value (e.g. "createdAt:desc,name:asc") into Sort.
	 * Multiple specs can be comma-separated. Invalid specs are skipped.
	 */
	public static Sort parse(String sortParam, Set<String> allowedFields) {
		if (sortParam == null || sortParam.isBlank()) return Sort.unsorted();
		return Arrays.stream(sortParam.split(","))
				.map(s -> parseOne(s, allowedFields))
				.filter(o -> o != null)
				.collect(Collectors.collectingAndThen(Collectors.toList(), orders ->
						orders.isEmpty() ? Sort.unsorted() : Sort.by(orders)));
	}
}
