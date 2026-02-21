package app.lumbral.backend.common.pagination;

import org.springframework.data.domain.Page;

import java.util.List;

/**
 * API pagination response envelope: data, page, pageSize, total.
 */
public record PageResponse<T>(List<T> data, int page, int pageSize, long total) {

	public static <T> PageResponse<T> from(Page<T> page) {
		return new PageResponse<>(
				page.getContent(),
				page.getNumber() + 1,
				page.getSize(),
				page.getTotalElements());
	}
}
