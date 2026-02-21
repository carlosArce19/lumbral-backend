package app.lumbral.backend.common.pagination;

import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

/**
 * API pagination request: 1-based page, pageSize default 20, max 100.
 */
public record PageRequest(int page, int pageSize) {

	private static final int DEFAULT_PAGE = 1;
	private static final int DEFAULT_PAGE_SIZE = 20;
	private static final int MAX_PAGE_SIZE = 100;

	public static PageRequest of(Integer page, Integer pageSize) {
		int p = page != null && page >= 1 ? page : DEFAULT_PAGE;
		int ps = pageSize != null && pageSize >= 1 ? pageSize : DEFAULT_PAGE_SIZE;
		if (ps > MAX_PAGE_SIZE) ps = MAX_PAGE_SIZE;
		return new PageRequest(p, ps);
	}

	public Pageable toPageable() {
		return toPageable(null);
	}

	public Pageable toPageable(Sort sort) {
		return org.springframework.data.domain.PageRequest.of(page - 1, pageSize, sort != null ? sort : Sort.unsorted());
	}
}
