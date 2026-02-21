package app.lumbral.backend.common.pagination;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Sort;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class SortParserTest {

	private static final Set<String> ALLOWED = Set.of("createdAt", "name", "priceCents");

	@Test
	void parse_validSingleSpec_returnsSort() {
		Sort sort = SortParser.parse("createdAt:desc", ALLOWED);
		assertThat(sort).isNotNull();
		assertThat(sort.get().toList()).hasSize(1);
		assertThat(sort.get().findFirst().orElseThrow().getProperty()).isEqualTo("createdAt");
		assertThat(sort.get().findFirst().orElseThrow().getDirection()).isEqualTo(Sort.Direction.DESC);
	}

	@Test
	void parse_asc_returnsAscending() {
		Sort sort = SortParser.parse("name:asc", ALLOWED);
		assertThat(sort.get().findFirst().orElseThrow().getDirection()).isEqualTo(Sort.Direction.ASC);
	}

	@Test
	void parse_multipleSpecs_returnsMultipleOrders() {
		Sort sort = SortParser.parse("createdAt:desc,name:asc", ALLOWED);
		assertThat(sort.get().toList()).hasSize(2);
		assertThat(sort.get().toList().get(0).getProperty()).isEqualTo("createdAt");
		assertThat(sort.get().toList().get(1).getProperty()).isEqualTo("name");
	}

	@Test
	void parse_disallowedField_returnsUnsorted() {
		Sort sort = SortParser.parse("unknown:desc", ALLOWED);
		assertThat(sort).isEqualTo(Sort.unsorted());
	}

	@Test
	void parse_invalidDirection_returnsUnsorted() {
		Sort sort = SortParser.parse("createdAt:invalid", ALLOWED);
		assertThat(sort).isEqualTo(Sort.unsorted());
	}

	@Test
	void parse_nullOrBlank_returnsUnsorted() {
		assertThat(SortParser.parse(null, ALLOWED)).isEqualTo(Sort.unsorted());
		assertThat(SortParser.parse("", ALLOWED)).isEqualTo(Sort.unsorted());
		assertThat(SortParser.parse("   ", ALLOWED)).isEqualTo(Sort.unsorted());
	}

	@Test
	void parse_oneValidOneInvalid_returnsSingleOrder() {
		Sort sort = SortParser.parse("createdAt:desc,unknown:asc", ALLOWED);
		assertThat(sort.get().toList()).hasSize(1);
		assertThat(sort.get().findFirst().orElseThrow().getProperty()).isEqualTo("createdAt");
	}
}
