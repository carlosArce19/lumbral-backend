package app.lumbral.backend.common.errors;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = GlobalExceptionHandlerTest.TestController.class)
@Import({ GlobalExceptionHandler.class, app.lumbral.backend.observability.logging.TraceIdFilter.class, GlobalExceptionHandlerTest.TestController.class })
class GlobalExceptionHandlerTest {

	@Autowired
	MockMvc mvc;

	@Autowired
	ObjectMapper objectMapper;

	@Test
	@WithMockUser
	void validationError_returns400_withTraceIdAndFieldErrors() throws Exception {
		mvc.perform(post("/test/validate")
						.with(csrf())
						.contentType(MediaType.APPLICATION_JSON)
						.content("{}"))
				.andExpect(status().isBadRequest())
				.andExpect(header().exists("X-Trace-Id"))
				.andExpect(jsonPath("$.type").value("https://api.lumbral.app/problems/validation-error"))
				.andExpect(jsonPath("$.title").value("Validation error"))
				.andExpect(jsonPath("$.status").value(400))
				.andExpect(jsonPath("$.traceId").isNotEmpty())
				.andExpect(jsonPath("$.errors").isArray())
				.andExpect(jsonPath("$.errors[0].field").exists())
				.andExpect(jsonPath("$.errors[0].message").exists());
	}

	@RestController
	static class TestController {
		@PostMapping("/test/validate")
		void validate(@Valid @RequestBody TestRequest body) {
			// no-op; validation triggers MethodArgumentNotValidException
		}
	}

	public record TestRequest(@NotBlank String name) {}
}
