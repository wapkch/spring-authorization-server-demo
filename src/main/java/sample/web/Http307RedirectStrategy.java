package sample.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import org.springframework.core.log.LogMessage;
import org.springframework.security.web.DefaultRedirectStrategy;

public class Http307RedirectStrategy extends DefaultRedirectStrategy {

	@Override
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
		String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);
		redirectUrl = response.encodeRedirectURL(redirectUrl);
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Redirecting to %s", redirectUrl));
		}
		response.setHeader("Location", redirectUrl);
		response.sendError(HttpServletResponse.SC_TEMPORARY_REDIRECT);
	}

}
