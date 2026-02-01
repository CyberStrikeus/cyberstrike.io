/**
 * Form configuration for Cyberstrike
 * Update FORM_HANDLER_URL with your Cloudflare Worker URL
 */

export const FORM_CONFIG = {
  // Cloudflare Worker URL - değiştir!
  handlerUrl: "https://universal-form-handler.orhan-yil.workers.dev",

  // Endpoints
  endpoints: {
    contact: "/contact",
    waitlist: "/waitlist",
    subscribe: "/subscribe",
  },

  // Success redirect pages (optional)
  thankYouPages: {
    contact: "/thank-you",
    waitlist: "/thank-you",
    subscribe: null, // inline message göster
  }
};
