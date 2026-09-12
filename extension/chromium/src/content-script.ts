/**
 * Content script.
 *
 * Intentionally inert for privacy: ezcap observes from outside the page
 * (daemon + eBPF/pcap) and never injects observation hooks into page
 * content. The content script exists only as a no-op placeholder so the
 * extension manifest stays uniform across builds — and so that removing
 * it is a one-line change if a future, explicitly opt-in page-level
 * feature is ever approved.
 *
 * It must never read page content, form fields, or storage, and never
 * send page data anywhere.
 */

export {};  // no behavior by design
