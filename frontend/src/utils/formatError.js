export function formatError(err, fallback) {
  if (err?.response) {
    const status = err.response.status
    const msg = err.response.data?.message || err.response.statusText
    return `${fallback} (HTTP ${status}${msg ? `: ${msg}` : ''})`
  }
  if (err?.request) {
    return `${fallback} (no response from server — is the backend reachable?)`
  }
  return `${fallback} (${err?.message || 'unknown error'})`
}
