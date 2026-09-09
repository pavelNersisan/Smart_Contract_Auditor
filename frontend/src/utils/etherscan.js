/**
 * Fetch verified Solidity source from Etherscan.
 *
 * Two honest caveats:
 *  - This runs in the browser. Etherscan's public API does not reliably send
 *    CORS headers, so from some origins the request will be blocked by the
 *    browser. Proxy it through the backend if that happens.
 *  - A key is needed for any meaningful rate limit. Without one you get the
 *    unauthenticated quota, which is very low.
 */

const ENDPOINTS = {
  mainnet: 'https://api.etherscan.io/api',
}

export async function fetchVerifiedSource(address, apiKey = '', network = 'mainnet') {
  const base = ENDPOINTS[network]
  if (!base) throw new Error(`Unsupported network: ${network}`)

  const params = new URLSearchParams({
    module: 'contract',
    action: 'getsourcecode',
    address,
  })
  if (apiKey) params.set('apikey', apiKey)

  const response = await fetch(`${base}?${params.toString()}`)
  if (!response.ok) {
    throw new Error(`Etherscan responded ${response.status}`)
  }

  const payload = await response.json()
  if (payload.status !== '1' || !Array.isArray(payload.result) || !payload.result.length) {
    throw new Error(payload.result || 'Contract source is not verified on Etherscan')
  }

  const entry = payload.result[0]
  if (!entry.SourceCode) {
    throw new Error('Etherscan returned no source for that address')
  }

  return {
    name: entry.ContractName || '',
    compilerVersion: entry.CompilerVersion || '',
    optimizationUsed: entry.OptimizationUsed === '1',
    license: entry.LicenseType || '',
    source: normaliseSource(entry.SourceCode),
  }
}

/**
 * Etherscan returns multi-file sources as a JSON-encoded standard-input blob
 * wrapped in an extra pair of braces. Flatten that into a single file so the
 * auditor receives plain Solidity.
 */
export function normaliseSource(raw) {
  const text = String(raw).trim()
  if (!text.startsWith('{')) return text

  let parsed
  try {
    parsed = JSON.parse(text.startsWith('{{') ? text.slice(1, -1) : text)
  } catch {
    return text
  }

  const sources = parsed?.sources
  if (!sources || typeof sources !== 'object') return text

  const parts = Object.entries(sources).map(
    ([path, value]) => `// ---- ${path} ----\n${value?.content ?? ''}`,
  )
  return parts.join('\n\n')
}
