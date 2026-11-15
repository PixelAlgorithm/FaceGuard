import { EDGE_URL, MOCK_ENABLED } from '../config'
import { HttpEdgeApi } from './http'
import { MockEdgeApi } from './mock'
import type { EdgeApi } from './types'

let api: EdgeApi | null = null

/** Single edge client for the page: in-browser mock (VITE_MOCK=1 / ?mock=1) or the real edge. */
export function getApi(): EdgeApi {
  if (!api) api = MOCK_ENABLED ? new MockEdgeApi() : new HttpEdgeApi(EDGE_URL)
  return api
}

export * from './types'
