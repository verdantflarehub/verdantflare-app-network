// Consumer view of the public AppSDK v1 contract. No host store or Wails imports.
export type Lifecycle = 'active' | 'hidden' | 'dispose'
export type Request = { path: string; method: string; body?: unknown }
export interface Host {
  appSDK: {
    version: string
    app: { request(input: Request, options?: { signal?: AbortSignal }): Promise<{ status: number; data: unknown; requestId: string }> }
    lifecycle: { subscribe(listener: (event: Lifecycle) => void): () => void }
    theme: { get(): 'light' | 'dark'; subscribe(listener: (theme: 'light' | 'dark') => void): () => void }
    navigation: { get(): { path: string; revision: number }; subscribe(listener: (route: { path: string; revision: number }) => void): () => void; request(input: { path: string; target: 'app' | 'appcenter' }): Promise<void> }
  }
  dashboardHost: { ready(): void; setDirty(value: boolean): void; resize(height: number): void }
}
let current: Host | undefined
let state: Lifecycle = 'dispose'
let unsubscribe = () => {}
const listeners = new Set<(event: Lifecycle) => void>()
const reads = new Set<AbortController>()
const all = new Set<AbortController>()

export function connect(value: Host): () => void {
  if (!value || !/^1\.\d+\.\d+$/.test(value.appSDK?.version) || Number(value.appSDK.version.split('.')[1]) < 1 || !value.appSDK.app?.request || !value.appSDK.lifecycle?.subscribe || !value.appSDK.theme?.get || !value.appSDK.theme?.subscribe || !value.appSDK.navigation?.get || !value.appSDK.navigation?.subscribe || !value.dashboardHost?.ready) throw Error('APP_SDK_UNAVAILABLE')
  disconnect()
  current = value
  state = 'active'
  unsubscribe = value.appSDK.lifecycle.subscribe(event => {
    state = event
    for (const controller of event === 'dispose' ? all : event === 'hidden' ? reads : []) controller.abort()
    for (const listener of [...listeners]) listener(event)
    if (event === 'dispose') disconnect()
  })
  return disconnect
}
function disconnect() {
  unsubscribe(); unsubscribe = () => {}
  for (const controller of all) controller.abort()
  all.clear(); reads.clear(); listeners.clear(); state = 'dispose'; current = undefined
}
export function host(): Host { if (!current) throw Error('APP_SDK_UNAVAILABLE'); return current }
export function isActive() { return state === 'active' }
export function subscribeLifecycle(listener: (event: Lifecycle) => void) { listeners.add(listener); return () => { listeners.delete(listener) } }
export async function requestApp(input: Request) {
  if (!isActive()) throw Error('应用页面当前不可用，请重新打开')
  const controller = new AbortController()
  all.add(controller); if (input.method === 'GET') reads.add(controller)
  try {
    const result = await host().appSDK.app.request(input, { signal: controller.signal })
    if (controller.signal.aborted || !current) throw Error('REQUEST_CANCELLED')
    return result
  } finally { reads.delete(controller); all.delete(controller) }
}
