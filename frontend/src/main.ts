import { createApp, nextTick } from 'vue'
import StationProxy from './StationProxy.vue'
import { connect, subscribeLifecycle, type Host } from './host'
import './tokens.css'
import './layout.css'

declare global { interface Window { $wujie?: { props?: Host } } }
const container = document.getElementById('app')!
const bridge = window.$wujie?.props
if (!bridge) {
  container.textContent = '请从 Studio 应用中心打开网络出口。'
} else {
  const disconnect = connect(bridge)
  const applyTheme = (theme: 'light' | 'dark') => { document.body.dataset.theme = theme }
  applyTheme(bridge.appSDK.theme.get())
  const unsubscribeTheme = bridge.appSDK.theme.subscribe(applyTheme)
  const app = createApp(StationProxy)
  app.mount(container)
  const resize = () => bridge.dashboardHost.resize(document.documentElement.scrollHeight)
  const observer = new ResizeObserver(resize)
  observer.observe(container)
  const unsubscribe = subscribeLifecycle(event => {
    if (event === 'active') resize()
    if (event === 'dispose') { observer.disconnect(); unsubscribe(); unsubscribeTheme(); app.unmount(); disconnect() }
  })
  void nextTick(() => { bridge.dashboardHost.ready(); resize() })
}
