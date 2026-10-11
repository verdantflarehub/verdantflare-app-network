import { readFile, writeFile, readdir } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve, relative } from 'node:path'

const root = resolve('dist')
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const files = {}
async function visit(directory) {
  for (const item of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const file = resolve(directory, item.name)
    if (item.isSymbolicLink()) throw Error('SYMLINK_ASSET_REJECTED')
    if (item.isDirectory()) { await visit(file); continue }
    const name = relative(root, file).replaceAll('\\', '/')
    if (['asset-index.json', 'dashboard-declaration.json', 'navigation-declaration.json'].includes(name)) continue
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,255}$/.test(name) || !/\.(html|js|mjs|css)$/.test(name)) throw Error('UNSUPPORTED_ASSET')
    const data = await readFile(file)
    if (data.length > 4 * 1024 * 1024) throw Error('ASSET_TOO_LARGE')
    files[name] = digest(data)
  }
}
await visit(root)
if (!files['index.html'] || Object.keys(files).length > 256) throw Error('INVALID_ASSET_INDEX')
const version = (await readFile('../VERSION', 'utf8')).trim()
if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) throw Error('INVALID_VERSION')
const index = Buffer.from(JSON.stringify({ schemaVersion: 1, files: Object.fromEntries(Object.entries(files).sort()) }))
if (index.length > 64 * 1024) throw Error('INDEX_TOO_LARGE')
const declaration = { schemaVersion: 1, appId: 'network', appVersion: version, dashboard: {
  entryRef: 'dashboard/index.html', artifactDigest: 'sha256:' + digest(index), adapter: 'wujie', sdkMajor: 1,
  minimumSdkVersion: '1.1.0', requiredCapabilities: ['app.request', 'navigation.request'], optionalCapabilities: [],
  appApiPolicyRef: 'network-management-v1', keepAlive: true,
} }
await writeFile(resolve(root, 'asset-index.json'), index)
await writeFile(resolve(root, 'dashboard-declaration.json'), JSON.stringify(declaration))
const navigation = { schemaVersion: 1, appId: 'network', appVersion: version, artifactDigest: declaration.dashboard.artifactDigest,
  entry: { entryId: 'main', title: '网络出口', iconRef: 'network', route: '/', accessRuleRef: 'network-read' } }
await writeFile(resolve(root, 'navigation-declaration.json'), JSON.stringify(navigation))
