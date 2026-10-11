import { test } from 'node:test'
import assert from 'node:assert/strict'
import { connect, requestApp, isActive, type Host, type Lifecycle } from '../src/host.ts'

test('hidden cancels reads, disposal cancels mutations, and unsupported SDK is rejected', async () => {
  let lifecycle: (state: Lifecycle) => void = () => {}
  const signals: AbortSignal[] = []
  let finish: (value: {status:number; data:unknown; requestId:string}) => void = () => {}
  const bridge: Host = { appSDK: { version:'1.1.0', app:{ request: (_input, options) => { signals.push(options!.signal!); return new Promise(resolve => { finish = resolve }) } },
    lifecycle:{ subscribe: listener => { lifecycle = listener; return () => {} } },
    theme:{ get: () => 'light', subscribe: () => () => {} },
    navigation:{ get: () => ({path:'/',revision:0}), subscribe: () => () => {}, request: async () => {} } },
    dashboardHost:{ ready(){},setDirty(){},resize(){} } }
  const dispose = connect(bridge)
  const first = requestApp({path:'/proxies',method:'GET'})
  lifecycle('hidden'); assert.equal(isActive(),false); assert.equal(signals[0].aborted,true)
  finish({status:200,data:{items:[]},requestId:'one'});await assert.rejects(first,/CANCELLED/)
  await assert.rejects(requestApp({path:'/proxies',method:'GET'}),/不可用/)
  lifecycle('active')
  const second = requestApp({path:'/proxies',method:'POST',body:{}})
  lifecycle('hidden');assert.equal(signals[1].aborted,false)
  lifecycle('dispose');assert.equal(signals[1].aborted,true)
  finish({status:201,data:{},requestId:'two'});await assert.rejects(second,/CANCELLED/)
  dispose()
  bridge.appSDK.version='1.0.0';assert.throws(() => connect(bridge),/UNAVAILABLE/)
})
