// Exercises the actual compiled API client without a browser or external calls.
import {transform} from 'esbuild';
import {readFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const result=await transform(await readFile(new URL('../src/lib/api.ts',import.meta.url),'utf8'),{loader:'ts',format:'esm',define:{'import.meta.env':'{}'}});
const storage=new Map();
globalThis.localStorage={getItem:k=>storage.get(k)??null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)};
globalThis.window={localStorage:globalThis.localStorage,dispatchEvent:()=>true};
const api=await import('data:text/javascript;base64,'+Buffer.from(result.code).toString('base64'));
let checks=0;
globalThis.fetch=async()=>new Response('{}',{status:404});
assert.equal((await api.listWorkspaces())[0].legacy,true);checks++;
for(const status of [401,403,500]){
 globalThis.fetch=async()=>new Response('{}',{status});
 await assert.rejects(api.listWorkspaces(),error=>error instanceof api.ApiError&&error.status===status);checks++;
}
globalThis.fetch=async()=>new Response(JSON.stringify([{id:'actual',name:'Real workspace',role:'viewer'}]),{status:200});
assert.deepEqual(await api.listWorkspaces(),[{id:'actual',name:'Real workspace',role:'viewer'}]);checks++;
api.setSelectedWorkspace('tab-A');storage.set('trace.workspace','other-tab-B');
assert.equal(api.getSelectedWorkspace(),'tab-A');checks++;
let headers;
globalThis.fetch=async(url,init)=>{headers=init.headers;return new Response('[]',{status:200});};
await api.listWorkspaces();assert.equal(headers['X-Trace-Workspace'],'tab-A');checks++;
console.log(`API client checks: ${checks} passed`);
