import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createApp } from '../dist/index.js';

const A='synthetic-p2p-account-a', B='synthetic-p2p-account-b';
const init={jsonrpc:'2.0',id:1,method:'initialize',params:{protocolVersion:'2025-03-26',capabilities:{},clientInfo:{name:'test',version:'1'}}};
async function fixture(options={}) {
  let time=1000, mode=200, trapCalls=0;
  const calls=[];
  const upstream=http.createServer((req,res)=>{
    if(req.url==='/trap'){trapCalls++;res.end('TRAP');return;}
    calls.push({url:req.url,key:req.headers.authorization});
    if(mode===302){res.writeHead(302,{Location:'/trap'});res.end();return;}
    res.writeHead(typeof mode==='number'?mode:200,{'Content-Type':'application/json'});
    res.end(mode===200?JSON.stringify({items:[{id:'synthetic-chain'}]}):mode==='invalid'?'synthetic-private-error':JSON.stringify({error:`private ${A} ${B}`}));
  });
  upstream.listen(0,'127.0.0.1');await once(upstream,'listening');
  const fetchMock=async(url,opts)=>{
    const u=new URL(url);assert.equal(u.origin,'https://api.lambda.p2p.org');
    assert.equal(opts.redirect,'error');assert.ok(opts.signal);
    return fetch(`http://127.0.0.1:${upstream.address().port}${u.pathname}${u.search}`,opts);
  };
  const runtime=createApp({now:()=>time,fetch:fetchMock,...options});
  const server=runtime.app.listen(0,'127.0.0.1');await once(server,'listening');
  const base=`http://127.0.0.1:${server.address().port}`;
  const clients=[];
  async function connect(key=A){
    const client=new Client({name:'p2p-repair-test',version:'1'});
    const transport=new StreamableHTTPClientTransport(new URL(base+'/mcp'),{requestInit:{headers:{Authorization:'Bearer '+key}}});
    clients.push(client);await client.connect(transport);return {client,transport};
  }
  async function req(method, {key=A,sid,body=init,path='/mcp'}={}){
    const headers={Accept:'application/json, text/event-stream','Content-Type':'application/json'};
    if(key!==null)headers.Authorization='Bearer '+key;
    if(sid!==undefined)headers['mcp-session-id']=sid;
    const r=await fetch(base+path,{method,headers,...(method==='POST'?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(3000)});
    const status=r.status;await r.body?.cancel();return status;
  }
  async function token(){const r=await fetch(base+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'client_credentials',client_id:'p2p-lambda',client_secret:A})});assert.equal(r.status,200);return (await r.json()).access_token;}
  return {runtime,base,calls,connect,req,token,setMode:v=>{mode=v},advance:v=>{time+=v},trapCalls:()=>trapCalls,
    close:async()=>{await Promise.all(clients.map(c=>c.close().catch(()=>{})));await runtime.close();server.closeAllConnections();upstream.closeAllConnections();await Promise.all([new Promise(r=>server.close(r)),new Promise(r=>upstream.close(r))]);}};
}
async function withFixture(options,fn){const f=await fixture(options);try{await fn(f)}finally{await f.close()}}
const read=c=>c.callTool({name:'chains_list',arguments:{limit:1}});

test('SDK initialize/list/read: exact raw provider credential, fixed origin, limit',()=>withFixture({},async f=>{
 const {client}=await f.connect();const list=await client.listTools();assert.ok(list.tools.some(x=>x.name==='chains_list'));
 const r=await read(client);assert.notEqual(r.isError,true);assert.equal(JSON.parse(r.content[0].text).items.length,1);
 assert.deepEqual(f.calls,[{url:'/api/v1/chains?limit=1',key:A}]);
}));
for(const method of ['POST','GET','DELETE'])for(const key of [null,B])test(`${method} session rejects ${key===null?'missing':'other account'} credentials without provider calls`,()=>withFixture({},async f=>{
 const {client,transport}=await f.connect();const n=f.calls.length;
 assert.equal(await f.req(method,{key,sid:transport.sessionId,body:{jsonrpc:'2.0',id:4,method:'tools/call',params:{name:'chains_list',arguments:{limit:1}}}}),key===null?401:403);
 assert.equal(f.calls.length,n);assert.notEqual((await read(client)).isError,true);
}));
for(const body of [{jsonrpc:'2.0',id:1,method:'tools/list'}, {jsonrpc:'2.0',id:1,method:'initialize',params:{}},[init]])test(`only schema-valid single initialize creates a session: ${JSON.stringify(body)}`,()=>withFixture({maxSessions:1},async f=>{
 assert.equal(await f.req('POST',{body}),400);const {client}=await f.connect();assert.notEqual((await read(client)).isError,true);
}));
for(const method of ['POST','GET','DELETE'])test(`${method} unknown session does not initialize`,()=>withFixture({maxSessions:1},async f=>{
 assert.equal(await f.req(method,{sid:'unknown'}),404);assert.equal(f.calls.length,0);await f.connect();
}));
test('owner closes session, stale ID is rejected and SDK reconnect works',()=>withFixture({},async f=>{
 const {transport}=await f.connect();const sid=transport.sessionId;assert.equal(await f.req('DELETE',{sid}),200);
 assert.equal(await f.req('POST',{sid}),404);const {client}=await f.connect();assert.notEqual((await read(client)).isError,true);
}));
test('two independent SDK accounts route to their own upstream keys',()=>withFixture({},async f=>{
 const a=await f.connect(A),b=await f.connect(B);await read(a.client);await read(b.client);assert.deepEqual(f.calls.map(x=>x.key),[A,B]);
}));
test('session capacity rejects overflow; closure releases capacity',()=>withFixture({maxSessions:1},async f=>{
 const {transport}=await f.connect();assert.equal(await f.req('POST'),503);assert.equal(f.calls.length,0);
 await f.req('DELETE',{sid:transport.sessionId});await f.connect();
}));
test('concurrent initialization cannot exceed session cap',()=>withFixture({maxSessions:1},async f=>{
 const statuses=await Promise.all(Array.from({length:8},()=>f.req('POST')));assert.equal(statuses.filter(x=>x===200).length,1);assert.equal(statuses.filter(x=>x===503).length,7);
}));
test('idle cleanup removes session and releases capacity',()=>withFixture({maxSessions:1,sessionIdleMs:100},async f=>{
 const {transport}=await f.connect();f.advance(101);await f.runtime.cleanup();assert.equal(await f.req('POST',{sid:transport.sessionId}),404);await f.connect();
}));
test('idle expiration enforced on access without waiting for sweeper',()=>withFixture({sessionIdleMs:100},async f=>{
 const {transport}=await f.connect();f.advance(101);assert.equal(await f.req('POST',{sid:transport.sessionId}),404);assert.equal(f.calls.length,0);
}));
test('wrapper token maps to same credential, but expires before session reuse',()=>withFixture({tokenTtlMs:100},async f=>{
 const t=await f.token();const {client,transport}=await f.connect(t);await read(client);assert.equal(f.calls[0].key,A);
 f.advance(100);for(const method of ['POST','GET','DELETE'])assert.equal(await f.req(method,{key:t,sid:transport.sessionId}),401);
 assert.equal(f.calls.length,1);assert.equal(await f.req('POST',{key:A,sid:transport.sessionId,body:{jsonrpc:'2.0',id:7,method:'tools/list'}}),200);
}));
test('revoked wrapper cannot reuse session',()=>withFixture({},async f=>{
 const token=await f.token();const {transport}=await f.connect(token);
 await f.req('POST',{path:'/oauth/revoke',body:{token}});
 assert.equal(await f.req('POST',{key:token,sid:transport.sessionId}),401);assert.equal(f.calls.length,0);
}));
for(const mode of [401,403,500,'invalid'])test(`provider ${mode} sanitized as MCP tool error`,()=>withFixture({},async f=>{
 const {client}=await f.connect();f.setMode(mode);const r=await read(client);assert.equal(r.isError,true);
 const s=JSON.stringify(r);for(const forbidden of [A,B,'private','synthetic-private-error'])assert.equal(s.includes(forbidden),false);
 assert.match(r.content[0].text,/Provider request failed/);
}));
test('provider redirect refused and never sends credential to destination',()=>withFixture({},async f=>{
 const {client}=await f.connect();f.setMode(302);const r=await read(client);assert.equal(r.isError,true);assert.equal(f.trapCalls(),0);assert.equal(f.calls.length,1);
}));
test('malformed request body sanitized',()=>withFixture({},async f=>{
 const r=await fetch(f.base+'/mcp',{method:'POST',headers:{'Content-Type':'application/json'},body:'{"secret":"'+A+'"'});
 assert.equal(r.status,400);assert.equal((await r.text()).includes(A),false);assert.equal(f.calls.length,0);
}));
test('runtime shutdown clears sessions and rejects admission',()=>withFixture({},async f=>{
 const {transport}=await f.connect();await f.runtime.close();assert.equal(await f.req('POST',{sid:transport.sessionId}),503);assert.equal(await f.req('POST'),503);assert.equal(f.calls.length,0);
}));

test('invalid tool arguments fail before provider dispatch',()=>withFixture({},async f=>{
 const {client}=await f.connect();const r=await client.callTool({name:'chains_list',arguments:{limit:'private-invalid'}});
 assert.equal(r.isError,true);assert.equal(f.calls.length,0);assert.equal(JSON.stringify(r).includes('private-invalid'),false);
}));
test('unknown tool errors do not reflect caller data',()=>withFixture({},async f=>{
 const {client}=await f.connect();await assert.rejects(client.callTool({name:A,arguments:{}}),e=>!e.message.includes(A));assert.equal(f.calls.length,0);
}));
test('network failure is sanitized',()=>withFixture({fetch:async()=>{throw new Error('private '+A)}},async f=>{
 const {client}=await f.connect();const r=await read(client);assert.equal(r.isError,true);assert.equal(JSON.stringify(r).includes(A),false);assert.match(r.content[0].text,/Provider request failed/);
}));
test('automatic sweeper expires idle sessions',()=>withFixture({sessionIdleMs:100,cleanupIntervalMs:5},async f=>{
 const {transport}=await f.connect();f.advance(101);await new Promise(r=>setTimeout(r,30));
 assert.equal(await f.req('POST',{sid:transport.sessionId}),404);assert.equal(f.calls.length,0);
}));
test('failed transport initialize releases reserved capacity',()=>withFixture({maxSessions:1},async f=>{
 const r=await fetch(f.base+'/mcp',{method:'POST',headers:{Authorization:A,'Content-Type':'application/json',Accept:'application/json'},body:JSON.stringify(init)});
 assert.equal(r.status,406);await r.body?.cancel();await f.connect();
}));
test('raw incoming authorization supports same session identity as Bearer',()=>withFixture({},async f=>{
 const {transport}=await f.connect();const r=await fetch(f.base+'/mcp',{method:'POST',headers:{Authorization:A,'Content-Type':'application/json',Accept:'application/json, text/event-stream','mcp-session-id':transport.sessionId},body:JSON.stringify({jsonrpc:'2.0',id:3,method:'tools/list'})});
 assert.equal(r.status,200);await r.body?.cancel();assert.equal(f.calls.length,0);
}));
test('idle cleanup preserves an in-flight provider read',async()=>{
 let entered,release;const started=new Promise(r=>{entered=r}),gate=new Promise(r=>{release=r});
 await withFixture({sessionIdleMs:100,fetch:async()=>{entered();await gate;return new Response(JSON.stringify({items:[]}));}},async f=>{
  const {client,transport}=await f.connect();const pending=read(client);await started;f.advance(101);await f.runtime.cleanup();release();
  assert.notEqual((await pending).isError,true);assert.equal(await f.req('POST',{sid:transport.sessionId,body:{jsonrpc:'2.0',id:80,method:'tools/list'}}),200);
 });
});
