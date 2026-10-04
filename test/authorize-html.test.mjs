import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import express from 'express';
import { JSDOM } from 'jsdom';
import { createApp } from '../dist/index.js';

const fields=['client_id','redirect_uri','code_challenge','code_challenge_method','state','scope'];
const attack=`"><script>window.__injected=1</script><img data-injected="yes" src="x" onerror="window.__injected=2"><input name="injected" value="' & < >`;
async function fixture(fn){
 let submitted,providerCalls=0;
 const runtime=createApp({fetch:async()=>{providerCalls++;throw new Error('Unexpected provider call');}});
 const outer=express();outer.use(express.urlencoded({extended:false}));
 outer.use((req,_res,next)=>{if(req.method==='POST'&&req.path==='/authorize')submitted={...req.body};next();});
 outer.use(runtime.app);const server=outer.listen(0,'127.0.0.1');await once(server,'listening');
 const base=`http://127.0.0.1:${server.address().port}`;
 try{await fn({base,submitted:()=>submitted});assert.equal(providerCalls,0);}
 finally{await runtime.close();server.closeAllConnections();await new Promise(r=>server.close(r));}
}
async function page(base,values){
 const url=new URL('/authorize',base);url.search=new URLSearchParams({response_type:'code',...values});
 const r=await fetch(url);assert.equal(r.status,200);assert.match(r.headers.get('content-type'),/text\/html/);
 // Only our own harmless synthetic scripts are permitted here; external resources are disabled.
 return new JSDOM(await r.text(),{url:String(url),runScripts:'dangerously'});
}
function assertInertAndExact(dom,values){
 const {window}=dom,d=window.document;
 assert.equal(window.__injected,undefined);assert.equal(d.querySelectorAll('script,[data-injected],[name="injected"]').length,0);
 assert.equal(d.forms.length,1);assert.equal(d.forms[0].getAttribute('action'),'/authorize');
 assert.equal(d.querySelectorAll('input[type="hidden"]').length,6);
 for(const name of fields){const input=d.forms[0].elements.namedItem(name);assert.equal(input.value,values[name]);assert.deepEqual([...input.attributes].map(a=>a.name).sort(),['name','type','value']);}
 assert.equal(d.querySelector('.scope-badge')?.textContent,values.scope?'Scope: '+values.scope:undefined);
}
const defaults={client_id:'p2p-lambda',redirect_uri:'https://client.invalid/callback',code_challenge:'synthetic-challenge',code_challenge_method:'S256',state:'original-state',scope:'read'};
for(const field of fields)test(`authorize HTML keeps malicious ${field} inert and exact through form POST`,()=>fixture(async f=>{
 const values={...defaults,[field]:attack};const dom=await page(f.base,values);
 try{
  assertInertAndExact(dom,values);
  dom.window.document.getElementById('apiKey').value='synthetic-p2p-form-key';
  const form=dom.window.document.forms[0];const body=new URLSearchParams([...new dom.window.FormData(form)]);
  const r=await fetch(form.action,{method:form.method,body,redirect:'manual'});await r.body?.cancel();
  for(const name of fields)assert.equal(f.submitted()[name],values[name]);
 }finally{dom.window.close();}
}));
test('HTML entities, quotes, ampersands, Unicode and percent sequences survive once-only encoding',()=>fixture(async f=>{
 const literal=`&amp; &#34; &quot; <literal> " ' %22 + café Ω`;
 const values=Object.fromEntries(fields.map(name=>[name,literal]));const dom=await page(f.base,values);
 try{assertInertAndExact(dom,values);const data=new dom.window.FormData(dom.window.document.forms[0]);for(const name of fields)assert.equal(data.get(name),literal);}finally{dom.window.close();}
}));
test('escaped OAuth fields round-trip through actual authorize redirect and PKCE exchange',()=>fixture(async f=>{
 const verifier='synthetic-verifier-'.repeat(4);const challenge=createHash('sha256').update(verifier).digest('base64url');
 const values={client_id:`client "quoted" & <literal>`,redirect_uri:'https://client.invalid/callback?original=%22%26&keep=1',code_challenge:challenge,code_challenge_method:'S256',state:`state " ' &amp; <tag> + %22 Ω`,scope:`read & "quotes" <literal>`};
 const dom=await page(f.base,values);
 try{
  assertInertAndExact(dom,values);dom.window.document.getElementById('apiKey').value='synthetic-p2p-form-key';
  const form=dom.window.document.forms[0];const r=await fetch(form.action,{method:form.method,body:new URLSearchParams([...new dom.window.FormData(form)]),redirect:'manual'});
  assert.equal(r.status,302);const redirect=new URL(r.headers.get('location'));await r.body?.cancel();
  assert.equal(redirect.origin,'https://client.invalid');assert.equal(redirect.pathname,'/callback');assert.equal(redirect.searchParams.get('original'),'"&');assert.equal(redirect.searchParams.get('keep'),'1');assert.equal(redirect.searchParams.get('state'),values.state);
  for(const name of fields)assert.equal(f.submitted()[name],values[name]);
  const token=await fetch(f.base+'/oauth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'authorization_code',code:redirect.searchParams.get('code'),code_verifier:verifier,redirect_uri:values.redirect_uri})});
  assert.equal(token.status,200);assert.match((await token.json()).access_token,/^mcp_/);
 }finally{dom.window.close();}
}));
test('public landing page does not reflect authorization query values',()=>fixture(async f=>{
 const r=await fetch(f.base+'/?'+new URLSearchParams({scope:attack,state:attack}),{headers:{Accept:'text/html'}});
 assert.equal(r.status,200);const html=await r.text();assert.equal(html.includes(attack),false);assert.equal(html.includes('window.__injected'),false);
}));
