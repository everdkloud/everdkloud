FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC \
    NODE_ENV=production \
    EVERSMARTNODE_DATA_DIR=/var/lib/eversmartnode \
    EVERSMARTNODE_SECRET_DIR=/var/lib/eversmartnode/secrets \
    EVERSMARTNODE_SUPERVISOR_CONF=/etc/eversmartnode/supervisord.conf \
    LAUNCH_CLUSTER_MANAGED_IMAGE=everdkloud/everdkloud:latest

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod +x /usr/sbin/policy-rc.d \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg bash openssl \
      libssl3 libstdc++6 libsqlite3-0 libfuse3-3 supervisor zstd \
 && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /usr/local/bin/hotpocket /opt/eversmartnode /etc/eversmartnode \
      /var/lib/eversmartnode/secrets /var/lib/eversmartnode/ollama/models /var/log/supervisor

# The HotPocket runtime is bundled in this source tree. No external EverSmartNode
# image is pulled or used as a build/runtime dependency.
COPY runtime/hotpocket/ /usr/local/bin/hotpocket/
COPY runtime/lib/libblake3.so /usr/local/lib/libblake3.so
COPY runtime/lib/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
COPY runtime/lib/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1

RUN chmod 0755 /usr/local/bin/hotpocket/hpcore /usr/local/bin/hotpocket/hpfs /usr/local/bin/hotpocket/hpws \
 && chmod 0644 /usr/local/bin/hotpocket/evernode-license.pdf \
 && ldconfig

WORKDIR /opt/eversmartnode
COPY package.json ./package.json
RUN npm install --omit=dev --no-audit --no-fund \
 && node -e 'const fs=require("fs"),path=require("path");const one=(root,name)=>{const a=[];(function w(d){for(const e of fs.readdirSync(d,{withFileTypes:true})){const q=path.join(d,e.name);e.isDirectory()?w(q):e.name===name&&a.push(q)}})(root);if(a.length!==1)throw new Error(`Expected one ${name} under ${root}, found ${a.length}`);return a[0]};const ep=one(path.resolve("node_modules/everpocket-nodejs-contract"),"EvernodeContext.js");let s=fs.readFileSync(ep,"utf8"),n=s;s=s.replace(/((?:const|let|var)\s+ACQUIRE_ABANDON_LCL_THRESHOLD\s*=\s*)10;/,"$1Number.MAX_SAFE_INTEGER;");if(s===n&&!/ACQUIRE_ABANDON_LCL_THRESHOLD\s*=\s*Number\.MAX_SAFE_INTEGER/.test(s))throw new Error("Acquire abandon threshold signature not found");n=s;const call=/(const|let|var)\s+res\s*=\s*(await|yield)\s+tenantClient\.extractEvernodeEvent\(t\.tx\);/;s=s.replace(call,(m,decl,op)=>`const __esEventType = t.tx?.HookParameters?.find(p => p.name === evernode.HookParamKeys.PARAM_EVENT_TYPE_KEY)?.value;\n                const __esEventData = t.tx?.HookParameters?.find(p => p.name === evernode.HookParamKeys.PARAM_EVENT_DATA_KEY)?.value;\n                if ((__esEventType === evernode.EventTypes.ACQUIRE_SUCCESS || __esEventType === evernode.EventTypes.ACQUIRE_ERROR) && __esEventData && __esEventData !== item.refId) continue;\n                ${decl} res = ${op} tenantClient.extractEvernodeEvent(t.tx);`);if(s===n&&!/__esEventData !== item\.refId/.test(s))throw new Error("EverPocket acquire pre-decrypt correlation signature not found");fs.writeFileSync(ep,s);console.log(`Patched EverPocket acquire pre-decrypt correlation: ${ep}`);' \
 && EP_CTX="$(find node_modules/everpocket-nodejs-contract -type f -name EvernodeContext.js -print -quit)" \
 && test -n "$EP_CTX" \
 && node --check "$EP_CTX" \
 && npm cache clean --force

COPY server.js ./server.js
COPY launch-node-api.js ./launch-node-api.js
COPY install-ollama.sh ./install-ollama.sh
COPY ollama-runner.sh ./ollama-runner.sh
COPY contract/ ./contract/

# Bundle the AutoCluster controller because HotPocket executes consensus state
# without access to /opt/eversmartnode/node_modules.
RUN ./node_modules/.bin/esbuild /opt/eversmartnode/contract/launch-mnemonic.mjs \
      --bundle \
      --platform=browser \
      --format=iife \
      --target=es2020 \
      --outfile=/opt/eversmartnode/contract/launch-mnemonic.js \
 && ./node_modules/.bin/esbuild /opt/eversmartnode/contract/cluster-controller.js \
      --bundle \
      --platform=node \
      --format=cjs \
      --target=node20 \
      --outfile=/tmp/cluster-controller.js \
 && mv /tmp/cluster-controller.js /opt/eversmartnode/contract/cluster-controller.js \
 && WASM_SRC="$(find /opt/eversmartnode/node_modules -type f -path '*/nodejs/blake3_js_bg.wasm' -print -quit)" \
 && test -n "$WASM_SRC" \
 && cp "$WASM_SRC" /opt/eversmartnode/contract/blake3_js_bg.wasm \
 && test -s /opt/eversmartnode/contract/blake3_js_bg.wasm

# Refresh package metadata after our local modifications and controller bundle.
RUN node - <<'NODE'
const fs=require('fs'),crypto=require('crypto'),path=require('path');
const root='/opt/eversmartnode/contract';
const mf=path.join(root,'everadmin.package.json');
const m=JSON.parse(fs.readFileSync(mf,'utf8'));
const roleByPath=new Map((m.files||[]).map(x=>[x.path,x.role||'metadata']));
for (const p of ['cluster-controller.js','sidedish.js','launch-files.js']) roleByPath.set(p,'contract');
for (const p of ['blake3_js_bg.wasm','launch-cluster.css','launch-cluster.js','launch-portal.html','launch-portal.css','launch-portal.js','launch-ai-admin.js','launch-mnemonic.js']) roleByPath.set(p,'metadata');
const all=[...new Set([...(m.files||[]).map(x=>x.path),...roleByPath.keys()])];
m.files=all.filter(name=>fs.existsSync(path.join(root,name))).map(name=>{const b=fs.readFileSync(path.join(root,name));return{path:name,role:roleByPath.get(name)||'metadata',sha256:crypto.createHash('sha256').update(b).digest('hex'),size:b.length};});
m.webFiles=[...new Set([...(m.webFiles||[]),'launch-cluster.css','launch-cluster.js','launch-portal.html','launch-portal.css','launch-portal.js','launch-ai-admin.js','launch-mnemonic.js'])];
fs.writeFileSync(mf,JSON.stringify(m,null,2)+'\n');
NODE

COPY supervisord.conf /etc/eversmartnode/supervisord.conf
COPY supervisorctl /usr/local/bin/eversmartnode-supervisorctl
COPY start.sh /start.sh

RUN chmod 0755 /start.sh /usr/local/bin/eversmartnode-supervisorctl /opt/eversmartnode/install-ollama.sh /opt/eversmartnode/ollama-runner.sh \
 && chmod 0700 /var/lib/eversmartnode/secrets \
 && node --check /opt/eversmartnode/server.js \
 && node --check /opt/eversmartnode/launch-node-api.js \
 && node --check /opt/eversmartnode/contract/cluster-controller.js \
 && node --check /opt/eversmartnode/contract/sidedish.js \
 && node --check /opt/eversmartnode/contract/launch-files.js \
 && node --check /opt/eversmartnode/contract/launch-mnemonic.js \
 && node --check /opt/eversmartnode/contract/launch-cluster.js \
 && node --check /opt/eversmartnode/contract/launch-portal.js \
 && node --check /opt/eversmartnode/contract/launch-ai-admin.js \
 && test -x /opt/eversmartnode/install-ollama.sh \
 && test -x /opt/eversmartnode/ollama-runner.sh \
 && grep -q 'value="5000"' /opt/eversmartnode/contract/index.html \
 && grep -q 'everdkloud/everdkloud:latest' /opt/eversmartnode/contract/index.html \
 && grep -q 'finalBridgeAdd' /opt/eversmartnode/server.js \
 && grep -q 'effectiveRequiredPeers' /opt/eversmartnode/contract/cluster-controller.js \
 && node --version \
 && (/usr/local/bin/hotpocket/hpcore --help >/dev/null 2>&1 || true)

ENV NODE_PATH=/opt/eversmartnode/node_modules \
    LD_LIBRARY_PATH=/usr/local/lib:/usr/lib/x86_64-linux-gnu \
    OLLAMA_HOST=127.0.0.1:11434 \
    OLLAMA_MODELS=/var/lib/eversmartnode/ollama/models \
    OLLAMA_HOME=/var/lib/eversmartnode/ollama \
    EVERSMARTNODE_OLLAMA_BIN=/var/lib/eversmartnode/ollama/current/bin/ollama \
    EVERSMARTNODE_OLLAMA_INSTALL_SCRIPT=/opt/eversmartnode/install-ollama.sh \
    EVERSMARTNODE_OLLAMA_API_KEY_FILE=/var/lib/eversmartnode/secrets/ollama-api.key

LABEL org.opencontainers.image.title="Launch Cluster" \
      org.opencontainers.image.version="0.7.6-independent" \
      org.opencontainers.image.description="Self-contained Ubuntu 24.04 Evernode cluster wizard with bundled HotPocket runtime"

ENTRYPOINT ["/start.sh"]
