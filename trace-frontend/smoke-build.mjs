import {build} from 'vite';
import {writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import config from './scripts/vite-config.mjs';
const result=await build({...config,configFile:false,logLevel:'warn',build:{target:'node18',ssr:fileURLToPath(new URL('./smoke.tsx',import.meta.url)),write:false,minify:false,rollupOptions:{output:{entryFileNames:'smoke.bundle.mjs',inlineDynamicImports:true}}}});
for(const chunk of result.output){if(chunk.type==='chunk')await writeFile(new URL(chunk.fileName,import.meta.url),chunk.code);}
