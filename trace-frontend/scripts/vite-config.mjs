import react from '@vitejs/plugin-react';
import {fileURLToPath} from 'node:url';
export default {
 plugins:[react()],
 resolve:{alias:{'@':fileURLToPath(new URL('../src',import.meta.url))}},
 server:{port:5173,host:'127.0.0.1',strictPort:true,proxy:{'/api':{target:process.env.VITE_API_TARGET??'http://127.0.0.1:8005',changeOrigin:true}}},
 build:{target:'es2020',sourcemap:false,chunkSizeWarningLimit:1200},
};
