import { build } from 'esbuild';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = path.dirname(fileURLToPath(import.meta.url));
await build({
  absWorkingDir: root, entryPoints: ['shader-engine.mjs'],
  outfile: '../assets/shader-engine.js', bundle: true, minify: true,
  format: 'esm', target: 'es2022', legalComments: 'eof',
  // createShader supports explicitly provided definitions. Exclude the full
  // 200+ component registry; mount() supplies exactly our two definitions.
  plugins: [{name: 'selected-shaders', setup(b) {
    b.onResolve({filter: /\/core\/registry\.js$/}, args =>
      args.importer.replaceAll('\\','/').endsWith('/js/createShader.js')
        ? {path:'selected',namespace:'selected-shaders'} : undefined);
    b.onLoad({filter:/.*/,namespace:'selected-shaders'}, () => ({contents:'export const getAllShaders = () => [];',loader:'js'}));
  }}],
});
const notices = [];
for (const name of ['shaders','typegpu','typed-binary','tinyest','tsover-runtime']) {
  const base=path.join(root,'node_modules',name);
  const pkg=JSON.parse(await readFile(path.join(base,'package.json'),'utf8'));
  let license='';
  for (const file of ['LICENSE','LICENSE.md','LICENSE.txt']) {
    try { license=await readFile(path.join(base,file),'utf8');break; } catch (_) {}
  }
  if (!license) throw Error('Missing license: '+name);
  notices.push(`${name} ${pkg.version}\n${license}`);
}
await writeFile(path.join(root,'../assets/shaders-LICENSE.txt'),notices.join('\n\n---\n\n'));
console.log('Built offline shader engine and third-party notices.');
