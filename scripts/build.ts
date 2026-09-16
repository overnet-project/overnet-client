import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';
const root = new URL('../', import.meta.url);
const target = process.argv[2] ?? 'firefox';
if (!/^[a-z][a-z0-9-]*$/.test(target) || target === 'common') throw new Error('Usage: npm run build -- <browser>');
const readJSON = async (name: string) => JSON.parse(await readFile(new URL(name, root), 'utf8'));
const [pkg, common, browserManifest] = await Promise.all([readJSON('package.json'), readJSON('manifests/common.json'), readJSON(`manifests/${target}.json`)]);
const output = new URL(`dist/extension/${target}/`, root);
await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const page of ['popup', 'approval']) {
  await mkdir(new URL(`${page}/`, output));
  for (const file of ['index.html', `${page}.css`]) await cp(new URL(`src/extension/${page}/${file}`, root), new URL(`${page}/${file}`, output));
}
const base = { absWorkingDir: fileURLToPath(root), bundle: true, platform: 'browser' as const, target: 'es2022', legalComments: 'eof' as const };
const result = await build({ ...base, entryPoints: ['src/extension/background.ts', 'src/extension/content.ts', 'src/extension/popup/popup.ts', 'src/extension/approval/approval.ts'],
  outbase: 'src/extension', outdir: fileURLToPath(output), format: 'iife', metafile: true });
const sdk = await build({ ...base, entryPoints: ['src/web/index.ts'], outfile: 'dist/web.js', format: 'esm', metafile: true });
await build({ ...base, entryPoints: ['examples/site.ts'], outfile: 'dist/example.js', format: 'esm' });
await writeFile(new URL('dist/build-meta.json', root), `${JSON.stringify({ extension: result.metafile, sdk: sdk.metafile }, null, 2)}\n`);
await cp(new URL('LICENSE', root), new URL('LICENSE', output));
await writeFile(new URL('manifest.json', output), `${JSON.stringify({ ...common, ...browserManifest, version: pkg.version }, null, 2)}\n`);
console.log(`Built ${target}: ${fileURLToPath(output)}`);
