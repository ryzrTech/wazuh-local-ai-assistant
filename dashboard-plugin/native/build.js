// Build a version-pinned plugin without an entire OpenSearch Dashboards source tree.
// Install esbuild 0.25.12 in an isolated directory and set ESBUILD_PATH to its JS API.
const fs = require('fs');
const path = require('path');
const esbuild = require(process.env.ESBUILD_PATH || 'esbuild');

const root = __dirname;
const shared = {
  react: 'React',
  'react-dom': 'ReactDom',
  '@elastic/eui': 'ElasticEui',
};
const sharedPlugin = {
  name: 'osd-shared-dependencies',
  setup(build) {
    build.onResolve({ filter: /^(react|react-dom|@elastic\/eui)$/ }, (args) => ({
      path: args.path, namespace: 'osd-shared',
    }));
    build.onLoad({ filter: /.*/, namespace: 'osd-shared' }, (args) => ({
      contents: `module.exports = globalThis.__osdSharedDeps__.${shared[args.path]};`,
      loader: 'js',
    }));
  },
};

async function main() {
  const publicDir = path.join(root, 'target', 'public');
  fs.mkdirSync(publicDir, { recursive: true });
  const publicBundle = await esbuild.build({
    entryPoints: [path.join(root, 'public', 'index.ts')],
    bundle: true, write: false, format: 'iife', globalName: 'wazuhLocalAiBundle',
    platform: 'browser', target: 'es2020', loader: { '.css': 'text' },
    plugins: [sharedPlugin], logLevel: 'warning',
  });
  fs.writeFileSync(path.join(publicDir, 'wazuhAiPolicyApply.plugin.js'),
    publicBundle.outputFiles[0].text +
    '\n__osdBundles__.define("plugin/wazuhAiPolicyApply/public", function () { return wazuhLocalAiBundle; }, 0);\n');
  await esbuild.build({
    entryPoints: [path.join(root, 'server', 'index.ts')],
    outfile: path.join(root, 'server', 'index.js'),
    bundle: true, platform: 'node', format: 'cjs', target: 'node18',
    external: ['@osd/config-schema'], logLevel: 'warning',
  });
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
