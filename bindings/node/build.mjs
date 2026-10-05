// Builds the addon with Cargo and copies it to `proxy-watch.node` beside this file.
import { execFileSync } from 'node:child_process';
import { copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..', '..');
execFileSync('cargo', ['build', '-p', 'proxy-watch-node', '--release'], {
  cwd: root,
  stdio: 'inherit',
});
const name =
  { win32: 'proxy_watch_node.dll', darwin: 'libproxy_watch_node.dylib' }[process.platform] ??
  'libproxy_watch_node.so';
copyFileSync(join(root, 'target', 'release', name), join(here, 'proxy-watch.node'));
