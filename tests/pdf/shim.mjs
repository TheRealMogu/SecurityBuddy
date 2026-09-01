// Make the browser-shaped modules loadable under node for testing.
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const PDFLib = require('/home/user/SecurityBuddy/static/vendor/pdf-lib/pdf-lib.min.js');
globalThis.window = { PDFLib };
export { PDFLib };
