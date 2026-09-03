// Make the browser-shaped modules loadable under node for testing.
//
// The bridge stays here rather than in the modules: fontsource.js fetches its
// font files the way a page does, and a test that let it read the filesystem
// instead would be testing something the browser never runs.
import { createRequire } from 'module';
import { readFileSync } from 'fs';
import path from 'path';

const require = createRequire(import.meta.url);
const ROOT = path.resolve(import.meta.dirname, '../..');
const PDFLib = require(path.join(ROOT, 'static/vendor/pdf-lib/pdf-lib.min.js'));

globalThis.window = {
    PDFLib,
    // fontkit is loaded by injecting a <script> in the browser; under node it is
    // simply present, so loadFontkit() finds it and skips the injection.
    fontkit: require(path.join(ROOT, 'static/vendor/fontkit/fontkit.umd.min.js')),
};

// Serve /static/... from the repo, so relative fetches resolve as they do on
// the page.
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
    const href = String(url);
    if (href.startsWith('/static/')) {
        try {
            const bytes = readFileSync(path.join(ROOT, href.slice(1)));
            return new Response(bytes, { status: 200 });
        } catch {
            return new Response(null, { status: 404 });
        }
    }
    return realFetch(url, init);
};

export { PDFLib };
