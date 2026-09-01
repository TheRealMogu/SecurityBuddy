/* A scan with NO OCR layer: page images and nothing else. The document offers
 * no signal at all about type size, which is the case the declared default
 * exists for. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile } from 'fs/promises';
import path from 'path';
const { PDFDocument } = PDFLib;
const { SAVE_OPTIONS } = await import('../../static/js/pdf/pdflib.js');
const SCRATCH = '/tmp/claude-0/-home-user-SecurityBuddy/52ad63a2-b832-5080-8643-042bd0c53c10/scratchpad';

const doc = await PDFDocument.create();
for (const file of ['noocr-1.png', 'noocr-2.png']) {
  const png = await doc.embedPng(new Uint8Array(await readFile(path.join(SCRATCH, file))));
  // A4 at the scan's aspect ratio, image covering the whole page.
  const page = doc.addPage([595, 842]);
  page.drawImage(png, { x: 0, y: 0, width: 595, height: 842 });
}
doc.setTitle('Scanned, no OCR');
doc.setProducer('Scanner (no text layer)');
const out = path.resolve(import.meta.dirname, '../fixtures/pdf/10-scanned-no-ocr.pdf');
await writeFile(out, await doc.save(SAVE_OPTIONS));
console.log('wrote 10-scanned-no-ocr.pdf —', doc.getPageCount(), 'pages, image only');
