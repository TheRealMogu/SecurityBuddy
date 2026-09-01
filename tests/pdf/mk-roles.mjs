/* A page with two typographic roles stacked close together: a Times heading
 * directly above a Courier block of codes. The gap is deliberately small, so
 * the run nearest a click inside the code block is the END of the heading —
 * geometrically closest, typographically wrong. */
import { PDFLib } from './shim.mjs';
import { writeFile } from 'fs/promises';
import path from 'path';
const { PDFDocument, StandardFonts, rgb } = PDFLib;
const { SAVE_OPTIONS } = await import('../../static/js/pdf/pdflib.js');

const doc = await PDFDocument.create();
const times = await doc.embedFont(StandardFonts.TimesRomanBold);
const courier = await doc.embedFont(StandardFonts.Courier);
const helv = await doc.embedFont(StandardFonts.Helvetica);
const page = doc.addPage([595, 842]);

// Heading in Times Bold, ending far to the right so its last word hangs over
// the start of the code block below.
page.drawText('Reference codes for the quarter', {
    x: 60, y: 700, size: 16, font: times, color: rgb(0, 0, 0) });

// Code block in Courier, starting only 10pt below the heading baseline.
const codes = ['AX-1180-QQ', 'BX-2241-RR', 'CX-3302-SS'];
codes.forEach((code, i) => {
    page.drawText(code, { x: 60, y: 690 - i * 14, size: 10, font: courier });
});

// A body paragraph further down, in Helvetica.
page.drawText('Body paragraph set in a sans face, well away from the others.', {
    x: 60, y: 600, size: 11, font: helv });

doc.setTitle('Typographic roles');
const out = path.resolve(import.meta.dirname, '../fixtures/pdf/09-typographic-roles.pdf');
await writeFile(out, await doc.save(SAVE_OPTIONS));
console.log('wrote 09-typographic-roles.pdf');
console.log('  heading  Times-Bold 16pt  baseline y=700, x=60..~290');
console.log('  codes    Courier   10pt  baselines y=690, 676, 662');
console.log('  body     Helvetica 11pt  baseline y=600');
