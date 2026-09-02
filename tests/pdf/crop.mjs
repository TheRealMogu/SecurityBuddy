/* Cropping by removal. The assertion that matters is not that the output looks
 * cropped — a /CropBox does that — but that the text outside is GONE from the
 * file, checked with a parser that knows nothing about the crop. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { execFileSync } from 'child_process';
import path from 'path';

const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { planCrop, cropPages } = await import('../../static/js/pdf/crop.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });

let fail = 0;
const check = (ok, m) => { if (!ok) { fail += 1; console.log(`    FAIL ${m}`); } else console.log(`    ok   ${m}`); };
const open = async (f) => (await loadDocument(new Uint8Array(await readFile(path.join(DIR, f))), f)).doc;
const textOf = (file) => execFileSync('pdftotext', ['-layout', file, '-'], { encoding: 'utf8' });
/* pdftotext applica il CropBox: serve anche un lettore che guardi il content
 * stream cosi' com'e', altrimenti un test non distingue "rimosso" da "nascosto"
 * — che e' esattamente la differenza che questo strumento esiste per fare. */
const VENV_PY = '/tmp/claude-0/-home-user-SecurityBuddy/52ad63a2-b832-5080-8643-042bd0c53c10/scratchpad/venv/bin/python';

console.log('=== 1. il testo fuori dal ritaglio sparisce DAL FILE ===');
{
    const doc = await open('09-typographic-roles.pdf');
    // Titolo y 696..713.6, codici y 659.5..698.5, paragrafo y 597.2..609.4.
    // Il rettangolo tiene titolo e codici e taglia via il paragrafo, senza
    // attraversare nessuna riga: cosi' il test misura la rimozione, non il
    // rifiuto.
    const rect = { x: 50, y: 650, width: 240, height: 75 };
    const plan = planCrop(doc, doc.getPage(0), rect);
    console.log(`  piano: ${plan.remove.length} da rimuovere, ${plan.split.length} da accorciare, `
        + `${plan.keep.length} intatti, ${plan.blocked.length} non rimovibili`);
    check(plan.blocked.length === 0, 'niente da rifiutare su un taglio pulito');

    const { bytes, report } = await cropPages(doc, '09', [{ pageIndex: 0, rect }]);
    const file = path.join(OUT, '09-typographic-roles--cropped.pdf');
    await writeFile(file, bytes);

    const after = textOf(file);
    check(after.includes('AX-1180-QQ'), 'il testo DENTRO il ritaglio resta');
    check(after.includes('Reference codes'), 'il titolo DENTRO il ritaglio resta');
    check(!after.includes('Body paragraph'), 'il paragrafo FUORI e\' sparito dal file');

    const info = execFileSync('pdfinfo', [file], { encoding: 'utf8' });
    const box = info.split('\n').find((l) => l.startsWith('Page size')) ?? '';
    console.log(`  ${box.trim()}`);
    check(/240(\.\d+)? x 75/.test(box), 'la pagina ha davvero la misura del ritaglio');
    console.log(`  report: ${report.rebuilt.filter((r) => r.prominent).length} voce/i in evidenza`);
}

console.log('\n=== 1b. una riga tagliata di lato viene accorciata, non lasciata intera ===');
{
    const doc = await open('09-typographic-roles.pdf');
    // Il bordo destro cade dentro il titolo, fra "for" (finisce a 194.2) e
    // "the" (inizia a 198.2): la riga si accorcia su un confine di carattere.
    const rect = { x: 50, y: 650, width: 150, height: 75 };
    const plan = planCrop(doc, doc.getPage(0), rect);
    console.log(`  piano: ${plan.remove.length} rimossi, ${plan.split.length} accorciati, `
        + `${plan.blocked.length} non rimovibili`);
    check(plan.split.length === 1, 'il titolo viene accorciato');
    check(plan.blocked.length === 0, 'e non resta niente da rifiutare');

    const { bytes } = await cropPages(doc, '09', [{ pageIndex: 0, rect }]);
    const file = path.join(OUT, '09-typographic-roles--cropped-side.pdf');
    await writeFile(file, bytes);
    const after = textOf(file);
    console.log(`  testo dopo: ${JSON.stringify(after.trim().split('\n')[0])}`);
    check(after.includes('Reference codes for'), 'la parte dentro il bordo resta');
    check(!after.includes('quarter'), 'la parte oltre il bordo e\' sparita dal file');
}

console.log('\n=== 2. il layer OCR invisibile fuori dal ritaglio sparisce ===');
{
    const doc = await open('03-scanned-ocr.pdf');
    const page = doc.getPage(0);
    const { width, height } = page.getSize();
    const rect = { x: 0, y: height / 2, width, height: height / 2 };
    const plan = planCrop(doc, page, rect);
    const textOut = plan.remove.filter((r) => r.kind === 'text').length;
    console.log(`  ${textOut} run di testo invisibile interamente fuori, `
        + `${plan.split.length} da accorciare, ${plan.blocked.length} non rimovibili`);
    const reasons = new Map();
    for (const b of plan.blocked) reasons.set(b.reason, (reasons.get(b.reason) ?? 0) + 1);
    for (const [r, n] of reasons) console.log(`     ${r}: ${n}`);
    check(textOut > 0, 'trova testo invisibile da rimuovere');
    check([...reasons.keys()].includes('image-across-edge'),
          'rifiuta di fingere sull\'immagine che attraversa il bordo');

    let refused = false;
    try { await cropPages(doc, '03', [{ pageIndex: 0, rect }]); }
    catch (err) { refused = !!err.blocked; }
    check(refused, 'senza consenso esplicito l\'operazione si rifiuta');

    const { bytes } = await cropPages(doc, '03', [{ pageIndex: 0, rect }],
                                     { acceptUnremovable: true });
    const file = path.join(OUT, '03-scanned-ocr--cropped.pdf');
    await writeFile(file, bytes);

    // pdftotext rispetta il CropBox, quindi direbbe solo che il testo non si
    // vede piu'. La domanda e' se e' ancora NEL FILE: pypdf decodifica il
    // content stream e ignora il riquadro di pagina.
    const inStream = (f) => execFileSync(
        VENV_PY, ['-c',
            'import sys;from pypdf import PdfReader;'
            + 'print(len(PdfReader(sys.argv[1]).pages[0].extract_text().split()))', f],
        { encoding: 'utf8' }).trim();
    const before = Number(inStream(path.join(DIR, '03-scanned-ocr.pdf')));
    const after = Number(inStream(file));
    console.log(`  parole ricavabili dal content stream: ${before} prima, ${after} dopo`);
    check(after < before, 'il testo invisibile fuori dal ritaglio non e\' piu\' nel file');
    check(after > 0, 'il testo invisibile dentro il ritaglio e\' rimasto');
}

console.log('\n=== 3. un percorso che attraversa il bordo non viene cancellato di nascosto ===');
{
    const doc = await open('02-fillable-form.pdf');
    const page = doc.getPage(0);
    const rect = { x: 40, y: 700, width: 300, height: 60 };
    const plan = planCrop(doc, page, rect);
    console.log(`  ${plan.remove.length} rimovibili, ${plan.blocked.length} non rimovibili`);
    for (const b of plan.blocked) console.log(`     [${b.reason}] ${b.detail.slice(0, 66)}…`);
    check(plan.blocked.every((b) => b.detail.length > 40),
          'ogni cosa non rimovibile viene spiegata, non solo contata');
}

console.log(fail ? `\n${fail} CHECK(S) FAILED` : '\nall checks passed');
process.exit(fail ? 1 : 0);
