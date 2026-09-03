/* Forme disegnate sulla pagina.
 *
 * L'asserzione che conta non e' che la forma si veda, ma che i byte della
 * pagina originale non siano cambiati: una forma va in un content stream
 * AGGIUNTO, non dentro quello che c'era. E che coprire del testo venga detto
 * per quello che e' — nascondere, non rimuovere. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import path from 'path';

const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { pageContentText } = await import('../../static/js/pdf/textruns.js');
const { planShapes, addShapes, rgb } = await import('../../static/js/pdf/shapes.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });

let fail = 0;
const check = (ok, m) => { console.log(`    ${ok ? 'ok  ' : 'FAIL'} ${m}`); if (!ok) fail += 1; };
const open = async (f) => (await loadDocument(new Uint8Array(await readFile(path.join(DIR, f))), f)).doc;

console.log('=== 1. i colori ===');
{
    check(JSON.stringify(rgb('#ffffff')) === '[1,1,1]', 'bianco');
    check(JSON.stringify(rgb('#000')) === '[0,0,0]', 'nero in forma corta');
    check(rgb('non un colore') === null, 'un colore illeggibile non passa per nero');
}

console.log('\n=== 2. i byte della pagina non cambiano ===');
{
    const source = await open('09-typographic-roles.pdf');
    const before = pageContentText(source, source.getPage(0)).text;

    const doc = await open('09-typographic-roles.pdf');
    const { bytes, report } = await addShapes(doc, '09', [
        { kind: 'rectangle', pageIndex: 0, x: 60, y: 400, width: 200, height: 80,
          fill: '#e0f0ef', stroke: '#01696f', strokeWidth: 1.5 },
        { kind: 'ellipse', pageIndex: 0, x: 300, y: 400, width: 160, height: 90,
          stroke: '#b7791f', strokeWidth: 2 },
        { kind: 'line', pageIndex: 0, x: 60, y: 360, width: 400, height: 0,
          stroke: '#c0392b', strokeWidth: 1 },
    ]);
    const file = path.join(OUT, '09-typographic-roles--shapes.pdf');
    await writeFile(file, bytes);

    const out = (await loadDocument(bytes, 'out')).doc;
    const after = pageContentText(out, out.getPage(0)).text;
    check(after.startsWith(before), 'il contenuto originale e\' ancora in testa, immutato');
    check(after.length > before.length, 'le forme sono state aggiunte in coda');

    const sha = (s) => createHash('sha256').update(s).digest('hex');
    check(sha(after.slice(0, before.length)) === sha(before),
          'il flusso originale e\' identico byte per byte');

    const proc = spawnSync('pdftotext', [file, '-'], { encoding: 'utf8' });
    check(!/Syntax Error/.test(proc.stderr || ''), 'Poppler legge lo stream senza errori');
    check(proc.stdout.includes('Reference codes'), 'il testo della pagina e\' intatto');
    console.log(`    report: ${report.preserved.filter((r) => r.item.includes('shape')).length} voce/i sulle forme`);
}

console.log('\n=== 3. coprire il testo viene detto per quello che e\' ===');
{
    const doc = await open('09-typographic-roles.pdf');
    // Un rettangolo pieno sopra il titolo: il gesto che la gente scambia per
    // una redazione.
    const shape = { kind: 'rectangle', pageIndex: 0, x: 55, y: 693, width: 230, height: 24,
                    fill: '#000000' };
    const { plans } = planShapes(doc, [shape]);
    check(plans[0].covered.length > 0, 'il piano sa che c\'e\' del testo sotto');
    console.log(`    copre: ${JSON.stringify(plans[0].covered)}`);

    const { bytes, report } = await addShapes(doc, '09', [shape]);
    const file = path.join(OUT, '09-typographic-roles--covered.pdf');
    await writeFile(file, bytes);

    const warned = report.dropped.find((d) => d.item.includes('underneath a filled shape'));
    check(!!warned, 'il report avvisa che il testo e\' solo nascosto');
    check(warned?.prominent === true, 'ed e\' un avviso in evidenza, non una nota a pie\' di pagina');

    // La prova che l'avviso dice il vero: il testo si estrae ancora.
    const proc = spawnSync('pdftotext', [file, '-'], { encoding: 'utf8' });
    check(proc.stdout.includes('Reference codes for the quarter'),
          'il testo coperto si estrae ancora dal file — l\'avviso non esagera');
}

console.log(fail ? `\n${fail} CHECK FALLITI` : '\ntutti i check passati');
process.exit(fail ? 1 : 0);
