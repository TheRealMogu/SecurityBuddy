/* Numeri di pagina, filigrane, intestazioni: tutti STAMPANO in uno stream
 * aggiunto, quindi i byte della pagina non cambiano. E i token {n}/{total}
 * devono espandersi giusti. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { spawnSync } from 'child_process';
import { createHash } from 'crypto';
import path from 'path';

const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { pageContentText } = await import('../../static/js/pdf/textruns.js');
const { addStamp, planStamp } = await import('../../static/js/pdf/stamp.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });

let fail = 0;
const check = (ok, m) => { console.log(`    ${ok ? 'ok  ' : 'FAIL'} ${m}`); if (!ok) fail += 1; };
const open = async (f) => (await loadDocument(new Uint8Array(await readFile(path.join(DIR, f))), f)).doc;
const sha = (s) => createHash('sha256').update(s).digest('hex');

console.log('=== 1. numeri di pagina, e i byte non cambiano ===');
{
    const src = await open('01-word-export.pdf');
    const before = src.getPages().map((p) => pageContentText(src, p).text);

    const doc = await open('01-word-export.pdf');
    const { bytes, stamped } = await addStamp(doc, '01',
        { kind: 'number', text: 'Page {n} of {total}', position: 'bottom-center', size: 10 });
    const file = path.join(OUT, '01-word-export--numbered.pdf');
    await writeFile(file, bytes);
    check(stamped === 3, 'tutte e 3 le pagine numerate');

    const out = (await loadDocument(bytes, 'out')).doc;
    const after = out.getPages().map((p) => pageContentText(out, p).text);
    let intact = true;
    for (let i = 0; i < before.length; i += 1) {
        if (!after[i].startsWith(before[i])) intact = false;
        if (sha(after[i].slice(0, before[i].length)) !== sha(before[i])) intact = false;
    }
    check(intact, 'il contenuto originale di ogni pagina e\' immutato in testa');

    const proc = spawnSync('pdftotext', [file, '-'], { encoding: 'utf8' });
    check(!/Syntax Error/.test(proc.stderr || ''), 'Poppler legge senza errori');
    check(proc.stdout.includes('Page 1 of 3'), 'il numero espanso ("Page 1 of 3") e\' nel file');
    check(proc.stdout.includes('Page 3 of 3'), 'l\'ultima pagina dice "Page 3 of 3"');
}

console.log('\n=== 2. start-at e range ===');
{
    const doc = await open('01-word-export.pdf');
    // numera solo le pagine 2 e 3 (indici 1,2), partendo da 10
    const plan = planStamp(doc, { kind: 'number', pages: [1, 2], startAt: 10 });
    check(plan.items.length === 2, 'solo due pagine nel piano');
    check(plan.items[0].number === 10 && plan.items[1].number === 11, 'partono da 10, 11');
}

console.log('\n=== 3. filigrana: stream aggiunto, opacita\' via ExtGState ===');
{
    const doc = await open('09-typographic-roles.pdf');
    const before = pageContentText(doc, doc.getPage(0)).text;
    const { bytes } = await addStamp(doc, '09',
        { kind: 'watermark', text: 'BOZZA', angle: 45, size: 80 });
    const file = path.join(OUT, '09--watermark.pdf');
    await writeFile(file, bytes);

    const out = (await loadDocument(bytes, 'out')).doc;
    const after = pageContentText(out, out.getPage(0)).text;
    check(after.startsWith(before), 'il contenuto originale e\' ancora in testa');
    check(after.includes('/SBWM gs'), 'usa lo stato grafico di trasparenza');
    const proc = spawnSync('pdftotext', [file, '-'], { encoding: 'utf8' });
    check(!/Syntax Error/.test(proc.stderr || ''), 'Poppler legge la filigrana senza errori');
    // pdftotext non estrae bene il testo ruotato: la prova che la filigrana c'e'
    // sono i byte codificati nello stream ("BOZZA" = 42 4F 5A 5A 41) e il render.
    check(after.includes('<424F5A5A41> Tj'), 'i glifi della filigrana sono scritti nello stream');
    check(proc.stdout.includes('Reference codes'), 'il testo originale si estrae ancora');
}

console.log(fail ? `\n${fail} CHECK FALLITI` : '\ntutti i check passati');
process.exit(fail ? 1 : 0);
