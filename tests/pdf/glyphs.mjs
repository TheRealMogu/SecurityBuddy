/* I glifi che il sottoinsieme del documento non ha.
 *
 * Un font incorporato come subset contiene solo i glifi che il documento usava
 * gia': misurato sul corpus, DejaVuSans arriva con 42 caratteri scrivibili e 3
 * maiuscole su 26. Prima di questo, 139 run su 156 cliccabili rifiutavano
 * qualsiasi parola nuova. Il test verifica che ora i glifi mancanti vengano
 * presi da un file di font vero e incorporati, e soprattutto che il resto della
 * pagina non si muova di un byte. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { spawnSync } from 'child_process';
import path from 'path';
import { createHash } from 'crypto';

const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { readableRuns, planEdit, replaceText } = await import('../../static/js/pdf/replace.js');
const { pageContentText } = await import('../../static/js/pdf/textruns.js');
const { normaliseName, hasSource } = await import('../../static/js/pdf/fontsource.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });

let fail = 0;
const check = (ok, m) => { console.log(`    ${ok ? 'ok  ' : 'FAIL'} ${m}`); if (!ok) fail += 1; };
const open = async (f) => (await loadDocument(new Uint8Array(await readFile(path.join(DIR, f))), f)).doc;

console.log('=== 1. il nome del font si confronta senza il prefisso di subset ===');
{
    check(normaliseName('BAAAAA+DejaVuSans') === normaliseName('DejaVu Sans'),
          '"BAAAAA+DejaVuSans" e "DejaVu Sans" sono la stessa faccia');
    check(normaliseName('Calibri') !== normaliseName('DejaVuSans'),
          'facce diverse restano diverse');
    check(hasSource('DejaVuSans') === 'shipped', 'DejaVuSans ha una sorgente');
    check(hasSource('Calibri') === null, 'un font che non abbiamo non ha sorgente');
}

console.log('\n=== 2. si scrivono caratteri che il subset del documento non ha ===');
{
    const doc = await open('01-word-export.pdf');
    const page = doc.getPage(0);
    const run = readableRuns(doc, page).find((r) => r.text.startsWith('Section'));
    const before = pageContentText(doc, page).text;

    const plan = await planEdit(doc, page, run, 'Sezione VZ 42');
    check(!plan.blocked, 'la modifica non e\' piu\' bloccata');
    check(plan.embed?.origin === 'shipped', 'i glifi vengono da un file di font vero');
    check(plan.face === 'DejaVuSans', 'la faccia resta quella del documento');
    check(plan.notes.some((n) => n.includes('"z"')), 'dice quali glifi mancavano');

    const { bytes, written } = await replaceText(doc, '01', [
        { pageIndex: 0, runId: run.id, newText: 'Sezione VZ 42' }]);
    const file = path.join(OUT, '01-word-export--embedded-glyphs.pdf');
    await writeFile(file, bytes);
    check(written[0].fontSource === 'embedded:shipped', 'il report dice da dove vengono i glifi');

    // Poppler: lo stream deve essere sano E il testo nuovo leggibile.
    const proc = spawnSync('pdftotext', [file, '-'], { encoding: 'utf8' });
    const errors = (proc.stderr || '').trim();
    if (errors) console.log(`    stderr: ${errors.split('\n')[0]}`);
    check(!/Syntax Error/.test(errors), 'Poppler legge lo stream senza errori');
    check(proc.stdout.includes('Sezione VZ 42'), 'il testo nuovo e\' nel file');
    check(!proc.stdout.includes('Section 1\n'), 'il testo vecchio e\' sparito');
    check(proc.stdout.includes('Paragraph 1 with some ordinary'), 'il resto della pagina resta');
}

console.log('\n=== 3. la pagina non viene riavvolta in q/Q ===');
{
    // pdf-lib normalizza i content stream se gli si chiede una risorsa font per
    // la strada comoda, e cosi' riscrive byte che nessuno ha chiesto di
    // cambiare. Questo controlla che non succeda.
    const doc = await open('01-word-export.pdf');
    const page = doc.getPage(0);
    const run = readableRuns(doc, page).find((r) => r.text.startsWith('Section'));
    const { bytes } = await replaceText(doc, '01', [
        { pageIndex: 0, runId: run.id, newText: 'Sezione VZ 42' }]);

    const out = (await loadDocument(bytes, 'out')).doc;
    const outPage = out.getPage(0);
    const contents = outPage.node.lookup(PDFLib.PDFName.of('Contents'));
    const count = contents instanceof PDFLib.PDFArray ? contents.size() : 1;
    console.log(`    stream di contenuto in uscita: ${count}`);
    check(count === 1, 'la pagina ha ancora un solo content stream');

    const text = pageContentText(out, outPage).text;
    check(!text.startsWith('q\n'), 'il contenuto non e\' stato avvolto in q/Q');

    // le pagine non toccate devono essere identiche byte per byte
    const source = await open('01-word-export.pdf');
    const sha = (d, p) => createHash('sha256').update(pageContentText(d, p).text).digest('hex');
    for (const i of [1, 2]) {
        check(sha(source, source.getPage(i)) === sha(out, out.getPage(i)),
              `pagina ${i + 1} identica byte per byte`);
    }
}

console.log(fail ? `\n${fail} CHECK FALLITI` : '\ntutti i check passati');
process.exit(fail ? 1 : 0);
