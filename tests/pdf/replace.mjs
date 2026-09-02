/* Replacing text that is already on the page. */
import { PDFLib } from './shim.mjs';
import { readFile, writeFile, mkdir } from 'fs/promises';
import { spawnSync } from 'child_process';
import path from 'path';
const { PDFDocument } = PDFLib;
const { loadDocument } = await import('../../static/js/pdf/preserve.js');
const { readableRuns, planReplacement, replaceText } = await import('../../static/js/pdf/replace.js');

const DIR = path.resolve(import.meta.dirname, '../fixtures/pdf');
const OUT = path.join(DIR, 'out');
await mkdir(OUT, { recursive: true });
const open = async (f) => {
  const r = await loadDocument(new Uint8Array(await readFile(path.join(DIR, f))), f);
  if (!r.ok) throw new Error(r.message);
  return r.doc;
};

let fail = 0;
const check = (ok, m) => { if (!ok) { fail++; console.log('    FAIL ' + m); } };

console.log('=== 1. si riesce a LEGGERE il testo esistente? ===');
for (const f of ['09-typographic-roles.pdf', '01-word-export.pdf', '04-accented-cjk.pdf']) {
  const doc = await open(f);
  const runs = readableRuns(doc, doc.getPage(0));
  console.log(`  ${f}: ${runs.length} run leggibili`);
  for (const r of runs.slice(0, 3)) {
    console.log(`     "${r.text.slice(0, 46)}"  [${r.font.name} ${r.size}pt${r.kerned ? ', kerned' : ''}]`);
  }
  check(runs.length > 0, `${f}: nessun run leggibile`);
}

console.log('\n=== 2. sostituzione con font utilizzabile ===');
{
  const doc = await open('09-typographic-roles.pdf');
  const page = doc.getPage(0);
  const runs = readableRuns(doc, page);
  const target = runs.find(r => r.text.includes('AX-1180'));
  check(!!target, 'run AX-1180 non trovato');
  console.log(`  target: "${target.text}" (${target.font.name} ${target.size}pt)`);

  const plan = planReplacement(doc, page, target, 'ZZ-9999-XX');
  console.log(`  piano: blocked=${plan.blocked} face=${plan.face} ` +
              `larghezza ${plan.oldWidth}pt -> ${plan.newWidth}pt (${plan.widthDelta}%)`);
  check(!plan.blocked, 'non doveva essere bloccato');
  check(plan.face === 'Courier', 'deve usare il font originale');
  check(Math.abs(plan.widthDelta) < 5, 'stessa lunghezza -> stessa larghezza');

  const { bytes, report, written } = await replaceText(doc, '09', [
    { pageIndex: 0, runId: target.id, newText: 'ZZ-9999-XX' }]);
  await writeFile(path.join(OUT, '09-typographic-roles--replaced.pdf'), bytes);

  const out = await PDFDocument.load(bytes, { updateMetadata: false });
  const after = readableRuns(out, out.getPage(0)).map(r => r.text);
  console.log(`  testo nel file dopo: ${JSON.stringify(after)}`);
  check(after.some(t => t.includes('ZZ-9999-XX')), 'il testo nuovo deve essere nel file');
  check(!after.some(t => t.includes('AX-1180')), 'il testo VECCHIO deve essere sparito, non coperto');
  console.log(`  avvisi: ${report.rebuilt.filter(e => e.prominent).length} prominenti`);
}

console.log('\n=== 3. glifo mancante -> bloccato, non sostituito ===');
{
  const doc = await open('01-word-export.pdf');
  const page = doc.getPage(0);
  const runs = readableRuns(doc, page);
  const target = runs.find(r => r.text.length > 6);
  console.log(`  target: "${target.text.slice(0, 40)}" (${target.font.name}, subset)`);
  const plan = planReplacement(doc, page, target, 'Verifica QUESTO');
  console.log(`  blocked=${plan.blocked} reason=${plan.reason} missing=${JSON.stringify(plan.missing)}`);
  check(plan.blocked, 'un glifo mancante deve BLOCCARE, non sostituire il font');
  check(plan.reason === 'glyph-missing', 'motivo sbagliato');
}

console.log('\n=== 4. differenza di larghezza segnalata ===');
{
  const doc = await open('09-typographic-roles.pdf');
  const page = doc.getPage(0);
  const runs = readableRuns(doc, page);
  const target = runs.find(r => r.text.includes('AX-1180'));
  const plan = planReplacement(doc, page, target, 'ZZ-9999-XX-MOLTO-PIU-LUNGO');
  console.log(`  larghezza ${plan.oldWidth}pt -> ${plan.newWidth}pt (${plan.widthDelta}%)`);
  console.log(`  note: ${plan.notes.length}`);
  for (const n of plan.notes) console.log(`     ${n.slice(0, 110)}`);
  check(plan.notes.length >= 1, 'una differenza forte deve produrre una nota');
}

console.log('\n=== 5. un run con array di kerning (TJ) non corrompe lo stream ===');
{
  // Un run Tj non ha parentesi quadre, quindi ogni test fatto su un documento
  // senza kerning passava mentre ogni paragrafo di un export Word o LibreOffice
  // sarebbe uscito con "[" aperta e "]" cancellata. Questo caso e' qui perche'
  // il difetto e' arrivato in produzione senza che nessun test lo toccasse.
  const doc = await open('01-word-export.pdf');
  const runs = readableRuns(doc, doc.getPage(0));
  const target = runs.find(r => r.kerned);
  check(!!target, 'serve un run disegnato con TJ e aggiustamenti di coppia');
  console.log(`  target: "${target.text.slice(0, 40)}" [${target.font.name}, TJ]`);

  const { bytes } = await replaceText(doc, '01', [
    { pageIndex: 0, runId: target.id, newText: 'Paragraph 1 with some ordinary' }]);
  const file = path.join(OUT, '01-word-export--replaced-kerned.pdf');
  await writeFile(file, bytes);

  // Poppler segnala gli errori di sintassi su stderr: se lo stream e' rotto,
  // il testo puo' comunque uscire e solo stderr lo dice.
  const proc = spawnSync('pdftotext', [file, '-'], { encoding: 'utf8' });
  const errors = (proc.stderr || '').trim();
  if (errors) console.log(`  stderr di Poppler: ${errors.split('\n')[0]}`);
  check(!/Syntax Error/.test(errors), 'Poppler legge lo stream senza errori di sintassi');
  check(proc.stdout.includes('Paragraph 1 with some ordinary'), 'il testo nuovo c\'e\'');
}

console.log(fail ? `\n${fail} CHECK(S) FAILED` : '\nall in-process checks passed');
