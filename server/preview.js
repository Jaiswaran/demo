const AdmZip = require('adm-zip');
const { PDFDocument } = require('pdf-lib');

const MAX_PREVIEW_PAGES = 3;

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function epubTextPreview(buffer) {
  const zip = new AdmZip(buffer);
  const entries = zip.getEntries()
    .filter((entry) => !entry.isDirectory && /\.(xhtml|html|htm)$/i.test(entry.entryName))
    .slice(0, MAX_PREVIEW_PAGES);

  if (!entries.length) throw new Error('EPUB has no readable XHTML/HTML content');

  const sections = entries.map((entry, index) => {
    const raw = entry.getData().toString('utf8');
    const text = raw
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/gi, ' ')
      .replace(/&amp;/gi, '&')
      .replace(/&lt;/gi, '<')
      .replace(/&gt;/gi, '>')
      .replace(/\s+/g, ' ')
      .trim();
    return `<section><div class="page-number">Preview page ${index + 1}</div><p>${escapeHtml(text).slice(0, 12000)}</p></section>`;
  });

  return {
    body: Buffer.from(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>BOOKSPHERE Preview</title><style>body{margin:0;background:#f6f1e7;color:#24342f;font-family:Georgia,serif}.page{max-width:760px;margin:32px auto;padding:0 18px}section{min-height:900px;background:#fffdf8;margin:0 0 28px;padding:48px;box-sizing:border-box;box-shadow:0 10px 35px rgba(0,0,0,.08)}.page-number{font:600 12px system-ui,sans-serif;letter-spacing:.08em;text-transform:uppercase;opacity:.55;margin-bottom:28px}p{font-size:18px;line-height:1.8;white-space:normal}@media(max-width:600px){section{padding:28px;min-height:700px}p{font-size:16px}}</style></head><body><main class="page">${sections.join('')}</main></body></html>`),
    contentType: 'text/html; charset=utf-8',
    pageCount: entries.length
  };
}

async function buildPreview({ buffer, format }) {
  if (format === 'EPUB') return epubTextPreview(buffer);

  const source = await PDFDocument.load(buffer, { ignoreEncryption: false });
  const preview = await PDFDocument.create();
  const pageCount = Math.min(MAX_PREVIEW_PAGES, source.getPageCount());
  const pages = await preview.copyPages(source, Array.from({ length: pageCount }, (_, i) => i));
  pages.forEach((page) => preview.addPage(page));
  const body = Buffer.from(await preview.save());
  return { body, contentType: 'application/pdf', pageCount };
}

module.exports = { buildPreview, MAX_PREVIEW_PAGES };
