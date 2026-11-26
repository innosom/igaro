// Small RFC 4180 CSV parser for credential imports (T-043, ADR 0033). Pure data: nothing is evaluated, no formulas, no
// dialect guessing. Comma delimiter, double-quote quoting with "" escapes, CRLF or LF line ends, optional UTF-8 BOM,
// quoted fields may contain commas and newlines. Hard limits on rows, columns and cell length. Errors carry a fixed code
// and never any cell content.

export class CsvError extends Error {
  constructor(
    readonly code: 'CSV_ENCODING' | 'CSV_MALFORMED' | 'CSV_TOO_MANY_ROWS' | 'CSV_TOO_MANY_COLUMNS' | 'CSV_CELL_TOO_LONG',
    message: string,
  ) {
    super(message);
    this.name = 'CsvError';
  }
}

export interface CsvLimits {
  /** Maximum number of records including the header. */
  maxRecords: number;
  maxColumns: number;
  maxCellChars: number;
}

/** Decode strictly as UTF-8 (invalid sequences and NUL are refused) and drop a leading BOM. */
export function decodeCsv(bytes: Buffer): string {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
  } catch {
    throw new CsvError('CSV_ENCODING', 'The CSV file must be UTF-8 text');
  }
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  if (text.includes('\u0000')) throw new CsvError('CSV_ENCODING', 'The CSV file must be UTF-8 text');
  return text;
}

/** Returns records of raw string cells. Completely blank lines are skipped. */
export function parseCsv(text: string, limits: CsvLimits): string[][] {
  const records: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false; // inside a quoted field
  let afterQuote = false; // a closing quote was just read
  let fieldStarted = false; // the current field has any content or quote (distinguishes a blank line)

  const endCell = () => {
    if (cell.length > limits.maxCellChars) throw new CsvError('CSV_CELL_TOO_LONG', 'A cell is too long');
    row.push(cell);
    if (row.length > limits.maxColumns) throw new CsvError('CSV_TOO_MANY_COLUMNS', 'Too many columns');
    cell = '';
    quoted = false;
    afterQuote = false;
    fieldStarted = false;
  };
  const endRow = () => {
    const blank = row.length === 0 && !fieldStarted;
    if (!blank) {
      endCell();
      records.push(row);
      if (records.length > limits.maxRecords) throw new CsvError('CSV_TOO_MANY_ROWS', 'Too many rows');
    }
    row = [];
    cell = '';
    fieldStarted = false;
  };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i++;
        } else {
          quoted = false;
          afterQuote = true;
        }
      } else {
        cell += ch;
        if (cell.length > limits.maxCellChars) throw new CsvError('CSV_CELL_TOO_LONG', 'A cell is too long');
      }
      continue;
    }
    if (ch === ',') {
      fieldStarted = true;
      endCell();
      fieldStarted = true; // a trailing comma means one more (empty) field follows
      continue;
    }
    if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      endRow();
      continue;
    }
    if (afterQuote) throw new CsvError('CSV_MALFORMED', 'The CSV file is malformed');
    if (ch === '"') {
      if (cell.length > 0) throw new CsvError('CSV_MALFORMED', 'The CSV file is malformed');
      quoted = true;
      fieldStarted = true;
      continue;
    }
    cell += ch;
    fieldStarted = true;
    if (cell.length > limits.maxCellChars) throw new CsvError('CSV_CELL_TOO_LONG', 'A cell is too long');
  }
  if (quoted) throw new CsvError('CSV_MALFORMED', 'The CSV file is malformed');
  endRow();
  return records;
}
