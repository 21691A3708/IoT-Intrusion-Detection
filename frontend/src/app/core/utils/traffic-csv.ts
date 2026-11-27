import type {
  TrafficFeatures,
} from '../models/prediction.model';

export function parseCsv(text: string): string[][] {

  text = text.replace(/^\uFEFF/, '');

  const rows: string[][] = [];

  let row: string[] = [];
  let field = '';
  let quoted = false;
  let closedQuote = false;

  for (let i = 0; i < text.length; i++) {

    const char = text[i];

    if (quoted) {

      if (char === '"') {

        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
          closedQuote = true;
        }

      } else {
        field += char;
      }

      continue;
    }

    if (
      closedQuote &&
      char !== ',' &&
      char !== '\n' &&
      char !== '\r'
    ) {
      throw new Error('Invalid characters after quoted CSV field.');
    }

    if (char === '"') {

      if (field.length || closedQuote) {
        throw new Error('Unexpected CSV quotation mark.');
      }

      quoted = true;

    } else if (char === ',') {

      row.push(field);
      field = '';
      closedQuote = false;

    } else if (char === '\n' || char === '\r') {

      if (char === '\r' && text[i + 1] === '\n') i++;

      row.push(field);

      if (row.some(value => value.trim() !== '')) {
        rows.push(row);
      }

      row = [];
      field = '';
      closedQuote = false;

    } else {
      field += char;
    }
  }

  if (quoted) {
    throw new Error('CSV contains an unclosed quoted field.');
  }

  row.push(field);

  if (row.some(value => value.trim() !== '')) {
    rows.push(row);
  }

  return rows;
}

export function validateTrafficCsv(
  text: string,
  features: string[]
): TrafficFeatures[] {

  const rows = parseCsv(text);

  if (rows.length < 2) {
    throw new Error('CSV must contain a header and traffic records.');
  }

  if (rows.length - 1 > 10000) {
    throw new Error('Maximum supported upload is 10,000 records.');
  }

  const headers = rows[0].map(value => value.trim());

  if (new Set(headers).size !== headers.length) {
    throw new Error('CSV contains duplicate column names.');
  }

  const missing = features.filter(
    feature => !headers.includes(feature)
  );

  if (missing.length) {
    throw new Error(
      'Missing required features: ' + missing.join(', ')
    );
  }

  const indexes = features.map(
    feature => headers.indexOf(feature)
  );

  return rows.slice(1).map((row, index) => {

    if (row.length !== headers.length) {
      throw new Error(
        `Record ${index + 1}: incorrect column count.`
      );
    }

    const result: Record<string, number> = {};

    features.forEach((feature, position) => {

      const raw = row[indexes[position]].trim();

      const value = Number(raw);

      if (
        !raw ||
        !/^[+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?$/i.test(raw) ||
        !Number.isFinite(value) ||
        !Number.isFinite(Math.fround(value))
      ) {
        throw new Error(
          `Record ${index + 1}: invalid value for ${feature}.`
        );
      }

      result[feature] = value;
    });

    return result as unknown as TrafficFeatures;
  });
}
