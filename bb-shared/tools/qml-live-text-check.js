// QML: a BINDING that reads a TextField's or TextArea's `text` - it does not follow typing (KB 1.18: the text
// property is updated on commit - focus lost, Enter - not per keystroke), so a button bound to it stays as it was
// while the user types. Use a mirror property fed by onTextChanging + onTextChanged instead (KB 1.18, 1.26).
//
// Finds, per file, the ids given to TextField / TextArea objects, then every place that reads `<id>.text` as a
// binding: a property's value (`visible: input.text === ""`, `property bool x: field.text !== ""`) or anything
// inside a `prop: { ... }` binding block. Reads inside signal handlers (`onX: ...`) and functions are imperative
// and fine; `<id>.text = ...` is a write; `property alias ...: <id>.text` is an alias. Strings and comments are
// skipped. Exit code 1 when something is found.
//
// Usage: node qml-live-text-check.js file.qml ...
const fs = require('fs');

// The file's text with comments and string contents blanked out (same length, newlines kept), so braces and
// names inside them count for nothing.
function blank(text) {
    let out = '';
    let i = 0;
    while (i < text.length) {
        const c = text[i];
        const n = text[i + 1];
        if (c === '/' && n === '/') {
            while (i < text.length && text[i] !== '\n') {
                out += ' ';
                ++i;
            }
            continue;
        }
        if (c === '/' && n === '*') {
            while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) {
                out += (text[i] === '\n') ? '\n' : ' ';
                ++i;
            }
            out += '  ';
            i += 2;
            continue;
        }
        if (c === '"' || c === "'") {
            out += c;
            ++i;
            while (i < text.length && text[i] !== c && text[i] !== '\n') {
                if (text[i] === '\\') {
                    out += ' ';
                    ++i;
                }
                out += ' ';
                ++i;
            }
            if (i < text.length) {
                out += text[i];
                ++i;
            }
            continue;
        }
        out += c;
        ++i;
    }
    return out;
}

let found = 0;
for (const file of process.argv.slice(2)) {
    const lines = blank(fs.readFileSync(file, 'utf8').replace(/\r/g, '')).split('\n');

    // Pass 1: the ids of TextField / TextArea objects (the id line right inside such a block).
    const textIds = [];
    const typeStack = [];
    for (const line of lines) {
        const opens = (line.match(/\{/g) || []).length;
        const closes = (line.match(/\}/g) || []).length;
        const head = line.match(/^\s*([A-Z][\w.]*)\s*\{/);
        const idMatch = line.match(/^\s*id\s*:\s*([A-Za-z_]\w*)\s*$/);
        if (idMatch && typeStack.length > 0) {
            const owner = typeStack[typeStack.length - 1];
            if (owner === 'TextField' || owner === 'TextArea') {
                textIds.push(idMatch[1]);
            }
        }
        for (let k = 0; k < opens; ++k) {
            typeStack.push((k === 0 && head) ? head[1] : '{');
        }
        for (let k = 0; k < closes; ++k) {
            typeStack.pop();
        }
    }
    if (textIds.length === 0) {
        continue;
    }
    const readRe = new RegExp('\\b(' + textIds.join('|') + ')\\.text\\b(?!\\s*=[^=])');

    // Pass 2: the kind of block every line is in - object, handler, function, binding - and the reads.
    const kinds = [];   // a stack of 'object' / 'handler' / 'function' / 'binding'
    for (let li = 0; li < lines.length; ++li) {
        const line = lines[li];
        const inside = kinds.length > 0 ? kinds[kinds.length - 1] : 'object';
        const prop = line.match(/^\s*(?:readonly\s+)?(?:property\s+[\w<>]+\s+)?([a-zA-Z_][\w.]*)\s*:\s*(.*)$/);
        const isAlias = /^\s*property\s+alias\b/.test(line);
        const isHandler = prop && /^on[A-Z]/.test(prop[1].split('.').pop());
        let report = false;
        if (inside === 'binding' && readRe.test(line)) {
            report = true;
        } else if (inside === 'object' && prop && !isHandler && !isAlias && prop[1] !== 'id' && readRe.test(prop[2])) {
            report = true;
        }
        if (report) {
            ++found;
            console.log(file + ':' + (li + 1) + ': a binding reads ' + line.match(readRe)[0]
                        + ' - not live while typing (KB 1.18); bind a mirror set in onTextChanging + onTextChanged');
        }
        // What the braces on this line open and close.
        const opens = (line.match(/\{/g) || []).length;
        const closes = (line.match(/\}/g) || []).length;
        let kind = inside;
        if (/^\s*function\s/.test(line)) {
            kind = 'function';
        } else if (isHandler && /\{\s*$/.test(line)) {
            kind = 'handler';
        } else if (/^\s*[A-Z][\w.]*\s*\{/.test(line)) {
            kind = 'object';
        } else if (prop && !isHandler && inside === 'object' && /:\s*\{\s*$/.test(line)
                   && !/^\s*[a-z]\w*\s*\{/.test(line)) {
            kind = 'binding';
        } else if (/^\s*[a-z]\w*(\.\w+)?\s*\{/.test(line) && inside === 'object') {
            kind = 'object';   // a grouped property: `input { ... }`, `scrollViewProperties { ... }`
        }
        for (let k = 0; k < opens; ++k) {
            kinds.push(k === 0 ? kind : (kind === 'object' ? 'object' : kind));
        }
        for (let k = 0; k < closes; ++k) {
            kinds.pop();
        }
    }
}
if (found === 0) {
    console.log('no bindings on a text field\'s text');
}
process.exit(found > 0 ? 1 : 0);
