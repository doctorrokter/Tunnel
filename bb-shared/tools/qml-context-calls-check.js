// QML that reaches into C++ by a NAME the C++ no longer has. QML looks `chat.sendVideoNote(...)` up only when the line
// runs, so no build sees a C++ rename: Telega's commit 4cc8b74 (2026-10-03) turned ChatController::sendVideoNote into
// sendStreamNote, and every Send of a video message failed at run time for a month ("chat.sendVideoNote is not a
// function") until GUI 428.
//
// The objects come from the project's own C++: every `setContextProperty("name", object)` in its src/, the object a
// member (`m_chat`), a `new Class(...)`, `Class::instance()`, `this`, or a local (`Class* icons = ...`). Each class's
// QML-visible names are read from its header - Q_INVOKABLE methods, Q_PROPERTY names, public slots, signals - with
// its bases' and QObject's own. The headers: the project's git repository (a monorepo's shared code beside the app -
// Syno/core, Tunnel/client) and bb-shared. Then every `name.member` in the project's QML and JS is
// checked against them: a call must be a method, a slot or a signal; anything else may be any of them.
//
// Comments and strings are skipped. A file that declares the same name itself (an id, a property, a var, a
// parameter) is left out for that name. A class whose base is not in those headers (a DataModel, a CustomControl)
// is listed as not checked: its base's names are not known here. Exit code 1 when a name is missing.
//
// Usage: node qml-context-calls-check.js <project dir> ...   (its src/ and assets/; its repository and bb-shared)
const fs = require('fs');
const path = require('path');

const kSkipDirs = new Set(['node_modules', 'deps', 'third-party', 'thirdparty', '.git', 'arm', 'x86', 'build',
                           'tdlib', 'prebuilt']);
const kQObjectNames = ['objectName', 'objectNameChanged', 'destroyed', 'deleteLater', 'toString'];

// The text with comments blanked out (same length, newlines kept); with `strings` the string contents too, so
// names inside them count for nothing.
function blank(text, strings) {
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
                    out += strings ? ' ' : text[i];
                    ++i;
                }
                out += strings ? ' ' : text[i];
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

function read(file) {
    return fs.readFileSync(file, 'utf8').replace(/\r/g, '');
}

function walk(dir, extensions, out) {
    if (!fs.existsSync(dir)) {
        return out;
    }
    for (const name of fs.readdirSync(dir)) {
        const full = path.join(dir, name);
        const stat = fs.statSync(full);
        if (stat.isDirectory()) {
            if (!kSkipDirs.has(name)) {
                walk(full, extensions, out);
            }
        } else if (extensions.some((extension) => name.endsWith(extension))) {
            out.push(full);
        }
    }
    return out;
}

// bb-shared beside the project or above it (Telega/BBTelega -> ../../bb-shared), "" when there is none.
function findBbShared(projectDir) {
    let dir = path.resolve(projectDir);
    for (let up = 0; up < 4; up++) {
        const candidate = path.join(dir, 'bb-shared');
        if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
            return candidate;
        }
        dir = path.dirname(dir);
    }
    return '';
}

// The git repository the project is in (the folder with .git: the project's own or one above it); the project
// itself when there is none.
function findRepository(projectDir) {
    let dir = path.resolve(projectDir);
    for (let up = 0; up < 3; up++) {
        if (fs.existsSync(path.join(dir, '.git'))) {
            return dir;
        }
        const parent = path.dirname(dir);
        if (parent === dir) {
            break;
        }
        dir = parent;
    }
    return path.resolve(projectDir);
}

// The text from the `{` at `open` to its `}`.
function braceBlock(text, open) {
    let depth = 0;
    for (let i = open; i < text.length; i++) {
        if (text[i] === '{') {
            depth++;
        } else if (text[i] === '}') {
            depth--;
            if (depth === 0) {
                return text.slice(open, i + 1);
            }
        }
    }
    return text.slice(open);
}

// Every class declared in the headers: its bases and the names QML can reach in it.
function readClasses(headers) {
    const classes = new Map();
    for (const file of headers) {
        const text = blank(read(file), true);
        const head = /\bclass\s+(?:[A-Z_][A-Z0-9_]*\s+)?([A-Za-z_]\w*)\s*(?::\s*([^{;]*))?\{/g;
        let match;
        while ((match = head.exec(text)) !== null) {
            const name = match[1];
            const bases = (match[2] || '').split(',')
                .map((base) => base.replace(/\b(public|protected|private|virtual)\b/g, '').trim())
                .map((base) => base.replace(/<.*$/, '').split('::').pop().trim())
                .filter((base) => base !== '');
            const body = braceBlock(text, match.index + match[0].length - 1);
            if (classes.has(name) && classes.get(name).body.length >= body.length) {
                continue;   // a forward declaration's twin, or a smaller class of the same name elsewhere
            }
            classes.set(name, { name: name, bases: bases, body: body, file: file });
        }
    }
    return classes;
}

// The names in a class body that QML can reach: Q_INVOKABLE, Q_PROPERTY, Q_SLOT / Q_SIGNAL, and every method of a
// `public slots:` or `signals:` section.
function namesOf(body) {
    const names = new Set();
    for (const match of body.matchAll(/\bQ_INVOKABLE\b[^;{(]*?\b([A-Za-z_]\w*)\s*\(/g)) {
        names.add(match[1]);
    }
    for (const match of body.matchAll(/\b(?:Q_SLOT|Q_SIGNAL)\b[^;{(]*?\b([A-Za-z_]\w*)\s*\(/g)) {
        names.add(match[1]);
    }
    for (const match of body.matchAll(/\bQ_PROPERTY\s*\(\s*[^)]*?\s([A-Za-z_]\w*)\s+(?:READ|MEMBER|WRITE)\b/g)) {
        names.add(match[1]);
    }
    let reachable = false;
    for (const line of body.split('\n')) {
        const section = line.match(/^\s*(public|protected|private)?\s*(slots|Q_SLOTS|signals|Q_SIGNALS)?\s*:\s*$/);
        if (section && (section[1] || section[2])) {
            reachable = section[2] !== undefined && (section[1] === undefined || section[1] === 'public');
            continue;
        }
        if (reachable) {
            const method = line.match(/\b([A-Za-z_]\w*)\s*\(/);
            if (method && method[1] !== 'Q_SLOT' && method[1] !== 'Q_SIGNAL') {
                names.add(method[1]);
            }
        }
    }
    return names;
}

// A class's names with its bases'; `unknown` gets a base found in no header (other than QObject).
function allNamesOf(className, classes, unknown, seen) {
    const names = new Set(kQObjectNames);
    if (seen.has(className)) {
        return names;
    }
    seen.add(className);
    const found = classes.get(className);
    if (!found) {
        unknown.push(className);
        return names;
    }
    for (const name of namesOf(found.body)) {
        names.add(name);
    }
    for (const base of found.bases) {
        if (base === 'QObject') {
            continue;
        }
        for (const name of allNamesOf(base, classes, unknown, seen)) {
            names.add(name);
        }
    }
    return names;
}

// The argument of `setContextProperty("name", <here>)` - up to its closing parenthesis.
function argumentAt(text, start) {
    let depth = 0;
    for (let i = start; i < text.length; i++) {
        if (text[i] === '(') {
            depth++;
        } else if (text[i] === ')') {
            if (depth === 0) {
                return text.slice(start, i).trim();
            }
            depth--;
        }
    }
    return text.slice(start).trim();
}

// The class an object expression is, or "" when it is a value (QVariant, a number) or not found.
function classOfObject(expression, cppText, at, headerTexts) {
    const created = expression.match(/\bnew\s+([\w:]+)/);
    if (created) {
        return created[1].split('::').pop();
    }
    const single = expression.match(/^([\w:]+)::instance\s*\(\s*\)$/);
    if (single) {
        return single[1].split('::').pop();
    }
    if (expression === 'this') {
        // The class whose method this is: the last `Class::method(` DEFINED before it - a line that starts at the left
        // edge and is no statement (no ';').
        let owner = '';
        for (const match of cppText.slice(0, at).matchAll(/^(?![ \t])[^\n;]*?\b([A-Za-z_]\w*)::~?[A-Za-z_]\w*\s*\([^;\n]*$/gm)) {
            owner = match[1];
        }
        return owner;
    }
    const plain = expression.match(/^&?([A-Za-z_]\w*)$/);
    if (!plain) {
        return '';
    }
    const variable = plain[1];
    const declared = new RegExp('\\b([A-Za-z_][\\w:]*)\\s*(?:<[^>]*>)?\\s*\\*\\s*' + variable + '\\s*[;=)]');
    const pointer = new RegExp('\\bQPointer\\s*<\\s*([\\w:]+)\\s*>\\s*' + variable + '\\b');
    // A local before the call first, then the members in the headers.
    for (const text of [cppText.slice(0, at)].concat(headerTexts)) {
        let last = '';
        for (const match of text.matchAll(new RegExp(declared.source, 'g'))) {
            last = match[1];
        }
        if (last === '') {
            for (const match of text.matchAll(new RegExp(pointer.source, 'g'))) {
                last = match[1];
            }
        }
        if (last !== '' && last !== 'return' && last !== 'delete') {
            return last.split('::').pop();
        }
    }
    return '';
}

// Whether a QML / JS file gives the name a meaning of its own (an id, a property, a var, a parameter, an alias).
function declaresItself(text, name) {
    const word = '\\b' + name + '\\b';
    return new RegExp('\\bid\\s*:\\s*' + name + '\\s*$', 'm').test(text) ||
           new RegExp('\\bproperty\\s+[\\w.<>]+\\s+' + name + '\\b').test(text) ||
           new RegExp('\\b(var|let|const)\\s+' + name + '\\b').test(text) ||
           new RegExp('\\bfunction\\s*\\w*\\s*\\([^)]*' + word + '[^)]*\\)').test(text) ||
           new RegExp('\\bsignal\\s+\\w+\\s*\\([^)]*' + word + '[^)]*\\)').test(text);
}

let missing = 0;
for (const projectArgument of process.argv.slice(2)) {
    const projectDir = path.resolve(projectArgument);
    const srcDir = path.join(projectDir, 'src');
    const assetsDir = path.join(projectDir, 'assets');
    const bbShared = findBbShared(projectDir);
    const repository = findRepository(projectDir);
    const ownHeaders = walk(repository, ['.h', '.hpp'], []);
    const sharedHeaders = (bbShared !== '' && !bbShared.startsWith(repository)) ? walk(bbShared, ['.h', '.hpp'], []) : [];
    const headers = ownHeaders.concat(sharedHeaders);
    const headerTexts = headers.map((file) => blank(read(file), true));
    // A class of the project's own wins over bb-shared's of the same name (BBWeather's Diagnostics, bb-shared's).
    const classes = readClasses(ownHeaders);
    for (const [name, found] of readClasses(sharedHeaders)) {
        if (!classes.has(name)) {
            classes.set(name, found);
        }
    }

    // The objects QML gets by name.
    const objects = new Map();   // name -> { className, where }
    for (const file of walk(srcDir, ['.cpp'], [])) {
        const text = blank(read(file), false);
        for (const match of text.matchAll(/setContextProperty\s*\(\s*(?:QLatin1String\s*\(\s*)?"([A-Za-z_]\w*)"\s*\)?\s*,/g)) {
            const expression = argumentAt(text, match.index + match[0].length);
            const className = classOfObject(expression, text, match.index, headerTexts);
            const line = text.slice(0, match.index).split('\n').length;
            objects.set(match[1], { className: className, expression: expression,
                                    where: path.relative(projectDir, file).split(path.sep).join('/') + ':' + line });
        }
    }

    const checked = new Map();   // name -> its names
    const notChecked = [];
    for (const [name, object] of objects) {
        if (object.className === '') {
            if (!/^QVariant|^[0-9"]|^(true|false)$/.test(object.expression)) {
                notChecked.push(name + ' (' + object.expression + ' - its class not found)');
            }
            continue;
        }
        const unknown = [];
        const names = allNamesOf(object.className, classes, unknown, new Set());
        if (unknown.length > 0) {
            notChecked.push(name + ' (' + object.className + ': ' + unknown.join(', ') + ' not in the headers)');
            continue;
        }
        checked.set(name, names);
    }

    // Every `name.member` in the QML and JS.
    const qmlFiles = walk(assetsDir, ['.qml', '.js'], []);
    let uses = 0;
    for (const file of qmlFiles) {
        const text = blank(read(file), true);
        const lines = text.split('\n');
        for (const [name, names] of checked) {
            if (declaresItself(text, name)) {
                continue;
            }
            const use = new RegExp('(^|[^\\w.$])' + name + '\\s*\\.\\s*([A-Za-z_]\\w*)(\\s*\\()?', 'g');
            lines.forEach((line, index) => {
                for (const match of line.matchAll(use)) {
                    uses++;
                    if (!names.has(match[2])) {
                        missing++;
                        console.log(path.relative(projectDir, file).split(path.sep).join('/') + ':' + (index + 1) +
                                    ': ' + name + '.' + match[2] + (match[3] ? '(...)' : '') + ' - ' +
                                    objects.get(name).className + ' has no ' + match[2] + ' (' +
                                    objects.get(name).where + ')');
                    }
                }
            });
        }
    }

    console.log(path.basename(projectDir) + ': ' + objects.size + ' objects given to QML, ' + checked.size +
                ' checked over ' + qmlFiles.length + ' QML / JS files, ' + uses + ' uses' +
                (notChecked.length > 0 ? '; not checked: ' + notChecked.join('; ') : ''));
}
if (missing > 0) {
    console.log(missing + ' name(s) QML calls that the C++ does not have');
    process.exit(1);
}
console.log('every name QML reaches in C++ is there');
