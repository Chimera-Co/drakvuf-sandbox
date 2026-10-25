const common = /^(?:0x[\da-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?[uUlLfF]*)\b/i;
const cWords = new Set(
    "if else return while for switch case break goto sizeof do continue default typedef enum union static extern volatile const struct".split(
        " ",
    ),
);
const cTypes =
    /^(?:void|char|int|long|short|unsigned|signed|float|double|bool|boolean|byte|word|dword|qword|size_t|u?int\d*(?:_t)?|undefined\d*|longlong|ulonglong|code|wchar_t|pointer)$/;
function scan(
    source,
    {
        comments,
        words,
        types = /$a/,
        insensitive = false,
        preprocessor = false,
        variables = /$a/,
        html = false,
    },
) {
    const tokens = [];
    let rest = String(source).slice(0, 524288);
    while (rest.length) {
        let kind = "plain",
            value;
        const comment = comments
            .map((pattern) => rest.match(pattern)?.[0])
            .find(Boolean);
        if (comment) {
            kind = "comment";
            value = comment;
        } else if (preprocessor && /^#[ \t]*\w+[^\n]*/.test(rest)) {
            kind = "preprocessor";
            value = rest.match(/^#[ \t]*\w+[^\n]*/)[0];
        } else if (/^["'`]/.test(rest)) {
            kind = rest[0] === "'" ? "char" : "string";
            value =
                rest.match(
                    /^(?:"(?:\\.|`.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|`(?:\\.|[^`\\])*`?)/,
                )?.[0] || rest[0];
        } else if (common.test(rest)) {
            kind = "number";
            value = rest.match(common)[0];
        } else if (variables.test(rest)) {
            kind = "variable";
            value = rest.match(variables)[0];
        } else if (html && /^<\/?[\w:-]+[^>]*>/.test(rest)) {
            kind = "keyword";
            value = rest.match(/^<\/?[\w:-]+[^>]*>/)[0];
        } else if (/^[a-zA-Z_][\w-]*/.test(rest)) {
            value = rest.match(/^[a-zA-Z_][\w-]*/)[0];
            const word = insensitive ? value.toLowerCase() : value;
            kind = words.has(word)
                ? "keyword"
                : types.test(value)
                  ? "type"
                  : /^\s*\(/.test(rest.slice(value.length))
                    ? "function"
                    : /^\s*:/.test(rest.slice(value.length))
                      ? "label"
                      : "plain";
        } else {
            value = rest.match(/^\s+/)?.[0] || rest[0];
        }
        tokens.push({ kind, text: value });
        rest = rest.slice(value.length);
    }
    return tokens;
}
const cComments = [/^\/\*[\s\S]*?(?:\*\/|$)/, /^\/\/[^\n]*/];
const words = (value) => new Set(value.split(" "));
export const tokenizeC = (text) =>
    scan(text, {
        comments: cComments,
        words: cWords,
        types: cTypes,
        preprocessor: true,
    });
export const tokenizePowerShell = (text) =>
    scan(text, {
        comments: [/^<#[\s\S]*?(?:#>|$)/, /^#[^\n]*/],
        words: words(
            "if else elseif function param return foreach for while switch try catch finally throw begin process end filter in",
        ),
        insensitive: true,
        variables: /^\$[\w:?]+/,
    });
export const tokenizeJavaScript = (text) =>
    scan(text, {
        comments: cComments,
        words: words(
            "if else return function var let const new class extends while for switch case break try catch finally throw async await typeof null true false this import export",
        ),
        types: /^(?:String|Number|Object|Array|Boolean)$/,
    });
export const tokenizeVBScript = (text) =>
    scan(text, {
        comments: [/^'[^\n]*/, /^rem\b[^\n]*/i],
        words: words(
            "dim set sub function end if then else elseif for each next do loop while wend call createobject execute executeglobal eval true false nothing on error resume",
        ),
        insensitive: true,
    });
export const tokenizeBatch = (text) =>
    scan(text, {
        comments: [/^(?:rem\b|::)[^\n]*/i],
        words: words(
            "echo set if else for in do call goto exit start copy del move shift pause not exist defined",
        ),
        insensitive: true,
        variables: /^(?:%[^%\n]+%|![^!\n]+!|%[0-9*])/,
    });
export const tokenizeShell = (text) =>
    scan(text, {
        comments: [/^#[^\n]*/],
        words: words(
            "if then else elif fi for in do done while until case esac function export local return echo eval exec",
        ),
        variables: /^\$(?:\{[^}]*\}|[\w?@#]+)/,
    });
export const tokenizePython = (text) =>
    scan(text, {
        comments: [/^#[^\n]*/],
        words: words(
            "def class if elif else return for in while try except finally import from as with pass raise yield lambda and or not is None True False async await",
        ),
        types: /^(?:str|int|float|bool|list|dict|bytes|set|tuple)$/,
    });
// Annotations (@Override) read as types; JADX's "/* renamed from: */" notes are ordinary comments.
const annotation = /^@[A-Za-z_][\w.]*/;
export const tokenizeJava = (text) =>
    scan(text, {
        comments: cComments,
        words: words(
            "abstract assert break case catch class continue default do else enum extends final finally for if implements import instanceof interface native new package private protected public return static strictfp super switch synchronized this throw throws transient try volatile while var record yield null true false",
        ),
        types: /^(?:void|boolean|byte|char|short|int|long|float|double|String|Object|Integer|Long|Boolean|Class|[A-Z][A-Za-z0-9_]*(?:Exception|Error))$/,
        variables: annotation,
    });
export const tokenizeKotlin = (text) =>
    scan(text, {
        comments: cComments,
        words: words(
            "package import class interface object fun val var if else when for while do return break continue throw try catch finally is in as by companion data sealed enum open override abstract private protected public internal lateinit suspend inline null true false this super",
        ),
        types: /^(?:Unit|Int|Long|Short|Byte|Boolean|Char|Float|Double|String|Any|Nothing|List|Map|Set|Array)$/,
        variables: annotation,
    });
export const tokenizeHTML = (text) =>
    scan(text, {
        comments: [/^<!--[\s\S]*?(?:-->|$)/],
        words: new Set(),
        html: true,
    });
export const tokenizers = {
    c: tokenizeC,
    powershell: tokenizePowerShell,
    javascript: tokenizeJavaScript,
    jscript: tokenizeJavaScript,
    vbscript: tokenizeVBScript,
    batch: tokenizeBatch,
    shell: tokenizeShell,
    python: tokenizePython,
    html: tokenizeHTML,
    hta: tokenizeHTML,
    java: tokenizeJava,
    kotlin: tokenizeKotlin,
    xml: tokenizeHTML,
};
export function tokenize(text, language = "c") {
    return (tokenizers[language] || tokenizeC)(text);
}
