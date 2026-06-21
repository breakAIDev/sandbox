import io
import sys
import tokenize
from pathlib import Path

def strip_blank_and_comments(src: str) -> str:
    out = []
    last_lineno = 1
    last_col = 0

    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        tok_type = tok.type
        tok_str = tok.string
        (sline, scol) = tok.start
        (eline, ecol) = tok.end

        if tok_type == tokenize.COMMENT:
            continue
        if tok_type == tokenize.NL:
            continue
        if tok_type == tokenize.NEWLINE:
            out.append("\n")
            last_lineno = eline
            last_col = 0
            continue
        if tok_type in {tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}:
            continue

        if sline > last_lineno:
            out.append("\n" * (sline - last_lineno))
            last_col = 0
        if scol > last_col:
            out.append(" " * (scol - last_col))

        out.append(tok_str)
        last_lineno = eline
        last_col = ecol

    cleaned = "".join(out)

    # remove blank lines
    cleaned = "\n".join(line for line in cleaned.splitlines() if line.strip()) + "\n"
    return cleaned

if __name__ == "__main__":
    in_file = Path(sys.argv[1])
    out_file = Path(sys.argv[2]) if len(sys.argv) > 2 else in_file.with_name(in_file.stem + "_stripped.py")

    src = in_file.read_text(encoding="utf-8")
    out_file.write_text(strip_blank_and_comments(src), encoding="utf-8")
    print(f"wrote: {out_file}")