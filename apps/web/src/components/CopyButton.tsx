import { useCopy } from "../hooks/useCopy";
import { Icon } from "./Icon";

export function CopyButton({ text, label }: { text: string; label: string }) {
  const { copied, copy } = useCopy();
  return (
    <button
      type="button"
      className="icon-btn icon-btn--dark"
      onClick={() => void copy(text)}
      aria-label={copied ? "Copié" : label}
      title={copied ? "Copié" : label}
    >
      <Icon name={copied ? "check" : "copy"} size={16} />
    </button>
  );
}

interface CodeBlockProps {
  code: string;
  copyLabel: string;
  /** Commands scroll horizontally instead of wrapping. */
  command?: boolean;
}

export function CodeBlock({ code, copyLabel, command = false }: CodeBlockProps) {
  return (
    <div className="code">
      <pre className={command ? "code__text code__text--scroll" : "code__text"}>{code}</pre>
      <CopyButton text={code} label={copyLabel} />
    </div>
  );
}
