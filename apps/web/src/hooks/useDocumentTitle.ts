import { useEffect } from "react";

const APP_NAME = "web-check";

/** Set the browser tab title for the current page; restored on unmount. */
export function useDocumentTitle(title: string | undefined): void {
  useEffect(() => {
    const previous = document.title;
    document.title = title ? `${title} · ${APP_NAME}` : APP_NAME;
    return () => {
      document.title = previous;
    };
  }, [title]);
}
