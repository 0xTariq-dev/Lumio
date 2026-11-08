export type SafeAttachmentFinding = {
  id: string;
  title: string;
  explanation: string;
  severity: "informational" | "moderate";
  strength: "direct" | "contextual";
};

const safeAttachmentFindings: Record<string, SafeAttachmentFinding> = {
  "risky-attachment-type": {
    id: "risky-attachment-type",
    title: "Potentially risky attachment type",
    explanation:
      "Attachment metadata indicates a type that can contain or launch executable content. The baseline check inspected only a bounded header prefix; no attachment content was executed.",
    severity: "moderate",
    strength: "contextual",
  },
  "attachment-bounded-inspection": {
    id: "attachment-bounded-inspection",
    title: "Attachment checks were bounded",
    explanation:
      "The baseline check read metadata and at most 16 header bytes within the MIME-part limit. No attachment content was executed; supported document text is parsed only after separate consent.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-pdf": {
    id: "attachment-signature-pdf",
    title: "PDF header marker detected",
    explanation:
      "The first 16 bytes matched a PDF header marker. This signature check does not inspect document content or establish safety.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-zip": {
    id: "attachment-signature-zip",
    title: "ZIP container marker detected",
    explanation:
      "The first 16 bytes matched a ZIP container marker. This signature check does not inspect archive contents or establish safety.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-ole": {
    id: "attachment-signature-ole",
    title: "OLE document marker detected",
    explanation:
      "The first 16 bytes matched an OLE compound-document marker. This signature check does not inspect document contents.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-mz": {
    id: "attachment-signature-mz",
    title: "MZ executable-like marker detected",
    explanation:
      "The first 16 bytes began with MZ. This marker alone does not confirm a valid PE file or indicate malware.",
    severity: "informational",
    strength: "contextual",
  },
  "attachment-signature-mismatch": {
    id: "attachment-signature-mismatch",
    title: "Attachment header differs from declared type",
    explanation:
      "A supported header marker conflicts with the declared filename extension or MIME type. These declarations are untrusted; the baseline check did not inspect full file contents.",
    severity: "moderate",
    strength: "contextual",
  },
};

const fallbackAttachmentFinding: SafeAttachmentFinding = {
  id: "attachment-metadata-indicator",
  title: "Attachment metadata indicator",
  explanation:
    "Attachment metadata and a bounded header prefix were checked. No attachment content was executed; supported document text is parsed only after separate consent.",
  severity: "informational",
  strength: "contextual",
};

export function safeAttachmentFindingCopy(findingId: string): SafeAttachmentFinding {
  return Object.hasOwn(safeAttachmentFindings, findingId)
    ? safeAttachmentFindings[findingId]
    : fallbackAttachmentFinding;
}

export function omitAttachmentDocuments<T extends { attachmentDocuments?: unknown }>(
  report: T,
): Omit<T, "attachmentDocuments"> {
  const { attachmentDocuments: _privateDocuments, ...publicReport } = report;
  return publicReport;
}
