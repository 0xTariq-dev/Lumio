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
      "Attachment metadata indicates a type that can contain or launch executable content. Only a bounded header prefix was checked; no content was parsed or executed.",
    severity: "moderate",
    strength: "contextual",
  },
  "attachment-bounded-inspection": {
    id: "attachment-bounded-inspection",
    title: "Attachment checks were bounded",
    explanation:
      "Metadata was checked, and at most 16 header bytes were inspected for attachments within the MIME-part limit. Full contents were not parsed, decompressed, or executed.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-pdf": {
    id: "attachment-signature-pdf",
    title: "PDF header marker detected",
    explanation:
      "The first 16 attachment bytes matched a PDF header marker. The document was not parsed; this does not establish safety.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-zip": {
    id: "attachment-signature-zip",
    title: "ZIP container marker detected",
    explanation:
      "The first 16 attachment bytes matched a ZIP container marker. The archive was not decompressed or inspected.",
    severity: "informational",
    strength: "direct",
  },
  "attachment-signature-ole": {
    id: "attachment-signature-ole",
    title: "OLE document marker detected",
    explanation:
      "The first 16 attachment bytes matched an OLE compound-document marker. The document was not parsed.",
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
      "A supported header marker conflicts with the declared filename extension or MIME type. These declarations are untrusted; no file content was parsed.",
    severity: "moderate",
    strength: "contextual",
  },
};

const fallbackAttachmentFinding: SafeAttachmentFinding = {
  id: "attachment-metadata-indicator",
  title: "Attachment metadata indicator",
  explanation:
    "Attachment metadata and a bounded header prefix were checked. Full file contents were not parsed or executed.",
  severity: "informational",
  strength: "contextual",
};

export function safeAttachmentFindingCopy(findingId: string): SafeAttachmentFinding {
  return Object.hasOwn(safeAttachmentFindings, findingId)
    ? safeAttachmentFindings[findingId]
    : fallbackAttachmentFinding;
}
