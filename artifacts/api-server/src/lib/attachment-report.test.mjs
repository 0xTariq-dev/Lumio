import assert from "node:assert/strict";
import test from "node:test";

import { safeAttachmentFindingCopy } from "./attachment-report.ts";

test("attachment signature copies are fixed, bounded, and caveated", () => {
  const pdf = safeAttachmentFindingCopy("attachment-signature-pdf");
  const zip = safeAttachmentFindingCopy("attachment-signature-zip");
  const ole = safeAttachmentFindingCopy("attachment-signature-ole");
  const mz = safeAttachmentFindingCopy("attachment-signature-mz");

  assert.match(pdf.explanation, /first 16 attachment bytes/);
  assert.match(zip.explanation, /not decompressed/);
  assert.match(ole.explanation, /not parsed/);
  assert.match(mz.title, /MZ executable-like marker/);
  assert.match(mz.explanation, /does not confirm a valid PE file/);
  for (const finding of [pdf, zip, ole, mz]) {
    assert.equal(finding.severity, "informational");
    assert.equal(finding.id.includes("undefined"), false);
  }
});

test("signature mismatch copy does not expose submitted names or MIME values", () => {
  const finding = safeAttachmentFindingCopy("attachment-signature-mismatch");

  assert.equal(finding.severity, "moderate");
  assert.match(finding.explanation, /filename extension or MIME type/);
  assert.equal(finding.explanation.includes("invoice.exe"), false);
});

test("unknown attachment finding IDs receive safe generic copy", () => {
  const finding = safeAttachmentFindingCopy("<img src=x onerror=alert(1)>");
  const inheritedProperty = safeAttachmentFindingCopy("constructor");

  assert.equal(finding.id, "attachment-metadata-indicator");
  assert.equal(finding.title, "Attachment metadata indicator");
  assert.equal(finding.title.includes("<"), false);
  assert.equal(inheritedProperty.id, "attachment-metadata-indicator");
});
