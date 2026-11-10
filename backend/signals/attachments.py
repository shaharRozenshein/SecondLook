"""Signal: risky attachments. Only names and metadata are inspected; file contents are never sent."""

from models import EmailInput, Reason

MAX_CHECKED_ATTACHMENTS = 20
RTL_OVERRIDE = "\u202e"  # invisible character that reverses text direction

EXECUTABLE = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".msi", ".js", ".jse", ".vbs",
              ".vbe", ".wsf", ".hta", ".ps1", ".jar", ".lnk", ".reg", ".iso", ".img"}
DOCUMENT_DISGUISE = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                     ".jpg", ".jpeg", ".png", ".txt", ".zip"}
MACRO_ENABLED = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}
WEB_CONTENT = {".html", ".htm", ".shtml", ".svg"}


def _extensions(name: str) -> list[str]:
    """'invoice.pdf.exe' -> ['.pdf', '.exe']. Trailing dots and spaces (a Windows trick) are ignored."""
    parts = name.lower().strip().rstrip(". ").split(".")
    return ["." + part for part in parts[1:]]


def _classify(name: str) -> tuple[str, str, int] | None:
    """Return (signal, detail, points) for the most serious problem with one file name, or None."""
    if RTL_OVERRIDE in name:
        return ("rtl_override_filename",
                "An attachment name contains a hidden character that reverses text direction "
                "to disguise its real file type", 40)
    extensions = _extensions(name)
    if not extensions:
        return None
    last = extensions[-1]
    if last in EXECUTABLE and len(extensions) >= 2 and extensions[-2] in DOCUMENT_DISGUISE:
        return ("double_extension",
                f"Attachment {name} pretends to be a {extensions[-2]} file but is actually {last}", 40)
    if last in EXECUTABLE:
        return ("executable_attachment",
                f"Attachment {name} is a program or script that can run on your computer", 35)
    if last in WEB_CONTENT:
        return ("web_content_attachment",
                f"Attachment {name} can contain scripts or a fake login form", 25)
    if last in MACRO_ENABLED:
        return ("macro_attachment",
                f"Attachment {name} is an Office file that can contain macros", 20)
    return None


def check_attachments(email: EmailInput) -> list[Reason]:
    findings: dict[str, Reason] = {}
    for attachment in email.attachments[:MAX_CHECKED_ATTACHMENTS]:
        result = _classify(attachment.name)
        if result:
            signal, detail, points = result
            findings.setdefault(signal, Reason(signal=signal, detail=detail, points=points))

    if email.attachment_count > MAX_CHECKED_ATTACHMENTS:
        findings["many_attachments"] = Reason(
            signal="many_attachments",
            detail=f"Unusually many attachments ({email.attachment_count}); "
                   f"only the first {MAX_CHECKED_ATTACHMENTS} were checked",
            points=15)
    return list(findings.values())