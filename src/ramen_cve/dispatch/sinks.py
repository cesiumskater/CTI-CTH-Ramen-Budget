"""ramen_cve.dispatch.sinks — Slack / generic-webhook / email digest
dispatchers + default-dispatcher factory (Layer-3 notification sinks).

Email MIME imports are intentionally function-local. See
README.md and src/ramen_cve/__init__.py.
"""
from __future__ import annotations

import logging
import os
import smtplib
from pathlib import Path

import requests

from ..constants import USER_AGENT
from ..models import EnrichedCve

_log = logging.getLogger(__name__)


class _DispatcherBase:
    """Abstract base for outbound dispatchers (Slack, generic webhook, ...).

    Subclasses set `name`, gate themselves via `enabled()`, and implement
    `dispatch(rec, *, transition=None)` to push one EnrichedCve to the
    configured target. `transition` is the optional
    `(old_bucket, new_bucket)` tuple from `compute_bucket_deltas`;
    when provided the payload should surface it. `dispatch()` must
    NEVER raise — return False on failure.
    """

    name: str = ""

    def enabled(self) -> bool:
        return False

    def dispatch(
        self,
        rec: EnrichedCve,
        *,
        transition: tuple[str | None, str] | None = None,
    ) -> bool:
        raise NotImplementedError


class SlackWebhookDispatcher(_DispatcherBase):
    """Post a Block-Kit summary to a Slack incoming webhook (SLACK_WEBHOOK_URL)."""

    name = "slack"

    def __init__(self, webhook_url: str | None) -> None:
        self.webhook_url = webhook_url

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def _build_payload(
        self,
        rec: EnrichedCve,
        transition: tuple[str | None, str] | None = None,
    ) -> dict:
        emoji = {
            "kev_override": ":rotating_light:",
            "patch_now": ":rotating_light:",
            "plan_and_patch": ":construction:",
            "watch_closely": ":eyes:",
        }.get(rec.bucket, ":pushpin:")
        title = f"{emoji} {rec.cve_id} — {rec.bucket.replace('_', ' ').title()}"
        cvss = f"{rec.cvss_score:.1f}" if rec.cvss_score is not None else "N/A"
        epss = f"{rec.epss_score:.4f}" if rec.epss_score is not None else "N/A"
        body_lines = [
            f"*Action:* {rec.suggested_action}",
            f"*CVSS:* {cvss} ({rec.cvss_severity or 'N/A'}) · *EPSS:* {epss}",
        ]
        if transition is not None:
            old_bucket, new_bucket = transition
            if old_bucket is None:
                body_lines.append("*Status:* first seen")
            else:
                body_lines.append(
                    f"*Transition:* `{old_bucket}` → `{new_bucket}`"
                )
        if rec.kev_listed:
            kev_line = "*CISA KEV:* listed"
            if rec.kev_due_date:
                kev_line += f" (due {rec.kev_due_date})"
            if rec.kev_known_ransomware_use:
                kev_line += " — known ransomware use"
            body_lines.append(kev_line)
        if rec.attack_techniques:
            body_lines.append(f"*ATT&CK:* {', '.join(rec.attack_techniques)}")
        if rec.exploit_status and rec.exploit_status != "none":
            body_lines.append(f"*Exploit Status:* `{rec.exploit_status}`")
        if rec.linked_actors:
            body_lines.append(
                "*Linked Actors:* " + ", ".join(a.name for a in rec.linked_actors)
            )
        if rec.affected_hosts:
            body_lines.append(
                f"*Affected hosts:* {len(rec.affected_hosts)} in inventory"
            )
        return {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": title}},
                {"type": "section", "text": {"type": "mrkdwn",
                                             "text": "\n".join(body_lines)}},
                {
                    "type": "context",
                    "elements": [
                        {
                            "type": "mrkdwn",
                            "text": f"<https://nvd.nist.gov/vuln/detail/{rec.cve_id}|NVD>",
                        }
                    ],
                },
            ]
        }

    def dispatch(
        self,
        rec: EnrichedCve,
        *,
        transition: tuple[str | None, str] | None = None,
    ) -> bool:
        try:
            resp = requests.post(
                self.webhook_url or "",
                json=self._build_payload(rec, transition=transition),
                headers={"User-Agent": USER_AGENT},
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            _log.warning("Slack dispatch failed for %s: %s", rec.cve_id, exc)
            return False


class GenericWebhookDispatcher(_DispatcherBase):
    """POST a JSON-serialized EnrichedCve summary to RAMEN_DISPATCH_WEBHOOK."""

    name = "webhook"

    def __init__(self, webhook_url: str | None) -> None:
        self.webhook_url = webhook_url

    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def _build_payload(
        self,
        rec: EnrichedCve,
        transition: tuple[str | None, str] | None = None,
    ) -> dict:
        payload = {
            "cve_id": rec.cve_id,
            "bucket": rec.bucket,
            "suggested_action": rec.suggested_action,
            "cvss_score": rec.cvss_score,
            "cvss_severity": rec.cvss_severity,
            "epss_score": rec.epss_score,
            "kev_listed": rec.kev_listed,
            "kev_due_date": str(rec.kev_due_date) if rec.kev_due_date else None,
            "kev_known_ransomware_use": rec.kev_known_ransomware_use,
            "cwe": list(rec.cwe),
            "attack_techniques": list(rec.attack_techniques),
            "exploit_status": rec.exploit_status,
            "linked_actors": [a.name for a in rec.linked_actors],
            "linked_malware": [m.name for m in rec.linked_malware],
            "linked_campaigns": [c.name for c in rec.linked_campaigns],
            "affected_hosts": list(rec.affected_hosts),
            "tlp": rec.tlp,
            "admiralty": rec.admiralty,
        }
        if transition is not None:
            old_bucket, new_bucket = transition
            payload["previous_bucket"] = old_bucket
            payload["transition"] = (
                f"{old_bucket or 'first_seen'}->{new_bucket}"
            )
        return payload

    def dispatch(
        self,
        rec: EnrichedCve,
        *,
        transition: tuple[str | None, str] | None = None,
    ) -> bool:
        try:
            resp = requests.post(
                self.webhook_url or "",
                json=self._build_payload(rec, transition=transition),
                headers={"User-Agent": USER_AGENT},
                timeout=15,
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            _log.warning("Webhook dispatch failed for %s: %s", rec.cve_id, exc)
            return False


class EmailDispatcher:
    """SMTP-based daily-digest dispatcher.

    Unlike Slack / generic-webhook dispatchers, this one is BATCH-shaped: it
    sends one email per recipient summarizing the day's high-priority
    findings, with the CSV and Markdown reports attached. The caller is
    _maybe_digest(), which groups findings by inventory owner before invoking
    send_digest() once per recipient.

    Configured entirely via env (no CLI surface area for credentials):
      RAMEN_SMTP_HOST  (required)
      RAMEN_SMTP_PORT  (default 587)
      RAMEN_SMTP_USER  (optional)
      RAMEN_SMTP_PASS  (optional)
      RAMEN_SMTP_FROM  (required — 'From:' header / envelope-from)
      RAMEN_SMTP_USE_TLS=1 (default; set to 0 to disable STARTTLS)
      RAMEN_DIGEST_TO  (fallback recipient when no inventory owner matches)
    """

    name = "email"

    def __init__(
        self,
        host: str | None,
        port: int,
        user: str | None,
        password: str | None,
        sender: str | None,
        use_tls: bool,
        fallback_recipient: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.sender = sender
        self.use_tls = use_tls
        self.fallback_recipient = fallback_recipient

    @classmethod
    def from_env(cls) -> EmailDispatcher:
        """Build a dispatcher from RAMEN_SMTP_* / RAMEN_DIGEST_TO env vars."""

        try:
            port = int(os.getenv("RAMEN_SMTP_PORT") or "587")
        except ValueError:
            port = 587
        use_tls = (os.getenv("RAMEN_SMTP_USE_TLS") or "1").strip().lower() not in (
            "0", "false", "no",
        )
        return cls(
            host=os.getenv("RAMEN_SMTP_HOST") or None,
            port=port,
            user=os.getenv("RAMEN_SMTP_USER") or None,
            password=os.getenv("RAMEN_SMTP_PASS") or None,
            sender=os.getenv("RAMEN_SMTP_FROM") or None,
            use_tls=use_tls,
            fallback_recipient=os.getenv("RAMEN_DIGEST_TO") or None,
        )

    def enabled(self) -> bool:
        """True only when both SMTP host and From address are configured."""
        return bool(self.host) and bool(self.sender)

    def _build_message(
        self,
        recipient: str,
        subject: str,
        body_markdown: str,
        attachments: list[Path],
    ) -> object:
        """Compose a MIME message with a text/plain body and binary attachments."""
        from email.mime.application import MIMEApplication
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        msg = MIMEMultipart()
        msg["From"] = self.sender or ""
        msg["To"] = recipient
        msg["Subject"] = subject
        # Markdown is plain text; if the recipient's client renders MD they get
        # rich formatting, otherwise it reads fine as-is.
        msg.attach(MIMEText(body_markdown, "plain", "utf-8"))
        for path in attachments:
            if not path or not path.exists():
                continue
            try:
                payload = path.read_bytes()
            except OSError as exc:
                _log.warning("Could not attach %s to digest: %s", path, exc)
                continue
            part = MIMEApplication(payload, Name=path.name)
            part["Content-Disposition"] = f'attachment; filename="{path.name}"'
            msg.attach(part)
        return msg

    def send_digest(
        self,
        recipient: str,
        subject: str,
        body_markdown: str,
        attachments: list[Path] | None = None,
    ) -> bool:
        """Send one digest email. Returns True on success, False on any failure."""

        if not self.enabled():
            _log.warning(
                "Email digest is enabled but RAMEN_SMTP_HOST / RAMEN_SMTP_FROM "
                "are not set; nothing was sent."
            )
            return False
        msg = self._build_message(recipient, subject, body_markdown, attachments or [])
        try:
            with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
                if self.use_tls:
                    smtp.starttls()
                if self.user and self.password:
                    smtp.login(self.user, self.password)
                smtp.send_message(msg)
            return True
        except Exception as exc:
            _log.warning("Email digest send to %s failed: %s", recipient, exc)
            return False


def _build_default_dispatchers() -> list[_DispatcherBase]:
    """Build the default ordered list of dispatchers, gated by environment vars."""

    return [
        SlackWebhookDispatcher(os.getenv("SLACK_WEBHOOK_URL") or None),
        GenericWebhookDispatcher(os.getenv("RAMEN_DISPATCH_WEBHOOK") or None),
    ]


# Default bucket transitions worth dispatching on. KEV is highest priority,
# patch_now is next; everything else is too low-signal for a chat ping.
DISPATCH_DEFAULT_BUCKETS: tuple[str, ...] = ("kev_override", "patch_now")

