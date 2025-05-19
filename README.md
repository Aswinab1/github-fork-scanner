# 🚀 Repo Fork Scanner Automation Script

A **Python**-based CLI tool that automates 🛡️ code compliance scans with Semgrep and license-detector, uploads reports to Freshservice tickets, and notifies stakeholders via Slack. It streamlines security reviews by creating approval requests, posting detailed notes, and flagging issues for manual verification.

---

## ✨ Features

* 🔍 **SAST & SCA Scans**: Run Semgrep static analysis for code and supply-chain vulnerabilities.
* 🔒 **Secrets Detection**: Optionally detect secrets when open-sourcing.
* 📜 **License Compliance**: Identify open‑source licenses and categorize them (Green, Yellow, Red, Other).
* 📊 **Automated Reporting**: Generate an Excel report with separate sheets for SAST, SCA, secrets, and licenses.
* 🤝 **Freshservice Integration**:

  * Create approval requests.
  * Upload compliance reports as ticket attachments.
  * Post professional notes (public & private) based on findings.
* 📣 **Slack Notifications**: Send branded, contextual notifications to a Slack channel.
* ⚠️ **Manual Verification Flagging**: Skip auto-approval when secret or non-standard license issues are present, and alert the agent for manual review.

---

## 🛠️ Prerequisites

* **Python 3.8+**
* **Semgrep** CLI installed with a valid `SEMGREP_API_KEY`.
* **license-detector** tool installed.
* **Freshservice** account with API access.
* **Slack** workspace with an incoming webhook.

---

## 📦 Installation

1. Clone the repo:

   ```bash
   git clone https://github.com/your_org/compliance-automation.git
   cd compliance-automation
   ```
2. Create & activate a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```
4. Ensure `semgrep` and `license-detector` are on your `$PATH`.

---

## ⚙️ Configuration

Set environment variables before running:

| Variable               | Description                                         |
| ---------------------- | --------------------------------------------------- |
| `FRESHSERVICE_URL`     | Freshservice domain (e.g., `acme.freshservice.com`) |
| `FRESHSERVICE_API_KEY` | API key for Freshservice                            |
| `SEMGREP_API_KEY`      | API key for Semgrep                                 |
| `SLACK_WEBHOOK_URL`    | Slack incoming webhook URL                          |

Example:

```bash
export FRESHSERVICE_URL=acme.freshservice.com
export FRESHSERVICE_API_KEY=your_key
export SEMGREP_API_KEY=your_semgrep_key
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/XXX/YYY/ZZZ
```

---

## 🚀 Usage

```bash
python compliance_script.py <repo_url> <ticket_id> <agent_id> <operation>
```

* `<repo_url>`: Git repo URL to scan.
* `<ticket_id>`: Freshservice ticket ID.
* `<agent_id>`: Agent to assign & notify.
* `<operation>`: `fork` or `opensource`.

### Example

```bash
python compliance_script.py https://github.com/acme/myrepo.git 12345 1001 fork
```

---

## 🔄 Workflow

1. **Approval Request**: Create Freshservice approval and assign agent.
2. **Scan & Report**: Clone repo, run Semgrep & license scans, generate Excel report.
3. **Attachment**: Upload report to the ticket.
4. **Approval Logic**: Auto-approve/reject unless flagged for manual review.
5. **Notes**:

   * Public note summarizing scan results.
   * Private note to agent if manual review is needed.
6. **Slack**: Post a summary notification with findings & approval status.

---

## 🔄 Freshservice Workflow Automator Setup

Leverage Freshservice's built-in Workflow Automator to trigger compliance scans and notifications without external CI:

1. **Navigate to** *Admin > Workflow Automator* in your Freshservice portal.
2. **Create a new workflow**:

   * **Trigger**: Ticket is created or updated (e.g. status changed to “In Progress” or a specific ticket type).
   * **Condition**: Request category is “Development” (or your chosen category for code compliance).
3. **Add Action** → **Trigger webhook**

   * **Method**: `POST`
   * **URL**: `https://api.github.com/repos/{{ticket.custom_fields.github_owner}}/{{ticket.custom_fields.github_repo}}/dispatches`
   * **Headers**:

     ```json
     {
       "Accept": "application/vnd.github.v3+json",
       "Authorization": "token {{ffm GITHUB_TOKEN}}",
       "Content-Type": "application/json"
     }
     ```
   * **Body**:

     ```json
     {
       "event_type": "run-compliance-scan",
       "client_payload": {
         "repo_url": "{{ticket.custom_fields.repo_url}}",
         "ticket_id": {{ticket.id}},
         "agent_id": {{ticket.responder.id}},
         "operation": "{{ticket.custom_fields.operation_type}}"
       }
     }
     ```
4. **Save** and **Activate** the workflow.

> 🚀 Now, whenever a relevant ticket is created or updated, Freshservice will fire the webhook to your compliance endpoint, automatically running scans, attaching reports, posting notes, and sending Slack notifications!

---

## 🤝 Contributing

1. **Fork** the repo.
2. **Create** a feature branch: `git checkout -b feature/name`.
3. **Commit** your changes: `git commit -m "Add feature"`.
4. **Push** to the branch: `git push origin feature/name`.
5. **Open** a Pull Request.

Thank you for contributing! 🎉

