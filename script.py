#!/usr/bin/env python3

import argparse
import base64
import json
import os
import subprocess
from typing import List, Tuple, Optional, Callable
import requests
import tablib
from dataclasses import dataclass

# License categorization sets
GREEN_LICENSES = {"Apache", "Artistic", "Boost", "BSD", "ISC", "MIT", "OpenSSL", "PHP", "SSLeay", "Zlib", "X11"}
YELLOW_LICENSES = {"CDDL", "EPL", "EUPL", "GPL", "LGPL", "MPL"}
RED_LICENSES = {"AGPL", "SSPL", "Business Source License", "CC BY-NC-SA", "Commons Clause License Condition"}

# Environment Variables
FRESHSERVICE_DOMAIN        = os.getenv("FRESHSERVICE_URL")
if not FRESHSERVICE_DOMAIN:
    raise ValueError("FRESHSERVICE_URL environment variable is not set.")
FRESHSERVICE_API_URL       = f"https://{FRESHSERVICE_DOMAIN}/api/v2"
FRESHSERVICE_TICKETS_URL   = f"https://{FRESHSERVICE_DOMAIN}/api/_/tickets"
FRESHSERVICE_ATTACHMENT_URL= f"https://{FRESHSERVICE_DOMAIN}/api/_/attachments"
FRESHSERVICE_NOTES_URL     = f"https://{FRESHSERVICE_DOMAIN}/api/_/tickets"
FRESHSERVICE_API_KEY       = os.getenv("FRESHSERVICE_API_KEY")
SEMGREP_API_KEY            = os.getenv("SEMGREP_API_KEY")
SLACK_WEBHOOK_URL          = os.getenv("SLACK_WEBHOOK_URL")

@dataclass
class ScanResult:
    semgrep_sast: List[List[str]]
    semgrep_sca:  List[List[str]]
    license_issues: List[List[str]]

class RepoProcessor:
    def __init__(self, repo_url: str, ticket_id: str):
        self.repo_url = repo_url
        self.ticket_id = ticket_id
        self.repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        self.default_branch = "main"

    def _get_default_branch(self) -> str:
        try:
            result = subprocess.run(
                ["git","rev-parse","--abbrev-ref","HEAD"],
                cwd=self.repo_name,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except:
            return "main"

    def _get_auth_header(self) -> dict:
        token = f"{FRESHSERVICE_API_KEY}:X"
        encoded = base64.b64encode(token.encode()).decode()
        return {"Authorization": f"Basic {encoded}", "Content-Type": "application/json"}

    def clone_repository(self) -> str:
        subprocess.run(["git","clone",self.repo_url], check=True)
        self.default_branch = self._get_default_branch()
        return self.repo_name

    def assign_to_agent(self, agent_id: int) -> None:
        try:
            requests.put(
                f"{FRESHSERVICE_TICKETS_URL}/{self.ticket_id}",
                headers=self._get_auth_header(),
                json={"responder_id": agent_id}
            )
        except:
            pass

    def create_approval_request(self, agent_id: int) -> Optional[int]:
        try:
            resp = requests.post(
                f"https://{FRESHSERVICE_DOMAIN}/api/_/tickets/{self.ticket_id}/approvals",
                headers=self._get_auth_header(),
                json={"approval_type":1, "email_content":"<div>Approval requested</div>", "notified_to":[agent_id]}
            )
            resp.raise_for_status()
            return resp.json().get('approvals',[{}])[0].get('id')
        except:
            return None

    def update_approval_status(self, approval_id: int, status: int, remark: str) -> None:
        try:
            requests.put(
                f"https://{FRESHSERVICE_DOMAIN}/api/_/approvals/{approval_id}",
                headers=self._get_auth_header(),
                json={"approval_status":status, "remark":remark}
            )
        except:
            pass

    def run_semgrep_scan(
        self,
        dir_name: str,
        operation: str
    ) -> Tuple[
        Tuple[List[str],List[List[str]]],
        Tuple[List[str],List[List[str]]],
        Tuple[List[str],List[List[str]]],
        Tuple[List[str],List[List[str]]]
    ]:
        # Paths
        sast_path    = os.path.join(dir_name, "sast.json")
        sca_path     = os.path.join(dir_name, "sca.json")
        secrets_path = os.path.join(dir_name, "secrets.json")
        license_path = os.path.join(dir_name, "licenses.json")

        def run_scan(cmd: List[str], out: str, label: str):
            try:
                r = subprocess.run(
                    cmd, cwd=dir_name,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={**os.environ, "SEMGREP_API_KEY": SEMGREP_API_KEY}
                )
                if r.stdout:
                    with open(out, 'wb') as f:
                        f.write(r.stdout)
            except:
                pass

        # Always run SAST & SCA
        run_scan(["semgrep","ci","--code","--json","--json-output",sast_path],   sast_path,   "SAST")
        run_scan(["semgrep","ci","--supply-chain","--json","--json-output",sca_path], sca_path, "SCA")
        # Secrets only when open-source
        if operation=='opensource':
            run_scan(["semgrep","ci","--secrets","--json","--json-output",secrets_path], secrets_path, "SECRETS")
        # License detector
        try:
            r = subprocess.run(
                ["license-detector","-f","json","."], cwd=dir_name,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if r.stdout:
                with open(license_path,'wb') as f:
                    f.write(r.stdout)
        except:
            pass

        def safe(path, fn):
            if not os.path.exists(path): return [], []
            try: return fn(path)
            except: return [], []

        return (
            safe(sast_path,    self._process_semgrep),
            safe(sca_path,     self._process_semgrep),
            safe(secrets_path, self._process_semgrep),
            safe(license_path, self._process_licenses)
        )

    def _process_semgrep(self, path: str) -> Tuple[List[str],List[List[str]]]:
        data = json.load(open(path))
        headers = ["Ruleid","Severity","Description","Path","Reference"]
        rows = []
        for rec in data.get('results',[]):
            sev = rec['extra']['severity'].upper().replace('ERROR','HIGH').replace('WARNING','MEDIUM').replace('INFO','LOW')
            url = f"https://github.com/{self.repo_name}/tree/{self.default_branch}/{rec['path']}#L{rec['start']['line']}"
            rows.append([rec.get('check_id',''), sev, rec['extra'].get('message',''), url, rec['extra']['metadata'].get('source','')])
        return headers, rows

    def _process_licenses(self, path: str) -> Tuple[List[str],List[List[str]]]:
        data = json.load(open(path))
        headers = ["Project","File","License","Confidence","Policy"]
        rows = []
        for entry in data if isinstance(data,list) else []:
            proj = entry.get('project','')
            for m in entry.get('matches',[]):
                lic = m.get('license','')
                conf= m.get('confidence',0)
                policy = ('Green License' if lic in GREEN_LICENSES else 'Yellow License' if lic in YELLOW_LICENSES else 'Red License' if lic in RED_LICENSES else 'Other License')
                rows.append([proj, m.get('file',''), lic, str(conf), policy])
        return headers, rows

    def generate_excel_report(self, sast, sca, secrets, lic) -> str:
        book = tablib.Databook()
        for title, hdr, rows in [
            ('SAST Findings', *sast),
            ('SCA Findings',  *sca),
            ('Secrets Findings', *secrets),
            ('License Findings', *lic)
        ]:
            if not hdr:
                hdr = ['Category','Status']; rows=[['No findings','None']]
            book.add_sheet(tablib.Dataset(*rows, headers=hdr, title=title))
        out = f"{self.repo_name}_{self.ticket_id}_compliance_report.xlsx"
        open(out,'wb').write(book.xlsx)
        return out

    def upload_attachment(self, path:str) -> Optional[str]:
        h = self._get_auth_header()
        b64 = base64.b64encode(open(path,'rb').read()).decode()
        payload = {'content':f"data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64}", 'content_file_name':os.path.basename(path), 'content_file_size':os.path.getsize(path), 'content_content_type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
        try:
            r = requests.post(FRESHSERVICE_ATTACHMENT_URL, headers=h, json=payload); r.raise_for_status()
            return r.json().get('id')
        except: return None

    def post_note_to_ticket(self, message:str, attachment_id:Optional[str]) -> None:
        body = {'body':message, 'attachments':[attachment_id] if attachment_id else [], 'private':False}
        try:
            requests.post(f"{FRESHSERVICE_NOTES_URL}/{self.ticket_id}/notes", headers=self._get_auth_header(), json=body)
        except: pass

    def add_private_note_if_needed(self, lic_rows:List[List[str]], secrets_count:int) -> None:
        has_other = any(r[4]=='Other License' for r in lic_rows)
        has_sec   = secrets_count>0
        if has_other or has_sec:
            info = self._get_responder_name()
            if info:
                name,email=info
                body={
                    'body':f"<div>Greetings {name},<br><br>Your expertise is required! The recent compliance scan flagged secret and/or non-standard license findings. Please refer to the attached report for details and advise on next steps.<br><br>Thank you,<br>Your Compliance Bot</div>",
                    'conversation_from_summary':False,'private':True,'notify_emails':[f"{name} <{email}>"]
                }
                requests.post(f"{FRESHSERVICE_NOTES_URL}/{self.ticket_id}/notes", headers=self._get_auth_header(), json=body)

    def _get_responder_name(self) -> Optional[Tuple[str,str]]:
        url = f"{FRESHSERVICE_TICKETS_URL}/{self.ticket_id}?include=responder"
        try:
            r = requests.get(url, headers=self._get_auth_header()); r.raise_for_status()
            t = r.json().get('ticket',{})
            rd = t.get('responder',{}); n=rd.get('name'); e=rd.get('email')
            return (n,e) if n and e else None
        except: return None


def count_by_severity(rows:List[List[str]])->dict:
    c={'CRITICAL':0,'HIGH':0,'MEDIUM':0,'LOW':0}
    for r in rows:
        s=r[1].upper()
        if s in c: c[s]+=1
    return c


def send_slack_notification(webhook_url:str, message:str)->None:
    try: requests.post(webhook_url, json={'text':message})
    except: pass


def main():
    p=argparse.ArgumentParser()
    p.add_argument('repo_url'); p.add_argument('ticket_id'); p.add_argument('agent_id',type=int); p.add_argument('operation',choices=['fork','opensource'])
    args=p.parse_args()

    proc=RepoProcessor(args.repo_url,args.ticket_id)
    approval_id=proc.create_approval_request(args.agent_id)
    proc.assign_to_agent(args.agent_id)

    sast,sca,secrets,lic=proc.run_semgrep_scan(proc.clone_repository(), args.operation)
    report=proc.generate_excel_report(sast,sca,secrets,lic)
    attach_id=proc.upload_attachment(report)

    sc = count_by_severity(sast[1])
    sca_c = count_by_severity(sca[1])
    sec_cnt = len(secrets[1])
    other = any(r[4]=='Other License' for r in lic[1])
    manual = sec_cnt>0 or other

    # Approval only if not manual
    if approval_id and not manual:
        if args.operation=='fork':
            if any(r[4]=='Red License' for r in lic[1]): proc.update_approval_status(approval_id,2,'Rejected: red-list license present.')
            elif sc['CRITICAL']==0 and sc['HIGH']==0: proc.update_approval_status(approval_id,1,'No security issues or red licenses found.')
            else: proc.update_approval_status(approval_id,2,'Rejected: critical/high security issues found.')
        else:
            if any(r[4]=='Red License' for r in lic[1]) or sc['CRITICAL']>0 or sc['HIGH']>0 or sec_cnt>0:
                proc.update_approval_status(approval_id,2,'Rejected for open-sourcing due to security, secrets, or red-license issues.')
            else:
                proc.update_approval_status(approval_id,1,'Approved for open-sourcing: no security, secrets, or red-license issues.')

    # Ticket note
    if manual:
        note_msg = (
            "<div>Automated compliance scan complete.</div>"
            "<div style='margin-top:8px;'>Hello! Your attention is required—secret and/or non-standard license findings were detected. Please review the report attached for details.</div>"
        )
    else:
        note_msg = (
            "<div>Automated compliance scan complete.</div>"
            f"<div style='margin-top:8px;'>{'Heads up: critical/high issues detected—please refer to the attached report.' if sc['CRITICAL']>0 or sc['HIGH']>0 else 'All clear: no critical/high findings. Good to go!!!'}</div>"
        )
    proc.post_note_to_ticket(note_msg, attach_id)
    proc.add_private_note_if_needed(lic[1], sec_cnt)

    # Slack
    approval_str = 'Pending manual review' if manual else ('Approved' if approval_id else 'Unknown')
    issues = ', '.join(f"{k}:{v}" for k,v in {**sc,**sca_c}.items() if v>0) or 'None'
    licenses = ', '.join(f"{r[2]}({r[4]})" for r in lic[1]) or 'None'
    slack_msg = (
        f"🤖 *Compliance Scan Complete!* for {args.repo_url}\n"
        f"{'🚨 Issues detected—see attached report.' if manual else '✅ No blocking issues—request approved!'}\n"
        f"*Findings:* {issues}\n"
        f"*Licenses:* {licenses}\n"
        f"*Approval:* {approval_str}"
    )
    if SLACK_WEBHOOK_URL:
        send_slack_notification(SLACK_WEBHOOK_URL, slack_msg)

if __name__=='__main__':
    main()
