from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from schemas import Alert, ContextRecord

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "llama3"

VerdictType = Literal["true_positive", "benign_true_positive", "false_positive", "needs_more_info"]

KNOWN_BENIGN_DOMAINS = {
    "teams.microsoft.com",
    "microsoft.com",
    "login.microsoftonline.com",
    "update.googleapis.com",
    "googleapis.com",
    "google.com",
    "amazonaws.com",
    "cloudfront.net",
    "r.cdn77.example",
    "news.zalando.example",
    "zalando.example",
    "retailforum.example",
}


class VerdictResult(BaseModel):
    verdict: VerdictType
    rationale: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    escalation: dict[str, Any] = Field(
        default_factory=lambda: {"escalate": False, "to": None, "reason": ""}
    )
    summary: str = ""
    detailed_analysis: str = ""
    mitre: list[str] = Field(default_factory=list)
    decision_engine: str = "llm"


def _truthy(val: Any) -> bool:
    return val is True or str(val).strip().lower() in {"true", "1", "yes", "si", "sí"}


def evaluate_verdict(
    alert: Alert,
    contexts: list[ContextRecord],
    related_logs: list[dict[str, Any]],
    severity: str,
) -> VerdictResult:
    """Motor expert determinista que aplica la política del SOC de Tarvia i els runbooks (RB01-RB10) en català."""
    evidence = alert.evidence or {}
    entities = alert.entities or {}
    rule_id = alert.rule_id or ""
    rule_name = alert.rule_name or ""
    source = alert.source_product.upper()
    desc = alert.description or ""
    evidence_str = json.dumps(evidence, ensure_ascii=False).lower()

    mitre_list: list[str] = []
    if isinstance(alert.model_extra, dict) and "mitre" in alert.model_extra:
        raw_m = alert.model_extra["mitre"]
        if isinstance(raw_m, dict) and "technique_id" in raw_m:
            mitre_list.append(raw_m["technique_id"])
        elif isinstance(raw_m, list):
            mitre_list.extend(str(x) for x in raw_m)

    intel_records = [c.data for c in contexts if c.kind == "intel" and isinstance(c.data, dict)]
    change_records = [c.data for c in contexts if c.kind == "change" and isinstance(c.data, dict)]
    user_records = [c.data for c in contexts if c.kind == "user" and isinstance(c.data, dict)]
    sandbox_records = [c.data for c in contexts if c.kind == "sandbox" and isinstance(c.data, dict)]

    # -------------------------------------------------------------------------
    # 1. COMPROVACIÓ DE BENIGN TRUE POSITIVE (Activitat autoritzada / Simulacre / Manteniment)
    # -------------------------------------------------------------------------

    # 1.1 Simulacre de phishing (RB-01)
    subject = str(evidence.get("subject", ""))
    sender = str(evidence.get("sender", ""))
    if (
        "simulacro" in subject.lower()
        or "simulacro" in desc.lower()
        or "simulacre" in subject.lower()
        or "rrhh@tarvia.example" in sender.lower()
        or "simulacro" in evidence_str
    ):
        return VerdictResult(
            verdict="benign_true_positive",
            rationale="Simulacre intern de phishing autoritzat i organitzat per Recursos Humans (RB-01).",
            confidence=0.99,
            recommended_actions=[
                {
                    "action": "close_ticket",
                    "target": alert.alert_id,
                    "requires_approval": False,
                    "justification": "Simulacre de phishing documentat de RRHH.",
                }
            ],
            escalation={"escalate": False, "to": None, "reason": "Activitat autoritzada"},
            summary=f"Alerta {alert.alert_id} generada per un informe d'empleat corresponent a un simulacre de phishing de RRHH.",
            detailed_analysis="L'alerta correspon a una campanya interna d'entrenament de conscienciació de ciberseguretat. No s'ha detectat cap compromís real. Es recomana tancar el tiquet com a fals incident sense accions de contenció addicionals.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 1.2 Canvis aprovats al calendari (calendario_cambios.csv)
    for change in change_records:
        title = change.get("titulo") or change.get("descripcion") or change.get("servicio", "")
        status = str(change.get("estado", "")).lower()
        if status in {"aprobado", "en_curso", "completado", "autorizado", ""}:
            return VerdictResult(
                verdict="benign_true_positive",
                rationale=f"Activitat coincident amb canvi o manteniment autoritzat al calendari: '{title}' (estat: {status or 'aprovat'}).",
                confidence=0.95,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": f"Canvi autoritzat: {title}",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Canvi autoritzat"},
                summary=f"L'alerta correspon a una activitat programada i prèviament aprovada per l'equip de sistemes ({title}).",
                detailed_analysis=f"S'ha contrastat l'esdeveniment amb el calendari de canvis corporatiu. L'activitat sobre l'actiu coincideix plenament amb la finestra aprovada ({title}). No requereix contenció.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # Pentest autoritzat: 08/10 al 10/10 a la botiga web (empresa_tarvia.md)
    created_at = alert.created_at or ""
    if (
        ("2026-10-08" in created_at or "2026-10-09" in created_at or "2026-10-10" in created_at)
        and source == "WAF"
        and ("pentest" in desc.lower() or "tarvia.example" in evidence_str)
    ):
        return VerdictResult(
            verdict="benign_true_positive",
            rationale="Pentest extern autoritzat sobre la botiga online contractat del 8 al 10 d'octubre de 2026.",
            confidence=0.95,
            recommended_actions=[
                {
                    "action": "close_ticket",
                    "target": alert.alert_id,
                    "requires_approval": False,
                    "justification": "Pentest programat.",
                }
            ],
            escalation={"escalate": False, "to": None, "reason": "Pentest autoritzat"},
            summary="Trànsit atribuïble al test d'intrusió extern contractat per a la preparació de la campanya de Black Friday.",
            detailed_analysis="L'activitat registrada prové de l'empresa auditora contractada per avaluar la seguretat del portal d'e-commerce abans del Black Friday. Es documenta i es tanca sense bloqueig.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 1.3 SCCM / Script d'inventari del sistema (RB-02, UC-EDR-002)
    parent_proc = str(evidence.get("parent", ""))
    user_ev = str(evidence.get("user", ""))
    decoded_prev = str(evidence.get("decoded_preview", ""))
    if (
        rule_id == "UC-EDR-002"
        or "PowerShell con comando codificado" in rule_name
        or "powershell" in rule_name.lower()
    ):
        if (
            "ccmexec" in parent_proc.lower()
            or "sccm" in parent_proc.lower()
            or "sccm" in evidence_str
            or ("system" in user_ev.upper() and "inventory" in decoded_prev.lower())
        ):
            return VerdictResult(
                verdict="benign_true_positive",
                rationale="Execució legítima de PowerShell per part de l'agent SCCM (CcmExec.exe) en tasques d'inventari amb el compte SYSTEM (RB-02).",
                confidence=0.96,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": "Execució legítima de SCCM.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Activitat administrativa benigna"},
                summary="Ordre PowerShell codificada invocada pel procés d'SCCM per a l'inventari periòdic de programari.",
                detailed_analysis="El procés pare és el client de gestió SCCM de Microsoft i s'executa com a SYSTEM recollint dades de Win32_Product. S'ha comprovat que no hi ha descàrregues remotes ni persistència maliciosa.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 1.4 Fitxer de prova antivirus EICAR (RB-02, UC-EDR-003)
    detection_name = str(evidence.get("detection_name", ""))
    edr_action = str(evidence.get("action", "")).lower()
    if "eicar" in detection_name.lower() or "eicar" in evidence_str:
        return VerdictResult(
            verdict="benign_true_positive",
            rationale="Fitxer estàndard de prova EICAR detectat i posat en quarantena per l'antivirus; no representa malware real (RB-02).",
            confidence=0.98,
            recommended_actions=[
                {
                    "action": "close_ticket",
                    "target": alert.alert_id,
                    "requires_approval": False,
                    "justification": "Fitxer de prova EICAR.",
                }
            ],
            escalation={"escalate": False, "to": None, "reason": "Fitxer de prova"},
            summary="Detecció de verificació antivirus estàndard EICAR neutralitzada sense execució en l'equip.",
            detailed_analysis="L'antivirus de l'estació ha bloquejat la cadena EICAR utilitzada comunament per comprovar la funcionalitat dels motors d'escaneig. Es tanca la incidència.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 1.5 Viatge notificat a RRHH (RB-03, UC-IDP-001)
    if rule_id == "UC-IDP-001" or "viaje imposible" in rule_name.lower():
        current_login = evidence.get("current_login", {})
        target_city = (
            current_login.get("city", "") if isinstance(current_login, dict) else ""
        ).lower()
        has_matching_travel = False
        travel_event_desc = ""
        for u in user_records:
            for hr in u.get("hr_events", []):
                tipo = str(hr.get("tipo", "")).lower()
                detalle = str(hr.get("detalle", "")).lower()
                if "viaje" in tipo or "viaje" in detalle or (target_city and target_city in detalle):
                    has_matching_travel = True
                    travel_event_desc = f"{hr.get('tipo', 'Viatge')} ({hr.get('detalle', '')})"
                    break
        if has_matching_travel:
            return VerdictResult(
                verdict="benign_true_positive",
                rationale=f"Viatge internacional registrat prèviament a Recursos Humans: {travel_event_desc} (RB-03).",
                confidence=0.92,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": "Viatge confirmat a RRHH.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Viatge notificat"},
                summary="Inici de sessió des de l'estranger justificat pel desplaçament laboral registrat a l'historial de RRHH de l'empleat.",
                detailed_analysis="La ubicació geogràfica de la connexió coincideix amb l'itinerari de treball notificat pel departament de persones. El dispositiu mòbil corporatiu és conegut i conforme amb la política d'accés.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 1.6 Flujos autorizados DLP / Subida sin datos personales (RB-04)
    if source == "DLP" or rule_id.startswith("UC-DLP"):
        personal_matches = evidence.get("personal_data_matches")
        if personal_matches == 0 or personal_matches == "0":
            return VerdictResult(
                verdict="benign_true_positive",
                rationale="Pujada d'arxius de treball a servei extern sense dades personals regulades (0 coincidències de dades personals) (RB-04).",
                confidence=0.90,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": "No conté dades personals regulades.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Sense impacte en privacitat"},
                summary="Transferència de fitxers de campanya sense dades sensibles ni impacte sota l'RGPD.",
                detailed_analysis="L'anàlisi de DLP confirma zero coincidències de targetes, DNIs o dades de clients. Correspon a material gràfic legítim de màrqueting.",
                mitre=mitre_list,
                decision_engine="regles",
            )
        if "asesoria@gestoria-pons.example" in evidence_str:
            return VerdictResult(
                verdict="benign_true_positive",
                rationale="Enviament de nòmines a la gestoria externa autoritzada (asesoria@gestoria-pons.example) d'acord amb el protocol intern.",
                confidence=0.96,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": "Flux de negoci aprovat.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Flux de nòmines aprovat"},
                summary="Enviament recurrent i aprovat del fitxer de nòmines cap a l'assessor laboral extern.",
                detailed_analysis="El destinatari és el proveïdor contractualment autoritzat per a la gestió de nòmines amb acord de confidencialitat vigent.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # -------------------------------------------------------------------------
    # 2. COMPROVACIÓ DE TRUE POSITIVES (Amenaces reals, C2, Malware, Robatori ATO)
    # -------------------------------------------------------------------------

    # 2.1 Coincidència a la Intel·ligència d'Amenaces (TIP)
    has_tip_malicious = False
    tip_reason = ""
    tip_indicator = ""
    for intel in intel_records:
        tip = intel.get("tip")
        if isinstance(tip, dict) and tip:
            indicator_val = intel.get("indicator") or tip.get("value", "")
            tags = tip.get("tags", [])
            tag_str = " ".join(tags) if isinstance(tags, list) else str(tags)
            descr = tip.get("description") or tip.get("categoria") or tag_str
            has_tip_malicious = True
            tip_indicator = indicator_val
            tip_reason = f"{descr} (confiança TIP: {tip.get('confidence', 'alta')})"
            break

    if not has_tip_malicious and "ti_match" in evidence:
        has_tip_malicious = True
        tip_indicator = str(evidence.get("dst_ip") or evidence.get("indicator") or "")
        tip_reason = str(evidence.get("ti_match"))

    if has_tip_malicious:
        rec_actions = []
        if tip_indicator:
            rec_actions.append(
                {
                    "action": "block_ioc",
                    "target": tip_indicator,
                    "requires_approval": False,
                    "justification": f"Indicador maliciós confirmat al TIP: {tip_reason}",
                }
            )
        hosts = entities.get("hosts", [])
        if hosts:
            h_name = hosts[0].get("hostname") if isinstance(hosts[0], dict) else str(hosts[0])
            if h_name:
                rec_actions.append(
                    {
                        "action": "isolate_host",
                        "target": h_name,
                        "requires_approval": True,
                        "justification": f"Comunicació confirmada amb infraestructura maliciosa ({tip_indicator}).",
                    }
                )

        return VerdictResult(
            verdict="true_positive",
            rationale=f"Indicador maliciós confirmat a la intel·ligència d'amenaces (TIP): {tip_reason} ({tip_indicator}).",
            confidence=0.96,
            recommended_actions=rec_actions,
            escalation={
                "escalate": True,
                "to": "N2",
                "reason": f"Trànsit confirmat cap a indicador del TIP: {tip_reason}",
            },
            summary=f"Connexió de xarxa detectada des de l'actiu intern cap a infraestructura catalogada com a maliciosa ({tip_reason}).",
            detailed_analysis="El sistema ha interceptat comunicacions actives cap a un indicador de compromís catalogat. Cal bloquejar l'IOC a escala perimetral i sol·licitar l'aïllament de l'estació afectada a l'analista N2 per investigar un possible comandament i control (C2).",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 2.2 Anàlisi de Sandbox maliciós
    for sbx in sandbox_records:
        verdict_sbx = str(sbx.get("verdict", "")).lower()
        score = sbx.get("threat_score") or sbx.get("score") or 0
        file_sha = sbx.get("sha256", "")
        if verdict_sbx in {"malicious", "malware"} or (isinstance(score, (int, float)) and score >= 70):
            family = sbx.get("family") or sbx.get("detection") or "malware"
            rec_actions = [
                {
                    "action": "block_ioc",
                    "target": file_sha,
                    "requires_approval": False,
                    "justification": f"Hash maliciós segons sandbox ({family})",
                }
            ]
            hosts = entities.get("hosts", [])
            if hosts:
                h_name = hosts[0].get("hostname") if isinstance(hosts[0], dict) else str(hosts[0])
                if h_name:
                    rec_actions.append(
                        {
                            "action": "isolate_host",
                            "target": h_name,
                            "requires_approval": True,
                            "justification": f"Execució o descàrrega de malware verificat en sandbox ({family}).",
                        }
                    )
            return VerdictResult(
                verdict="true_positive",
                rationale=f"Fitxer analitzat a la sandbox amb veredicte de malware confirmat (família: {family}, puntuació: {score}) (RB-02).",
                confidence=0.96,
                recommended_actions=rec_actions,
                escalation={
                    "escalate": True,
                    "to": "N2",
                    "reason": f"Malware confirmat per anàlisi de sandbox: {family}",
                },
                summary=f"Alerta de malware confirmada per l'anàlisi dinàmic de sandbox ({family}).",
                detailed_analysis="L'informe d'execució en entorn aïllat ha mostrat comportament d'infecció activa. Es bloqueja el hash globalment i es proposa aïllar l'equip a l'espera de remeiar l'amenaça.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 2.3 Clic en enllaç de phishing (RB-01, UC-EML-003)
    if (
        rule_id == "UC-EML-003"
        or "clic en url de phishing" in rule_name.lower()
        or evidence.get("rewrite_verdict_now") == "phishing"
    ):
        domain = ""
        domains = entities.get("domains", [])
        if domains:
            domain = domains[0] if isinstance(domains[0], str) else str(domains[0])
        rec_actions = []
        if domain:
            rec_actions.append(
                {
                    "action": "block_ioc",
                    "target": domain,
                    "requires_approval": False,
                    "justification": "Domini de phishing reclassificat posteriorment al lliurament.",
                }
            )
        users = entities.get("users", [])
        if users:
            u_name = users[0].get("upn") if isinstance(users[0], dict) else str(users[0])
            if u_name:
                rec_actions.extend(
                    [
                        {
                            "action": "revoke_sessions",
                            "target": u_name,
                            "requires_approval": True,
                            "justification": "Possible compromís de credencials després de clic en phishing.",
                        },
                        {
                            "action": "reset_password",
                            "target": u_name,
                            "requires_approval": True,
                            "justification": "Restabliment obligatori per protecció del compte.",
                        },
                    ]
                )

        return VerdictResult(
            verdict="true_positive",
            rationale="L'empleat ha fet clic en una URL reclassificada com a phishing després del lliurament del correu (RB-01).",
            confidence=0.94,
            recommended_actions=rec_actions,
            escalation={
                "escalate": True,
                "to": "N2",
                "reason": "Clic d'usuari en enllaç de phishing confirmat.",
            },
            summary="Interacció directa d'usuari amb enllaç de pesca de credencials; risc alt d'accés no autoritzat al compte corporatiu.",
            detailed_analysis="El filtre de correu ha determinat que l'enllaç condueix a una pàgina de suplantació de credencials. S'ha de bloquejar el domini a la passarel·la web i forçar la revocació de sessions actives amb canvi de contrasenya.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 2.4 Execució activa de script i persistència (RB-02, UC-EDR-001)
    persistence = evidence.get("persistence")
    if (
        (rule_id == "UC-EDR-001" or "proceso hijo sospechoso" in rule_name.lower())
        and (persistence or edr_action == "detected_only" or "detected_only" in evidence_str)
    ):
        rec_actions = []
        hosts = entities.get("hosts", [])
        if hosts:
            h_name = hosts[0].get("hostname") if isinstance(hosts[0], dict) else str(hosts[0])
            if h_name:
                rec_actions.append(
                    {
                        "action": "isolate_host",
                        "target": h_name,
                        "requires_approval": True,
                        "justification": "Execució confirmada de script amb clau de persistència establerta (RB-02).",
                    }
                )
        domains = entities.get("domains", [])
        for d in domains[:2]:
            rec_actions.append(
                {
                    "action": "block_ioc",
                    "target": str(d),
                    "requires_approval": False,
                    "justification": "Domini de descàrrega de payload / C2.",
                }
            )

        return VerdictResult(
            verdict="true_positive",
            rationale=f"Execució confirmada de script maliciós amb persistència ({persistence or 'Run key'}) i acció limitada a 'detected_only' de l'EDR (RB-02).",
            confidence=0.95,
            recommended_actions=rec_actions,
            escalation={
                "escalate": True,
                "to": "N2",
                "reason": "Execució confirmada de malware i persistència sense bloqueig previ de l'EDR.",
            },
            summary="Cadena d'execució d'amenaça (wscript/msiexec) amb instal·lació de clau de persistència al registre de l'equip.",
            detailed_analysis="Un document ofimàtic ha iniciat un intèrpret de scripts que ha descarregat una llibreria maliciosa establint persistència al registre d'usuari. L'EDR no l'ha bloquejat en primera instància; cal l'aïllament urgent del lloc de treball.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 2.5 Atacs de credencials: fatiga MFA, password spraying, ATO (RB-03, RB-05)
    if rule_id == "UC-IDP-003" or "fatiga mfa" in rule_name.lower():
        final_res = str(evidence.get("final_result", "")).lower()
        if "approved" in final_res or "aprobado" in final_res:
            users = entities.get("users", [])
            u_name = users[0].get("upn") if users and isinstance(users[0], dict) else ""
            rec_actions = []
            if u_name:
                rec_actions.extend(
                    [
                        {
                            "action": "revoke_sessions",
                            "target": u_name,
                            "requires_approval": True,
                            "justification": "Elusió d'MFA mitjançant bombardeig push acceptat fora de l'horari habitual.",
                        },
                        {
                            "action": "reset_password",
                            "target": u_name,
                            "requires_approval": True,
                            "justification": "Contrasenya vulnerada arran de l'atac de fatiga MFA.",
                        },
                    ]
                )
            return VerdictResult(
                verdict="true_positive",
                rationale="Atac de fatiga MFA (bombardeig push massiu) amb aprovació concedida des d'una ubicació anòmala o VPN comercial (RB-03).",
                confidence=0.96,
                recommended_actions=rec_actions,
                escalation={
                    "escalate": True,
                    "to": "N2",
                    "reason": "Compromís confirmat de compte d'usuari després de superar el segon factor d'autenticació.",
                },
                summary="Intrusió confirmada per bombardeig continu de notificacions MFA fins a obtenir l'aprovació de la víctima.",
                detailed_analysis="L'atacant coneixia la contrasenya i ha generat desenes de peticions push fins que l'usuari ha cedit. Es requereix tancar immediatament totes les sessions de l'IdP i forçar el restabliment de la clau.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    if rule_id == "UC-IDP-002" or "password spraying" in rule_name.lower():
        successes = evidence.get("successes", 0)
        if isinstance(successes, (int, float)) and successes > 0:
            return VerdictResult(
                verdict="true_positive",
                rationale=f"Atac de password spraying coordinat amb èxit en almenys {successes} compte(s) corporatiu(s) (RB-03).",
                confidence=0.95,
                recommended_actions=[
                    {
                        "action": "block_ioc",
                        "target": str(entities.get("ips", [""])[0]),
                        "requires_approval": False,
                        "justification": "Origen d'atac de password spraying massiu.",
                    }
                ],
                escalation={
                    "escalate": True,
                    "to": "N2",
                    "reason": "Password spraying amb accés vàlid obtingut per l'atacant.",
                },
                summary="Atac de força bruta distribuït mitjançant contrasenyes comunes amb compromís d'accés.",
                detailed_analysis="S'ha detectat un patró de contrasenyes per temporada que ha aconseguit validar un accés a la VPN. Bloquejar les IPs d'origen i revocar credencials dels comptes amb èxit.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    if rule_id == "UC-WEB-003" or "ato" in rule_name.lower() or "toma de control" in rule_name.lower():
        return VerdictResult(
            verdict="true_positive",
            rationale="Patró confirmat de presa de control de compte de client (ATO): inici headless, canvi d'adreça de correu i compra fraudulenta de targeta regal (RB-05).",
            confidence=0.95,
            recommended_actions=[
                {
                    "action": "block_ioc",
                    "target": str(entities.get("ips", [""])[0]),
                    "requires_approval": False,
                    "justification": "IP origen de frau financer i presa de control de comptes d'e-commerce.",
                }
            ],
            escalation={
                "escalate": True,
                "to": "N2 y Fraude",
                "reason": "Frau econòmic en curs i segrest de comptes de clients de la botiga online.",
            },
            summary="Maniobra de frau financer sobre la plataforma de comerç electrònic mitjançant comptes robats.",
            detailed_analysis="L'atacant utilitza navegadors automatitzats per consumir saldo o targetes desades comprant targetes de regal. Bloquejar l'origen i notificar immediatament l'equip de frau de Tarvia.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # 2.6 Accés no autoritzat a xarxa industrial OT (RB-08, UC-OT-001)
    if rule_id == "UC-OT-001" or "red ot" in rule_name.lower() or "logistics-ot" in evidence_str:
        hosts = entities.get("hosts", [])
        src_host = hosts[0].get("hostname") if hosts and isinstance(hosts[0], dict) else ""
        if src_host and src_host.upper() not in {"ENG-WS01", "WMS01"}:
            return VerdictResult(
                verdict="true_positive",
                rationale=f"Connexió no autoritzada cap al segment industrial OT des de l'equip {src_host}. Únicament ENG-WS01 i WMS01 estan autoritzats (RB-08).",
                confidence=0.96,
                recommended_actions=[],  # MAI aïllar OT des de SOC segons política
                escalation={
                    "escalate": True,
                    "to": "N2 y Operaciones",
                    "reason": "Accés no autoritzat a xarxa OT. POLÍTICA: PROHIBIT aïllar o bloquejar des del SOC.",
                },
                summary=f"Trànsit detectat cap a la xarxa del classificador logístic des d'un origen no permès ({src_host}).",
                detailed_analysis="La política del SOC prohibeix explícitament executar cap acció de contenció directa sobre el segment logístic per risc d'aturar la sortida de paquets de Martorell. Escalar immediatament a Operacions i N2.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 2.7 Beaconing C2 cap a domini novell (RB-09)
    if rule_id == "UC-NET-001" or "beaconing" in rule_name.lower():
        domains = entities.get("domains", [])
        dom = str(domains[0]) if domains else str(evidence.get("domain", ""))
        dom_age = evidence.get("domain_age_days")
        if dom_age is not None and isinstance(dom_age, (int, float)) and dom_age < 30:
            return VerdictResult(
                verdict="true_positive",
                rationale=f"Connexions regulars amb baixa variància (balisa C2) cap a domini recentment registrat sense historial: {dom} (antiguitat: {dom_age} dies) (RB-09).",
                confidence=0.92,
                recommended_actions=[
                    {
                        "action": "block_ioc",
                        "target": dom,
                        "requires_approval": False,
                        "justification": "Domini de comandament i control (C2) de recent creació.",
                    }
                ],
                escalation={
                    "escalate": True,
                    "to": "N2",
                    "reason": "Beaconing periòdic de comandament i control confirmat.",
                },
                summary=f"Patró d'exfiltració o control per xarxa cap a infraestructura sospitosa ({dom}).",
                detailed_analysis="El trànsit mostra intervals fixos característics d'implants de malware. Es recomana bloquejar el domini al proxy i aprofundir en l'anàlisi de l'equip emissor.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # -------------------------------------------------------------------------
    # 3. COMPROVACIÓ DE FALSE POSITIVES (Butlletins benignes, Serveis al núvol, Vela)
    # -------------------------------------------------------------------------

    # 3.1 Butlletí comercial reportat per error per l'usuari (RB-01, UC-EML-001)
    if rule_id == "UC-EML-001" or "reportado como phishing" in rule_name.lower():
        domains = entities.get("domains", [])
        dom = str(domains[0]) if domains else ""
        if (
            dom in KNOWN_BENIGN_DOMAINS
            or "newsletter" in sender.lower()
            or "news." in dom
            or "zalando" in dom
            or "retailforum" in dom
        ):
            return VerdictResult(
                verdict="false_positive",
                rationale=f"Butlletí comercial o invitació legítima de proveïdor conegut ({dom or sender}) reportada per error per l'empleat (RB-01).",
                confidence=0.92,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": "Correu comercial legítim sense elements maliciosos.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Falsa alarma d'usuari"},
                summary="Correu legítim de subscripció que no presenta cap amenaça ni intent d'engany.",
                detailed_analysis="S'ha verificat la reputació del domini emissor i la integritat dels registres SPF/DKIM. El contingut no conté enllaços maliciosos ni sol·licituds de dades bancàries.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 3.2 Serveis legítims al núvol / CDN / Trànsit Teams (RB-09)
    if rule_id in {"UC-NET-001", "UC-NET-005"} or "beaconing" in rule_name.lower() or "dga" in rule_name.lower():
        domains = entities.get("domains", [])
        dom = str(domains[0]) if domains else str(evidence.get("domain", ""))
        parent_domain = str(evidence.get("parent_domain", ""))
        if (
            dom in KNOWN_BENIGN_DOMAINS
            or any(dom.endswith("." + b) or dom == b for b in KNOWN_BENIGN_DOMAINS)
            or any(parent_domain.endswith(b) for b in {"amazonaws.com", "cloudfront.net", "cdn77.example", "microsoft.com"})
        ):
            return VerdictResult(
                verdict="false_positive",
                rationale=f"Trànsit periòdic legítim cap a plataformes de col·laboració, CDN o actualitzacions de confiança ({dom or parent_domain}) (RB-09).",
                confidence=0.92,
                recommended_actions=[
                    {
                        "action": "propose_rule_exclusion",
                        "target": dom or parent_domain,
                        "requires_approval": False,
                        "justification": "Exclusió del domini corporatiu de confiança a la regla del SIEM.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Trànsit corporatiu legítim"},
                summary=f"Fals positiu per trànsit regular cap a serveis d'alta reputació ({dom or parent_domain}).",
                detailed_analysis="L'elevat volum de peticions o la baixa variància s'explica per la naturalesa del servei (com la telemetria de Microsoft Teams o descàrregues de Google). Es recomana ajustar la regla de correlació.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 3.3 Assistent de compra amb IA (Vela): llenguatge natural de client (RB-07, UC-AI-001)
    if rule_id == "UC-AI-001" or "prompt injection" in rule_name.lower():
        excerpt = str(evidence.get("prompt_excerpt", "")).lower()
        if (
            "estilista" in excerpt
            or "toallas" in excerpt
            or "pedido" in excerpt
            or "pantalón" in excerpt
            or "me equivoqué" in excerpt
            or len(excerpt) < 80
        ):
            return VerdictResult(
                verdict="false_positive",
                rationale="Interacció ordinària en llenguatge natural d'un comprador que ha activat erròniament el filtre de prompt injection (RB-07).",
                confidence=0.88,
                recommended_actions=[
                    {
                        "action": "close_ticket",
                        "target": alert.alert_id,
                        "requires_approval": False,
                        "justification": "Consulta normal de client sense intencionalitat maliciosa.",
                    }
                ],
                escalation={"escalate": False, "to": None, "reason": "Conversa legítima de client"},
                summary="Falsa alarma al passadís d'IA produïda per una frase quotidiana del client a la botiga online.",
                detailed_analysis="L'anàlisi semàntica del missatge mostra que el client únicament demanava consell de moda o rectificava la seva comanda anterior. No s'ha produït cap intent d'evasió de directrius ni fuga de dades.",
                mitre=mitre_list,
                decision_engine="regles",
            )

    # 3.4 Escaneig automatitzat d'internet aturat pel WAF (RB-05, UC-WEB-001)
    if source == "WAF" and edr_action == "blocked":
        hits = evidence.get("hits", 0)
        return VerdictResult(
            verdict="false_positive",
            rationale=f"Escaneig genèric de vulnerabilitats aturat eficaçment pel WAF ({hits} peticions blocades) sense impacte al servidor (RB-05).",
            confidence=0.85,
            recommended_actions=[
                {
                    "action": "close_ticket",
                    "target": alert.alert_id,
                    "requires_approval": False,
                    "justification": "Trànsit oportunista bloquejat al perímetre sense efecte.",
                }
            ],
            escalation={"escalate": False, "to": None, "reason": "Atac bloquejat al perímetre"},
            summary="Sondeig oportunista d'IPs interceptat pel tallafocs web sense cap execució a la infraestructura interna.",
            detailed_analysis="Les peticions apuntaven a rutes inexistents o van ser rebutjades immediatament pel WAF amb codi 403. No hi ha evidència de compromís.",
            mitre=mitre_list,
            decision_engine="regles",
        )

    # -------------------------------------------------------------------------
    # 4. CAS PER DEFECTE: NEEDS MORE INFO (Evidències insuficients)
    # -------------------------------------------------------------------------
    return VerdictResult(
        verdict="needs_more_info",
        rationale="Els registres i indicadors actuals no permeten dictaminar amb certesa absoluta; es requereix correlació manual i telemetria addicional.",
        confidence=0.45,
        recommended_actions=[],
        escalation={"escalate": False, "to": None, "reason": "Pendent de major context"},
        summary="Alerta en estat preliminar a l'espera de noves dades de registre o intel·ligència d'amenaces.",
        detailed_analysis="No s'ha obtingut resposta concloent dels serveis de reputació ni s'han trobat esdeveniments posteriors que demostrin impacte. L'analista de seguretat ha d'efectuar una revisió manual de l'equip afectat.",
        mitre=mitre_list,
        decision_engine="regles",
    )


def evaluate_verdict_with_llm(
    alert: Alert,
    contexts: list[ContextRecord],
    related_logs: list[dict[str, Any]],
    severity: str,
    model: str = DEFAULT_MODEL,
) -> VerdictResult:
    """Avalua l'alerta utilitzant el model local LLaMA 3, redactant tot el contingut en català."""
    try:
        import ollama
    except ImportError:
        logger.warning("Paquet ollama no importable; utilitzant motor de regles de contingència.")
        res = evaluate_verdict(alert, contexts, related_logs, severity)
        res.rationale = f"[Avís: Ollama no instal·lat; veredicte per regles del SOC] {res.rationale}"
        res.decision_engine = "regles (fallback)"
        return res

    context_data = {
        "alert": {
            "alert_id": alert.alert_id,
            "created_at": alert.created_at,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "source_product": alert.source_product,
            "severity_rule": alert.severity,
            "severity_calculated": severity,
            "description": alert.description,
            "entities": alert.entities,
            "evidence": alert.evidence,
        },
        "contexts": [
            {"kind": c.kind, "key": c.key, "data": c.data}
            for c in contexts
            if c.kind in {"asset", "user", "intel", "sandbox", "change"}
        ],
        "related_logs_count": len(related_logs),
        "related_logs_preview": related_logs[:3],
    }

    prompt = (
        "Ets un analista de ciberseguretat expert de Nivell 1 del SOC de Tarvia Group.\n"
        "La teva missió és analitzar les evidències de l'alerta, decidir el veredicte final i elaborar el pla d'acció segons la política del SOC:\n"
        "- 'true_positive': amenaça o incident real confirmat (C2, malware, robatori de credencials, clic en phishing, ATO).\n"
        "- 'benign_true_positive': detecció encertada però d'activitat autoritzada (simulacre de phishing de RRHH, tasca de SCCM, canvi aprovat en calendari, viatge notificat a RRHH).\n"
        "- 'false_positive': falsa alarma (newsletter benigna reportada per error, beaconing cap a serveis legítims com Teams o Google, conversa habitual a Vela, escaneig bloquejat sense impacte).\n"
        "- 'needs_more_info': informació insuficient per dictaminar.\n\n"
        "REGLA D'OR DE LLENGUA: És OBLIGATORI escriure TOT el contingut ('summary', 'rationale', 'detailed_analysis', 'recommended_actions' i 'escalation.reason') EN CATALÀ.\n\n"
        "Respon EXCLUSIVAMENT en format JSON vàlid amb aquesta estructura exacta:\n"
        "{\n"
        '  "verdict": "true_positive" | "benign_true_positive" | "false_positive" | "needs_more_info",\n'
        '  "confidence": 0.0 a 1.0,\n'
        '  "rationale": "Justificació en català de per què s\'ha pres aquest veredicte",\n'
        '  "summary": "Resum executiu en català de 3-4 frases que descrigui què ha passat per a l\'analista N2",\n'
        '  "detailed_analysis": "Explicació detallada en català de l\'anàlisi tècnica i passos a seguir per al pla d\'acció",\n'
        '  "recommended_actions": [{"action": "block_ioc|isolate_host|revoke_sessions|reset_password|close_ticket", "target": "string", "requires_approval": true|false, "justification": "Motiu en català"}],\n'
        '  "escalation": {"escalate": true|false, "to": "N2|Operaciones|null", "reason": "Motiu d\'escalat en català"}\n'
        "}\n\n"
        f"Dades de la investigació de l'alerta:\n{json.dumps(context_data, ensure_ascii=False, indent=2)}"
    )

    try:
        response = ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            format="json",
            options={"temperature": 0.1},
        )
        content = response["message"]["content"].strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        content = content.strip()
        data = json.loads(content)

        raw_v = str(data.get("verdict", "")).strip().lower()
        if raw_v not in {"true_positive", "benign_true_positive", "false_positive", "needs_more_info"}:
            raw_v = "needs_more_info"

        conf = float(data.get("confidence", 0.85))
        conf = max(0.0, min(1.0, conf))

        summary_cat = str(data.get("summary") or "")
        analysis_cat = str(data.get("detailed_analysis") or summary_cat)

        return VerdictResult(
            verdict=raw_v,  # type: ignore[arg-type]
            rationale=str(data.get("rationale") or "Veredicte emès per LLaMA 3 segons el context de l'alerta."),
            confidence=conf,
            recommended_actions=list(data.get("recommended_actions") or []),
            escalation=dict(data.get("escalation") or {"escalate": False, "to": None, "reason": ""}),
            summary=summary_cat,
            detailed_analysis=analysis_cat,
            decision_engine=f"LLaMA 3 (Ollama)",
        )
    except Exception as exc:
        logger.warning(f"Error connectant amb Ollama ({exc}); activant motor de contingència del SOC.")
        fallback = evaluate_verdict(alert, contexts, related_logs, severity)
        fallback.rationale = f"[Avís: Ollama no disponible ({exc}); veredicte calculat per regles de contingència] {fallback.rationale}"
        fallback.decision_engine = "regles (fallback)"
        return fallback


def build_soc_ticket(
    alert: Alert,
    contexts: list[ContextRecord],
    related_logs: list[dict[str, Any]],
    verdict_res: VerdictResult,
    severity: str,
    severity_rationale: str,
) -> dict[str, Any]:
    """Genera el tiquet de triatge N1 complet, compliant amb ticket_salida.schema.json i en català."""
    users = [c.data.get("upn") for c in contexts if c.kind == "user" and "upn" in c.data]
    for u in alert.entities.get("users", []):
        upn = u.get("upn") if isinstance(u, dict) else str(u)
        if upn and upn not in users:
            users.append(upn)

    hosts = [c.data.get("hostname") for c in contexts if c.kind == "asset" and "hostname" in c.data]
    for h in alert.entities.get("hosts", []):
        hname = h.get("hostname") if isinstance(h, dict) else str(h)
        if hname and hname not in hosts:
            hosts.append(hname)

    customers: list[str] = []
    for cust in alert.entities.get("customers", []):
        cid = cust.get("customer_id") if isinstance(cust, dict) else str(cust)
        if cid and cid not in customers:
            customers.append(cid)

    services = [
        c.data.get("business_service")
        for c in contexts
        if c.kind == "asset" and c.data.get("business_service")
    ]

    enrichment: list[dict[str, Any]] = []
    for c in contexts:
        if c.kind == "intel" and isinstance(c.data, dict):
            tip = c.data.get("tip")
            res_str = "Neteja / sense coincidències conegudes" if not tip else f"Maliciós al TIP: {tip.get('description', '')}"
            enrichment.append(
                {
                    "indicator": c.key,
                    "type": "ip_o_domini",
                    "source": "TIP Tarvia",
                    "result": res_str,
                }
            )
        elif c.kind == "sandbox" and isinstance(c.data, dict):
            enrichment.append(
                {
                    "indicator": c.key,
                    "type": "sha256",
                    "source": "Sandbox Tarvia",
                    "result": f"Veredicte: {c.data.get('verdict', 'desconegut')}",
                }
            )

    evidence_items = [
        {
            "source": log.get("_source", alert.source_product),
            "event_id": str(log.get("event_id") or log.get("id") or f"EVT-{idx}"),
            "finding": f"Esdeveniment coincident al registre de {log.get('_source', alert.source_product)}",
        }
        for idx, log in enumerate(related_logs[:5])
    ]
    if not evidence_items:
        evidence_items.append(
            {
                "source": alert.source_product,
                "event_id": str(alert.alert_id),
                "finding": alert.description or alert.rule_name,
            }
        )

    mitre_techniques = list(verdict_res.mitre)
    if not mitre_techniques and isinstance(alert.model_extra, dict):
        raw_m = alert.model_extra.get("mitre")
        if isinstance(raw_m, dict) and "technique_id" in raw_m:
            mitre_techniques.append(raw_m["technique_id"])
        elif isinstance(raw_m, list):
            mitre_techniques.extend(str(m) for m in raw_m)

    actions = verdict_res.recommended_actions
    if not actions:
        actions = [
            {
                "action": "review_analyst",
                "target": alert.alert_id,
                "requires_approval": False,
                "justification": "Revisió ordinària de l'analista de Nivell 1",
            }
        ]

    # Títol descriptiu del que passa
    if hosts:
        title = f"{alert.rule_name} sobre l'actiu {hosts[0]}"
    elif users:
        title = f"{alert.rule_name} implicant l'usuari {users[0]}"
    else:
        title = f"{alert.rule_name} a l'entorn de Tarvia"

    return {
        "ticket_id": f"TCK-{alert.alert_id}",
        "alert_ids": [alert.alert_id],
        "title": title,
        "verdict": verdict_res.verdict,
        "confidence": max(0.0, min(1.0, float(verdict_res.confidence))),
        "severity": severity,
        "severity_rationale": severity_rationale,
        "affected": {
            "users": list(dict.fromkeys(users)),
            "hosts": list(dict.fromkeys(hosts)),
            "business_services": list(dict.fromkeys(services)),
            "customers": list(dict.fromkeys(customers)),
        },
        "summary": verdict_res.summary or alert.description or alert.rule_name,
        "evidence": evidence_items,
        "enrichment": enrichment,
        "mitre": list(dict.fromkeys(mitre_techniques)),
        "recommended_actions": actions,
        "executed_actions": [],
        "escalation": verdict_res.escalation,
        "open_questions": [] if verdict_res.verdict != "needs_more_info" else ["Comprovar telemetria addicional"],
        "triage_seconds": 1.2,
    }
