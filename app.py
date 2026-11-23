import json
import sqlite3
from datetime import datetime
from pathlib import Path
import pandas as pd
import streamlit as st

from report_agent import (
    executar_pipeline_ferramentas,
    generate_security_report,
    importar_xml_nmap,
    save_report,
    zerar_ambiente_secops,
)

st.set_page_config(
    page_title="Obselik | Global SOAR & SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Modelo estrutural em branco apenas para o usuário baixar como guia de preenchimento
JSON_TEMPLATE = {
    "scan_metadata": {
        "scan_id": "MY-AUDIT-001",
        "subnet": "<YOUR_SUBNET_CIDR>",
    },
    "hosts": [
        {
            "hostname": "<YOUR_HOSTNAME>",
            "ip": "<YOUR_SERVER_IP>",
            "os": "Ubuntu 22.04 LTS",
            "role": "Database Server",
            "services": [
                {"port": 22, "service": "ssh"},
                {"port": 5432, "service": "postgres"},
            ],
        }
    ],
}


def parse_custom_ports(texto_portas: str) -> list[dict]:
    """Converte entradas livres como '5432:postgres, 8080:http' em serviços válidos."""
    servicos = []
    if not texto_portas.strip():
        return servicos
    for bloco in texto_portas.split(","):
        bloco = bloco.strip()
        if not bloco:
            continue
        if ":" in bloco:
            p_str, srv = bloco.split(":", 1)
            if p_str.strip().isdigit():
                servicos.append({"port": int(p_str.strip()), "service": srv.strip() or "custom"})
        elif bloco.isdigit():
            servicos.append({"port": int(bloco), "service": f"tcp-{bloco}"})
    return servicos


# =====================================================================
# INICIALIZAÇÃO 100% ZERADA (ZERO-STATE REAL SEM DADOS SIMULADOS)
# =====================================================================
if "obselik_initialized" not in st.session_state:
    zerar_ambiente_secops()
    st.session_state["obselik_initialized"] = True
    st.session_state["hosts_ativos"] = []
    st.session_state["idioma"] = "EN"
    st.session_state["telemetria"] = executar_pipeline_ferramentas({"hosts": []}, registrar_sqlite=False)
    st.session_state["relatorio_md"] = generate_security_report(
        {"hosts": []}, st.session_state["telemetria"], idioma="EN"
    )


def atualizar_estado_obselik(registrar_sqlite: bool = True, usar_llm: bool = False, api_key: str = ""):
    inv = {
        "scan_metadata": {"scan_id": f"OBSELIK-{datetime.now().strftime('%H%M%S')}"},
        "hosts": st.session_state["hosts_ativos"],
    }
    telemetria_nova = executar_pipeline_ferramentas(inv, registrar_sqlite=registrar_sqlite)
    relatorio_novo = generate_security_report(
        inv,
        telemetria_nova,
        custom_api_key=api_key,
        usar_llm=usar_llm,
        idioma=st.session_state.get("idioma", "EN"),
    )
    if st.session_state["hosts_ativos"]:
        save_report(relatorio_novo, "audit_report.md")
    st.session_state["telemetria"] = telemetria_nova
    st.session_state["relatorio_md"] = relatorio_novo


# =====================================================================
# BARRA LATERAL: ENTRADA INTUITIVA DE DADOS DO USUÁRIO
# =====================================================================
with st.sidebar:
    st.title("🛡️ Obselik")
    idioma_sel = st.radio(
        "🌐 Language / Idioma:",
        ["🇺🇸 English (US Enterprise)", "🇧🇷 Português (Brasil)"],
        index=0 if st.session_state.get("idioma", "EN") == "EN" else 1,
    )
    novo_id = "EN" if "English" in idioma_sel else "PT"
    if novo_id != st.session_state.get("idioma"):
        st.session_state["idioma"] = novo_id
        atualizar_estado_obselik(registrar_sqlite=False)
        st.rerun()

    is_en = st.session_state["idioma"] == "EN"
    st.caption(
        "Autonomous SOAR Platform • 14 Active Tools • SHA-256 Verified"
        if is_en
        else "Plataforma SOAR Autônoma • 14 Ferramentas • Assinatura SHA-256"
    )
    st.divider()

    # 1. CADASTRO MANUAL DE SERVIDOR
    st.subheader("➕ 1. Add Your Server" if is_en else "➕ 1. Cadastrar Seu Servidor")
    with st.form("form_add_server", clear_on_submit=True):
        h_name = st.text_input(
            "Hostname:",
            placeholder="e.g., prod-web-01" if is_en else "ex: prod-web-01",
        )
        h_ip = st.text_input(
            "IP Address:" if is_en else "Endereço IP:",
            placeholder="e.g., 10.0.1.15" if is_en else "ex: 10.0.1.15",
        )
        h_os = st.selectbox(
            "Operating System:" if is_en else "Sistema Operacional:",
            [
                "Ubuntu 22.04 LTS",
                "Debian 12",
                "Windows Server 2022",
                "Windows Server 2019",
                "RedHat Enterprise Linux 9",
                "Other Linux",
            ],
        )
        h_role = st.selectbox(
            "Server Role:" if is_en else "Função do Servidor:",
            [
                "Application Server",
                "Database Server",
                "File Server & AD",
                "Edge Gateway / Reverse Proxy",
            ],
        )
        h_ports = st.multiselect(
            "Common Exposed Ports:" if is_en else "Portas Expostas Comuns:",
            [
                "21 - ftp",
                "22 - ssh",
                "23 - telnet",
                "80 - http",
                "139 - netbios",
                "443 - nginx",
                "445 - smb",
                "3306 - mysql",
                "3389 - rdp",
                "5432 - postgres",
                "6379 - redis",
                "27017 - mongodb",
            ],
        )
        custom_ports_raw = st.text_input(
            "Custom Ports (optional):" if is_en else "Outras Portas (opcional):",
            placeholder="8080:http, 9200:elastic",
            help="Format: port:service separated by commas." if is_en else "Formato: porta:serviço separados por vírgula.",
        )

        btn_txt = "➕ Add Server & Run Analysis" if is_en else "➕ Adicionar e Analisar Servidor"
        if st.form_submit_button(btn_txt, type="primary", use_container_width=True):
            svcs = [
                {"port": int(p.split(" - ")[0]), "service": p.split(" - ")[1].strip()}
                for p in h_ports
            ]
            svcs.extend(parse_custom_ports(custom_ports_raw))

            if h_name.strip() and h_ip.strip() and svcs:
                st.session_state["hosts_ativos"].append({
                    "hostname": h_name.strip(),
                    "ip": h_ip.strip(),
                    "os": h_os,
                    "role": h_role,
                    "services": svcs,
                })
                atualizar_estado_obselik(registrar_sqlite=True)
                st.rerun()
            else:
                st.warning(
                    "Enter a Hostname, IP, and select or type at least 1 port."
                    if is_en
                    else "Informe o Hostname, o IP e selecione ou digite ao menos 1 porta."
                )

    st.divider()

    # 2. UPLOAD DIRETO DE SCANS DO USUÁRIO + TEMPLATE GUIA
    st.subheader("📂 2. Upload Scan (JSON / Nmap XML)" if is_en else "📂 2. Enviar Scan (JSON / Nmap XML)")
    up_file = st.file_uploader(
        "Drop your .json or Nmap .xml (-oX):" if is_en else "Envie seu arquivo .json ou Nmap .xml (-oX):",
        type=["json", "xml"],
    )
    if up_file is not None:
        if st.button("🚀 Analyze Uploaded File" if is_en else "🚀 Analisar Arquivo Enviado", type="primary", use_container_width=True):
            try:
                raw = up_file.read().decode("utf-8", errors="ignore")
                dados = importar_xml_nmap(raw) if up_file.name.lower().endswith(".xml") else json.loads(raw)
                novos_hosts = dados.get("hosts", [])
                if novos_hosts:
                    st.session_state["hosts_ativos"].extend(novos_hosts)
                    atualizar_estado_obselik(registrar_sqlite=True)
                    st.rerun()
                else:
                    st.error(
                        "No hosts with open ports found in this file."
                        if is_en
                        else "Nenhum host com portas abertas foi encontrado nesse arquivo."
                    )
            except Exception as err:
                st.error(f"Error reading file: {err}" if is_en else f"Erro ao ler arquivo: {err}")

    with st.expander("❓ How to format my scan?" if is_en else "❓ Como formatar meu arquivo?"):
        st.caption("Nmap XML command:" if is_en else "Comando Nmap para gerar XML:")
        st.code("nmap -sV -oX scan.xml <TARGET_IP>", language="bash")
        st.download_button(
            "⬇️ Download Blank JSON Template" if is_en else "⬇️ Baixar Modelo JSON",
            data=json.dumps(JSON_TEMPLATE, indent=2),
            file_name="obselik_template.json",
            mime="application/json",
            use_container_width=True,
        )

    st.divider()

    # 3. GERENCIAR HOSTS, MOTOR DE IA & RESET
    st.subheader("⚙️ 3. Scope & AI Engine" if is_en else "⚙️ 3. Escopo & Motor de IA")

    if st.session_state["hosts_ativos"]:
        nomes_ativos = [f"{i + 1}. {h['hostname']} ({h['ip']})" for i, h in enumerate(st.session_state["hosts_ativos"])]
        host_remover = st.selectbox("Remove server:" if is_en else "Remover servidor:", nomes_ativos)
        if st.button("➖ Remove Selected Server" if is_en else "➖ Remover Servidor Selecionado", use_container_width=True):
            idx_rem = nomes_ativos.index(host_remover)
            st.session_state["hosts_ativos"].pop(idx_rem)
            atualizar_estado_obselik(registrar_sqlite=False)
            st.rerun()

    provedor_ia = st.selectbox(
        "Report Engine:" if is_en else "Motor de Relatório:",
        [
            "Deterministic Real-Time Engine (Instant)",
            "Google Gemini API (.env / SDK)",
            "OpenAI GPT-4o (Modular Ready)",
            "Anthropic Claude 3.5 Sonnet (Modular Ready)",
            "Groq Llama 3.3 70B (Modular Ready)",
            "Ollama Local (Air-Gapped localhost:11434)",
        ],
    )
    api_key_custom = st.text_input("Optional API Key Override:" if is_en else "API Key Opcional:", type="password")

    if st.button("🧠 Generate Report via LLM API" if is_en else "🧠 Gerar Relatório via LLM API", use_container_width=True):
        atualizar_estado_obselik(registrar_sqlite=False, usar_llm=True, api_key=api_key_custom)
        st.rerun()

    if st.button("🗑️ Clear All & Reset to Zero" if is_en else "🗑️ Limpar Tudo e Zerar", use_container_width=True):
        zerar_ambiente_secops()
        st.session_state["hosts_ativos"] = []
        atualizar_estado_obselik(registrar_sqlite=False)
        st.rerun()


# =====================================================================
# CABEÇALHO, SELO FORENSE SHA-256 E KPIS EM TEMPO REAL
# =====================================================================
is_en = st.session_state["idioma"] == "EN"
telemetria = st.session_state["telemetria"]
relatorio_md = st.session_state["relatorio_md"]
scores_list = telemetria.get("scores_hosts", [])
cves_list = telemetria.get("cves_identificadas", [])
alertas_list = telemetria.get("alertas_soc", [])
info_sig = telemetria.get("assinatura_forense", {})

media_score = round(sum(s.get("score_numerico", 0) for s in scores_list) / len(scores_list), 1) if scores_list else 0.0
criticas_count = sum(1 for c in cves_list if c.get("severidade") == "CRÍTICA")
kev_count = sum(1 for c in cves_list if str(c.get("cisa_kev", "")).startswith("YES"))

st.title(
    "🛡️ Obselik — Global SOC & SOAR Command Center"
    if is_en
    else "🛡️ Obselik — Central de Comando SOC & SOAR"
)

if info_sig and scores_list:
    st.success(
        f"🔐 **Forensic Chain of Custody Verified (SHA-256):** `{info_sig.get('sha256_hash')}` | "
        f"**Signed UTC:** `{info_sig.get('timestamp_utc')}` | **Standard:** `OASIS SARIF v2.1.0 & SOC 2 Type II Ready`"
        if is_en
        else f"🔐 **Assinatura Digital Forense Verificada (SHA-256):** `{info_sig.get('sha256_hash')}` | "
        f"**Carimbo UTC:** `{info_sig.get('timestamp_utc')}` | **Integridade:** `100% Autêntico`"
    )

col1, col2, col3, col4, col5, col6 = st.columns(6)
col1.metric("Monitored Hosts" if is_en else "Hosts Auditados", len(scores_list), f"+{len(scores_list)} active" if scores_list else "0")
col2.metric("Total Findings" if is_en else "Vulnerabilidades", len(cves_list), f"{criticas_count} Critical", delta_color="inverse" if criticas_count else "off")
col3.metric("US CISA KEV Hits" if is_en else "Catálogo CISA KEV", kev_count, "Active Exploits" if kev_count else "0 Hits", delta_color="inverse" if kev_count else "off")
col4.metric("SIEM Alerts" if is_en else "Alertas SIEM", len(alertas_list), "soc_alerts.json", delta_color="inverse" if alertas_list else "off")
col5.metric("Avg Risk Score" if is_en else "Score Médio", f"{media_score}/100", "Live" if scores_list else "0.0", delta_color="inverse" if media_score >= 50 else "normal")
col6.metric("SOAR Tools Active" if is_en else "Tools SOAR Ativas", "14 / 14", "SHA-256 + SARIF")

st.divider()

# =====================================================================
# GUIA RÁPIDO QUANDO ZERADO VS PAINEL ANALÍTICO EM 5 ABAS
# =====================================================================
if not scores_list:
    st.info(
        "📡 **Obselik is ready (0 servers in scope).** Choose one of the two options in the left sidebar to start analyzing your infrastructure:"
        if is_en
        else "📡 **O Obselik está pronto (0 servidores no escopo).** Escolha uma das duas opções na barra lateral esquerda para começar a analisar sua infraestrutura:"
    )
    g1, g2 = st.columns(2)
    with g1:
        st.markdown(
            "### ➕ Option 1: Manual Entry\n"
            "Fill in your server's **Hostname**, **IP**, **OS**, and select or type the **exposed ports**. "
            "All 14 SOAR tools, risk scores, compliance matrices, and hardening scripts update instantly."
            if is_en
            else "### ➕ Opção 1: Cadastro Manual\n"
            "Informe o **Hostname**, **IP**, **Sistema Operacional** e selecione ou digite as **portas expostas**. "
            "As 14 ferramentas SOAR, gráficos de risco, matrizes de compliance e scripts de hardening são gerados na hora."
        )
    with g2:
        st.markdown(
            "### 📂 Option 2: Upload JSON or Nmap XML\n"
            "Drop an Nmap scan generated with `nmap -sV -oX scan.xml <TARGET>` or a custom `.json` inventory. "
            "Need the JSON layout? Expand **'How to format my scan?'** on the left to download a blank template."
            if is_en
            else "### 📂 Opção 2: Upload de JSON ou Nmap XML\n"
            "Envie um scan do Nmap gerado com `nmap -sV -oX scan.xml <ALVO>` ou um inventário `.json`. "
            "Precisa do formato exato? Abra **'Como formatar meu arquivo?'** na barra lateral para baixar o modelo."
        )
else:
    aba1, aba2, aba3, aba4, aba5 = st.tabs(
        [
            "📊 1. Risk Score & Financial Impact (USD/BRL)",
            "🎯 2. Threat Intel (CISA KEV, EPSS & MITRE)",
            "⚖️ 3. US & Global Compliance (SOC 2, HIPAA, PCI)",
            "🛡️ 4. Auto-Hardening, Ansible & SARIF",
            "🔐 5. Signed Report, SHA-256 & SQLite",
        ]
        if is_en
        else [
            "📊 1. Risco & Impacto Financeiro (USD/BRL)",
            "🎯 2. Threat Intel (CISA KEV, EPSS & MITRE)",
            "⚖️ 3. Compliance Internacional (SOC 2, HIPAA, LGPD)",
            "🛡️ 4. Auto-Hardening, Ansible & SARIF",
            "🔐 5. Relatório Assinado, SHA-256 & SQLite",
        ]
    )

    with aba1:
        col_g1, col_g2 = st.columns([1, 2])
        df_scores = pd.DataFrame(scores_list)
        with col_g1:
            st.markdown("**Host Risk Score (0-100) — Tool 2**")
            st.bar_chart(df_scores.set_index("hostname")["score_numerico"], color="#ef4444")
        with col_g2:
            st.markdown("**Financial Downtime (USD / BRL) & Regulatory Exposure (Tool 10)**")
            st.dataframe(pd.DataFrame(telemetria.get("risco_negocio_lgpd", [])), use_container_width=True, hide_index=True)

        c_p1, c_p2 = st.columns(2)
        with c_p1:
            st.markdown("**Active Socket Telemetry (Tool 3)**")
            st.dataframe(pd.DataFrame(telemetria.get("portas_verificadas", [])), use_container_width=True, hide_index=True)
        with c_p2:
            st.markdown("**HTTP Security Headers & TLS Audit (Tool 4)**")
            df_http = pd.DataFrame(telemetria.get("auditoria_http_tls", []))
            if not df_http.empty:
                st.dataframe(df_http, use_container_width=True, hide_index=True)
            else:
                st.caption("No web ports (80/443) in current scope." if is_en else "Nenhuma porta Web (80/443) no escopo atual.")

    with aba2:
        st.subheader("CVE / CVSS v3, EPSS Probability, US CISA KEV (Tool 1) & MITRE ATT&CK (Tool 9)")
        linhas_comb = []
        mitre_list = telemetria.get("mapeamento_mitre", [])
        for idx, c in enumerate(cves_list):
            m = mitre_list[idx] if idx < len(mitre_list) else {}
            linhas_comb.append({
                "Host": c.get("host"),
                "IP": c.get("ip"),
                "Port": c.get("porta"),
                "Service": c.get("servico_analisado"),
                "Severity": c.get("severity_en" if is_en else "severidade"),
                "CVE / CWE": c.get("cve_id"),
                "CVSS v3": c.get("cvss_v3"),
                "EPSS Probability": c.get("epss_score"),
                "US CISA KEV": c.get("cisa_kev"),
                "MITRE Tactic": m.get("tatica_mitre"),
                "MITRE Technique": m.get("tecnica_id"),
            })
        st.dataframe(pd.DataFrame(linhas_comb), use_container_width=True, hide_index=True)

        st.divider()
        col_s1, col_s2 = st.columns([3, 1])
        with col_s1:
            st.subheader("🚨 SIEM Incident Feed (`soc_alerts.json` — Tool 8)")
        with col_s2:
            if Path("soc_alerts.json").exists():
                st.download_button(
                    "⬇️ Download soc_alerts.json",
                    data=Path("soc_alerts.json").read_text(encoding="utf-8"),
                    file_name="soc_alerts.json",
                    mime="application/json",
                    use_container_width=True,
                )
        if alertas_list:
            st.dataframe(pd.DataFrame(alertas_list), use_container_width=True, hide_index=True)
        else:
            st.caption("No High or Critical SIEM alerts triggered." if is_en else "Nenhum alerta SIEM alto ou crítico gerado.")

    with aba3:
        col_c1, col_c2 = st.columns([3, 1])
        with col_c1:
            st.subheader("US & Global Compliance: SOC 2 Type II, PCI-DSS v4.0, HIPAA, NIST CSF 2.0, CIS & ISO 27001 (Tool 7)")
        with col_c2:
            if Path("vulnerability_matrix.csv").exists():
                st.download_button(
                    "📊 Download CSV Matrix (Excel/BI)",
                    data=Path("vulnerability_matrix.csv").read_bytes(),
                    file_name="vulnerability_matrix.csv",
                    mime="text/csv",
                    use_container_width=True,
                )
        st.dataframe(pd.DataFrame(telemetria.get("mapeamento_compliance", [])), use_container_width=True, hide_index=True)

    with aba4:
        col_f1, col_f2 = st.columns([3, 1])
        with col_f1:
            st.subheader("Automated Firewall Rules (Tool 5) & OASIS SARIF Export (Tool 14)")
        with col_f2:
            if Path("secops_results.sarif.json").exists():
                st.download_button(
                    "🛡️ Download SARIF (GitHub/Sentinel)",
                    data=Path("secops_results.sarif.json").read_text(encoding="utf-8"),
                    file_name="secops_results.sarif.json",
                    mime="application/json",
                    use_container_width=True,
                )
        st.dataframe(pd.DataFrame(telemetria.get("regras_firewall", [])), use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Executable Hardening Scripts (Tool 6) & Ansible Playbook (Tool 11)")
        col_h1, col_h2 = st.columns(2)
        for idx, sc in enumerate(telemetria.get("scripts_exportados", [])):
            alvo_col = col_h1 if idx % 2 == 0 else col_h2
            with alvo_col:
                p = Path(sc["script_gerado"])
                lang = "powershell" if p.suffix == ".ps1" else "bash"
                st.markdown(f"**🖥️ Host: `{sc['hostname']}` (`{p.name}`)**")
                if p.exists():
                    txt = p.read_text(encoding="utf-8")
                    st.code(txt, language=lang)
                    st.download_button(
                        f"⬇️ Download {p.name}",
                        data=txt,
                        file_name=p.name,
                        key=f"dl_{p.name}_{idx}",
                        use_container_width=True,
                    )

        p_ans = Path("hardening_scripts/playbook_hardening.yml")
        if p_ans.exists():
            st.markdown("**⚙️ Consolidated Ansible Playbook (`playbook_hardening.yml`)**")
            txt_ans = p_ans.read_text(encoding="utf-8")
            st.code(txt_ans, language="yaml")
            st.download_button(
                "⬇️ Download playbook_hardening.yml",
                data=txt_ans,
                file_name="playbook_hardening.yml",
                key="dl_ansible",
                use_container_width=True,
            )

    with aba5:
        col_r1, col_r2, col_r3 = st.columns([2, 1, 1])
        with col_r1:
            st.subheader("Signed Executive Report & SHA-256 Chain of Custody (Tool 13)")
        with col_r2:
            st.download_button(
                "⬇️ Download audit_report.md",
                data=relatorio_md,
                file_name="audit_report.md",
                mime="text/markdown",
                use_container_width=True,
            )
        with col_r3:
            if Path("audit_report.sha256").exists():
                st.download_button(
                    "🔐 Download .sha256 Signature",
                    data=Path("audit_report.sha256").read_text(encoding="utf-8"),
                    file_name="audit_report.sha256",
                    mime="text/plain",
                    use_container_width=True,
                )

        with st.expander("📖 View Full Signed Report" if is_en else "📖 Visualizar Relatório Completo Assinado", expanded=True):
            st.markdown(relatorio_md)

        st.divider()
        st.subheader("📈 Historical Scope Growth in SQLite (`secops_audit.db`)")
        if Path("secops_audit.db").exists():
            conn = sqlite3.connect("secops_audit.db")
            df_runs = pd.read_sql_query("SELECT * FROM audit_runs ORDER BY id ASC", conn)
            df_host_hist = pd.read_sql_query("SELECT * FROM host_scores ORDER BY id DESC LIMIT 20", conn)
            conn.close()
            if len(df_runs) > 1:
                st.line_chart(df_runs.set_index("id")[["total_hosts", "total_vulns", "critical_alerts"]])
            c_db1, c_db2 = st.columns(2)
            with c_db1:
                st.dataframe(df_runs, use_container_width=True, hide_index=True)
            with c_db2:
                st.dataframe(df_host_hist, use_container_width=True, hide_index=True)