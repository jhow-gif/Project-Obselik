from report_agent import (
    assinar_relatorio_sha256,
    buscar_cve_servico,
    calcular_risco_negocio_lgpd,
    calcular_score_host,
    exportar_sarif_github,
    mapear_compliance_cis,
    mapear_mitre_attack,
)


def test_cve_and_cisa_kev_mapping():
    res = buscar_cve_servico("redis")
    assert res["cvss_v3"] == 9.8
    assert "YES" in res["cisa_kev"]
    assert res["severity_en"] == "CRITICAL"


def test_host_risk_score_calculation():
    res = calcular_score_host("srv-test", "192.168.50.25", [6379, 3306])
    assert res["score_numerico"] == 75
    assert res["classification_en"] == "CRITICAL"


def test_us_compliance_frameworks_soc2_hipaa_pci():
    comp = mapear_compliance_cis("redis", "Debian 11")
    assert "CC6.1" in comp["soc2_type2"]
    assert "Req 8.3.1" in comp["pci_dss_v4"]
    assert "164.312" in comp["hipaa_security"]


def test_mitre_attack_and_usd_business_impact():
    mitre = mapear_mitre_attack("smb")
    assert "T1210" in mitre["tecnica_id"]
    impact = calcular_risco_negocio_lgpd("win-srv", "File Server", 85)
    assert "USD" in impact["estimated_downtime_usd"]


def test_forensic_sha256_signature_and_sarif():
    sig = assinar_relatorio_sha256("# Test Security Report")
    assert len(sig["sha256_hash"]) == 64
    assert sig["status_integridade"] == "VERIFIED_TAMPER_PROOF"

    sarif = exportar_sarif_github(
        [buscar_cve_servico("redis") | {"host": "db01", "ip": "10.0.0.1", "porta": 6379}]
    )
    assert sarif["total_findings"] == 1