import re
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}

SEVERITY_COLOR = {
    Severity.INFO: "#b4b4b4",
    Severity.LOW: "#8ab4f8",
    Severity.MEDIUM: "#fdd663",
    Severity.HIGH: "#f28b82",
}


@dataclass
class Finding:
    port: int
    service: str
    severity: Severity
    title: str
    detail: str
    banner: str


HIGH_RISK_PORTS = {
    23: "Telnet — нешифрованный протокол удалённого доступа, передаёт логин/пароль открытым текстом",
    21: "FTP — потенциально открытый или анонимный доступ, передача данных без шифрования",
    2375: "Docker API без TLS — полный контроль над хостом при отсутствии аутентификации",
    6379: "Redis — часто разворачивается без пароля, прямой доступ к данным",
    27017: "MongoDB — известны случаи незащищённых инстансов с доступом без авторизации",
    9200: "Elasticsearch — открытый индекс может привести к утечке всех хранимых данных",
    11211: "Memcached — уязвим к UDP-амплификации и раскрытию данных в памяти",
    5900: "VNC — удалённый доступ к рабочему столу, частые случаи слабых паролей",
    1433: "MSSQL — целевой сервис для брутфорса и известных эксплойтов",
    3389: "RDP — частая цель для брутфорса и эксплойтов (BlueKeep и аналоги)",
}

MEDIUM_RISK_PORTS = {
    445: "SMB — история критичных уязвимостей (EternalBlue), требует контроля версий",
    139: "NetBIOS — устаревший протокол, риск раскрытия информации о сети",
    111: "RPCBind — может раскрывать список доступных RPC-сервисов",
    161: "SNMP — риск при community string по умолчанию (public/private)",
    3306: "MySQL — требует строгого контроля доступа и актуальных патчей",
    5432: "PostgreSQL — требует проверки конфигурации pg_hba.conf",
    8080: "HTTP-Proxy/альтернативный веб-порт — часто используется для админ-панелей",
    7001: "WebLogic — известная цель для CVE, связанных с десериализацией",
}

BANNER_SIGNATURES: list[tuple[re.Pattern, Severity, str, str]] = [
    (re.compile(r"vsftpd 2\.3\.4", re.I), Severity.HIGH, "vsFTPd 2.3.4 Backdoor", "Известная версия с backdoor (CVE-2011-2523), позволяет удалённое выполнение команд"),
    (re.compile(r"OpenSSH[_ ]([0-3]\.\d|4\.\d|5\.[0-3])", re.I), Severity.MEDIUM, "Устаревшая версия OpenSSH", "Версия может быть подвержена известным уязвимостям, рекомендуется обновление"),
    (re.compile(r"Apache/1\.|Apache/2\.[0-2]\.", re.I), Severity.MEDIUM, "Устаревшая версия Apache HTTP Server", "Версия не получает обновлений безопасности, высокий риск известных CVE"),
    (re.compile(r"Apache/2\.4\.[0-9]\b|Apache/2\.4\.[1-2][0-9]\b", re.I), Severity.LOW, "Apache 2.4.x требует проверки версии", "Рекомендуется убедиться, что установлены последние патчи безопасности"),
    (re.compile(r"nginx/1\.[0-9]\.|nginx/0\.", re.I), Severity.MEDIUM, "Устаревшая версия nginx", "Старые версии nginx могут содержать известные уязвимости"),
    (re.compile(r"Microsoft-IIS/[1-6]\.", re.I), Severity.HIGH, "Критически устаревший IIS", "Версии IIS до 7.0 не поддерживаются и содержат множество известных эксплойтов"),
    (re.compile(r"ProFTPD 1\.3\.[0-3][^0-9]", re.I), Severity.HIGH, "ProFTPD с известным RCE", "Версии 1.3.0–1.3.3 подвержены mod_copy RCE (CVE-2015-3306)"),
    (re.compile(r"MySQL.*5\.[0-5]\.", re.I), Severity.MEDIUM, "Устаревшая версия MySQL", "Версии 5.0–5.5 содержат множество известных уязвимостей аутентификации"),
    (re.compile(r"Redis", re.I), Severity.HIGH, "Redis без видимой аутентификации", "Сервис отвечает на запрос без TLS/auth-баннера, проверьте requirepass"),
    (re.compile(r"220.*ready", re.I), Severity.LOW, "FTP сервис активен", "Проверьте, разрешён ли анонимный доступ (anonymous login)"),
    (re.compile(r"SMTP.*Exim 4\.[0-8][0-9]", re.I), Severity.MEDIUM, "Устаревшая версия Exim", "Старые версии Exim подвержены критическим RCE (например, CVE-2019-10149)"),
]


class VulnerabilityAnalyzer:
    def __init__(self):
        self._signatures = BANNER_SIGNATURES

    def analyze(self, port: int, service: str, banner: str) -> list[Finding]:
        findings: list[Finding] = []
        banner = banner or ""

        for pattern, severity, title, detail in self._signatures:
            if pattern.search(banner):
                findings.append(Finding(port, service, severity, title, detail, banner))

        if port in HIGH_RISK_PORTS:
            findings.append(Finding(
                port, service, Severity.HIGH,
                f"Высокорисковый сервис: {service}",
                HIGH_RISK_PORTS[port], banner
            ))
        elif port in MEDIUM_RISK_PORTS:
            findings.append(Finding(
                port, service, Severity.MEDIUM,
                f"Сервис повышенного внимания: {service}",
                MEDIUM_RISK_PORTS[port], banner
            ))

        if not findings:
            findings.append(Finding(
                port, service, Severity.INFO,
                f"Открытый порт: {service}",
                "Явных признаков уязвимости по баннеру не обнаружено, рекомендуется ручная проверка",
                banner
            ))

        return findings

    @staticmethod
    def overall_severity(findings: list[Finding]) -> Severity:
        if not findings:
            return Severity.INFO
        return max(findings, key=lambda f: SEVERITY_WEIGHT[f.severity]).severity
