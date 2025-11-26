#!/usr/bin/env python3
"""GeoIP-based firewall using ipset and iptables"""

import gzip
import hashlib
import logging
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path

CONFIG = {
    "DOWNLOAD_DIR": "/usr/local/geoip-firewall",
    "MMDB_FILE": "/usr/local/geoip-firewall/dbip-country-lite.mmdb",
    "HASH_FILE": "/usr/local/geoip-firewall/dbip-version.hash",
    "LAST_CHECK_FILE": "/usr/local/geoip-firewall/last-check.txt",
    "LOG_FILE": "/var/log/geoip-firewall-update.log",
    "ALLOWED_COUNTRIES": ["KR"],
    # 사설 IP 대역 (Docker, Kubernetes, 내부 네트워크 등)
    "PRIVATE_NETWORKS_V4": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",  # Link-local
    ],
    "PRIVATE_NETWORKS_V6": [
        "fc00::/7",        # Unique local address
        "fe80::/10",       # Link-local
    ],
}

# 전역 변수: 모든 국가 코드 목록 (apply_native_ipset에서 설정됨)
ALL_COUNTRIES: list[str] = []

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(CONFIG["LOG_FILE"]),
    ],
)
logger = logging.getLogger(__name__)


def get_current_month_url() -> str:
    now = datetime.now()
    url = (
        f"https://download.db-ip.com/free/"
        f"dbip-country-lite-{now.year}-{now.month:02d}.mmdb.gz"
    )
    return url


def check_remote_file_changed(url: str) -> bool:
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=30) as response:
            last_modified = response.headers.get("Last-Modified", "")
            content_length = response.headers.get("Content-Length", "")

        check_info = f"{last_modified}|{content_length}"

        if Path(CONFIG["LAST_CHECK_FILE"]).exists():
            with open(CONFIG["LAST_CHECK_FILE"]) as f:
                saved_info = f.read().strip()
                if saved_info == check_info:
                    logger.info("원격 파일 변경 없음")
                    return False

        Path(CONFIG["LAST_CHECK_FILE"]).parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG["LAST_CHECK_FILE"], "w") as f:
            f.write(check_info)

        logger.info(f"원격 파일 변경 감지: Last-Modified={last_modified}")
        return True

    except urllib.error.HTTPError as e:
        if e.code == 404:
            logger.warning(f"새 월 파일 아직 없음: {url}")
            return False
        logger.error(f"HTTP 오류 발생: {e}")
        raise
    except Exception as e:
        logger.error(f"원격 파일 체크 실패: {e}")
        raise


def calculate_file_hash(filepath: str | Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_file_hash_changed(filepath: str | Path) -> bool:
    current_hash = calculate_file_hash(filepath)

    if Path(CONFIG["HASH_FILE"]).exists():
        with open(CONFIG["HASH_FILE"]) as f:
            saved_hash = f.read().strip()
            if saved_hash == current_hash:
                logger.info("파일 해시 동일")
                return False

    Path(CONFIG["HASH_FILE"]).parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG["HASH_FILE"], "w") as f:
        f.write(current_hash)

    logger.info(f"새 파일 감지! Hash: {current_hash[:16]}...")
    return True


def download_dbip_database(url: str) -> bool:
    logger.info(f"DB-IP 데이터베이스 다운로드: {url}")

    Path(CONFIG["DOWNLOAD_DIR"]).mkdir(parents=True, exist_ok=True)
    gz_file = CONFIG["MMDB_FILE"] + ".gz"

    try:
        urllib.request.urlretrieve(url, gz_file)
        logger.info(f"다운로드 완료: {gz_file}")

        with gzip.open(gz_file, "rb") as f_in:
            with open(CONFIG["MMDB_FILE"], "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        logger.info(f"압축 해제 완료: {CONFIG['MMDB_FILE']}")
        Path(gz_file).unlink(missing_ok=True)  # 파일 없어도 에러 없이 처리

        return True
    except Exception as e:
        logger.error(f"다운로드 실패: {e}")
        return False


def parse_mmdb_to_country_ipranges() -> dict[str, list[str]]:
    try:
        import maxminddb
    except ImportError:
        logger.error("maxminddb 라이브러리가 설치되지 않았습니다")
        logger.error("설치: uv sync")
        return {}

    logger.info("MMDB 파일 파싱 시작")

    country_ip_ranges: dict[str, list[str]] = {}

    try:
        with maxminddb.open_database(CONFIG["MMDB_FILE"]) as reader:
            total_networks = 0
            skipped_networks = 0

            for network, data in reader:
                total_networks += 1

                if not data:
                    skipped_networks += 1
                    continue

                if "country" not in data:
                    skipped_networks += 1
                    continue

                country_data = data["country"]
                if "iso_code" not in country_data:
                    skipped_networks += 1
                    continue

                country_code = country_data["iso_code"]
                network_cidr = str(network)

                if country_code not in country_ip_ranges:
                    country_ip_ranges[country_code] = []

                country_ip_ranges[country_code].append(network_cidr)

                if total_networks % 10000 == 0:
                    logger.info(
                        f"처리 중: {total_networks:,}개 네트워크 "
                        f"({len(country_ip_ranges)}개 국가)"
                    )

        logger.info("파싱 완료")
        logger.info(f"총 네트워크: {total_networks:,}, 국가: {len(country_ip_ranges)}개")

        top_countries = sorted(
            country_ip_ranges.items(), key=lambda x: len(x[1]), reverse=True
        )[:10]
        logger.info("IP 범위 Top 10:")
        for country_code, ip_list in top_countries:
            logger.info(f"  {country_code}: {len(ip_list):,}개")

    except Exception as e:
        logger.error(f"MMDB 파싱 중 오류 발생: {e}")
        return {}

    return country_ip_ranges


def cleanup_existing_ipsets() -> bool:
    """Remove existing geoip-firewall rules and ipsets (only geoip-firewall rules)"""
    logger.info("기존 ipset 및 iptables 규칙 정리 중...")

    try:
        # Remove DROP rules first to prevent SSH disconnection
        for iptables_cmd in ["/usr/sbin/iptables", "/usr/sbin/ip6tables"]:
            # Remove DROP rules first (geoip-firewall-drop)
            while True:
                result = subprocess.run(
                    [iptables_cmd, "-L", "INPUT", "-n", "--line-numbers"],
                    capture_output=True,
                    text=True,
                )
                found = False
                for line in result.stdout.split("\n"):
                    if "geoip-firewall-drop" in line:
                        line_num = line.split()[0]
                        if line_num.isdigit():
                            subprocess.run(
                                [iptables_cmd, "-D", "INPUT", line_num],
                                capture_output=True,
                            )
                            logger.info(f"DROP 규칙 제거 완료 ({iptables_cmd})")
                            found = True
                            break
                if not found:
                    break

            # Remove all other geoip-firewall rules (including localhost, private, stateful)
            while True:
                result = subprocess.run(
                    [iptables_cmd, "-L", "INPUT", "-n", "--line-numbers"],
                    capture_output=True,
                    text=True,
                )
                found = False
                for line in result.stdout.split("\n"):
                    # geoip-firewall 주석이 있는 규칙만 삭제
                    if "geoip-firewall" in line:
                        line_num = line.split()[0]
                        if line_num.isdigit():
                            subprocess.run(
                                [iptables_cmd, "-D", "INPUT", line_num],
                                capture_output=True,
                            )
                            found = True
                            break
                if not found:
                    break

        # Remove geoip-firewall ipsets
        result = subprocess.run(
            ["/usr/sbin/ipset", "list", "-n"],
            capture_output=True,
            text=True,
        )
        geoip_sets = [s for s in result.stdout.split("\n") if s.startswith("country-") or s.startswith("geoip-")]

        for set_name in geoip_sets:
            subprocess.run(
                ["/usr/sbin/ipset", "destroy", set_name],
                capture_output=True,
            )

        if geoip_sets:
            logger.info(f"기존 ipset {len(geoip_sets)}개 삭제 완료")

    except Exception as e:
        logger.warning(f"정리 중 오류 (무시 가능): {e}")

    return True


def apply_native_ipset(country_ip_ranges: dict[str, list[str]]) -> bool:
    """Create ipset for each country (cleanup is done separately by cleanup_existing_ipsets)"""
    logger.info(f"Native ipset 생성 중: {len(country_ip_ranges)}개 국가")

    total_countries = len(country_ip_ranges)
    processed = 0

    global ALL_COUNTRIES
    ALL_COUNTRIES = list(country_ip_ranges.keys())

    for country_code, ip_ranges in country_ip_ranges.items():
        ipv4_ranges = []
        ipv6_ranges = []

        for ip_range in ip_ranges:
            if ":" in ip_range:
                ipv6_ranges.append(ip_range)
            else:
                ipv4_ranges.append(ip_range)

        try:
            processed += 1

            logger.info(
                f"[{processed}/{total_countries}] {country_code} 처리 중: "
                f"IPv4 {len(ipv4_ranges):,}개, IPv6 {len(ipv6_ranges):,}개"
            )

            if ipv4_ranges:
                set_name_v4 = f"country-{country_code}"
                max_size = int(len(ipv4_ranges) * 1.1)
                subprocess.run(
                    ["/usr/sbin/ipset", "create", set_name_v4, "hash:net", "maxelem", str(max_size), "-exist"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["/usr/sbin/ipset", "flush", set_name_v4],
                    check=True,
                    capture_output=True,
                )

                # Bulk add via stdin for performance
                process = subprocess.Popen(
                    ["/usr/sbin/ipset", "restore"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                commands = "\n".join([f"add {set_name_v4} {ip}" for ip in ipv4_ranges]) + "\n"
                stdout, stderr = process.communicate(input=commands.encode())
                if process.returncode not in (None, 0):
                    logger.error(f"ipset restore 실패 ({set_name_v4}): {stderr.decode()}")
                    raise subprocess.CalledProcessError(process.returncode, "ipset restore")

            if ipv6_ranges:
                set_name_v6 = f"country-{country_code}-v6"
                max_size = int(len(ipv6_ranges) * 1.1)
                subprocess.run(
                    ["/usr/sbin/ipset", "create", set_name_v6, "hash:net", "family", "inet6", "maxelem", str(max_size), "-exist"],
                    check=True,
                    capture_output=True,
                )
                subprocess.run(
                    ["/usr/sbin/ipset", "flush", set_name_v6],
                    check=True,
                    capture_output=True,
                )

                # Bulk add via stdin for performance
                process = subprocess.Popen(
                    ["/usr/sbin/ipset", "restore"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                commands = "\n".join([f"add {set_name_v6} {ip}" for ip in ipv6_ranges]) + "\n"
                stdout, stderr = process.communicate(input=commands.encode())
                if process.returncode not in (None, 0):
                    logger.error(f"ipset restore 실패 ({set_name_v6}): {stderr.decode()}")
                    raise subprocess.CalledProcessError(process.returncode, "ipset restore")

        except subprocess.CalledProcessError as e:
            logger.error(f"ipset 오류 ({country_code}): {e}")
            return False

    logger.info(f"ipset 생성 완료: {len(country_ip_ranges)}개 국가")
    return True


def setup_firewall_rules(allowed_countries: list[str]) -> bool:
    logger.info("iptables/ip6tables 규칙 설정 중...")

    try:
        logger.info("Stateful 방화벽 규칙 추가 중 (ESTABLISHED, RELATED)...")

        subprocess.run(
            [
                "/usr/sbin/iptables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-stateful",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "/usr/sbin/ip6tables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-stateful",
            ],
            check=True,
            capture_output=True,
        )

        logger.info("Stateful 방화벽 규칙 추가 완료")
    except subprocess.CalledProcessError as e:
        logger.error(f"Stateful 규칙 추가 실패: {e}")
        return False

    try:
        logger.info("Localhost 트래픽 허용 규칙 추가 중...")

        subprocess.run(
            [
                "/usr/sbin/iptables",
                "-A",
                "INPUT",
                "-i",
                "lo",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-localhost",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "/usr/sbin/ip6tables",
                "-A",
                "INPUT",
                "-i",
                "lo",
                "-j",
                "ACCEPT",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-localhost",
            ],
            check=True,
            capture_output=True,
        )

        logger.info("Localhost 트래픽 허용 완료")
    except subprocess.CalledProcessError as e:
        logger.error(f"Localhost 규칙 추가 실패: {e}")
        return False

    # 사설 IP 대역 허용 (Docker, Kubernetes, 내부 네트워크 등)
    try:
        logger.info("사설 IP 대역 허용 규칙 추가 중...")

        for network in CONFIG["PRIVATE_NETWORKS_V4"]:
            subprocess.run(
                [
                    "/usr/sbin/iptables",
                    "-A",
                    "INPUT",
                    "-s",
                    network,
                    "-j",
                    "ACCEPT",
                    "-m",
                    "comment",
                    "--comment",
                    "geoip-firewall-private",
                ],
                check=True,
                capture_output=True,
            )

        for network in CONFIG["PRIVATE_NETWORKS_V6"]:
            subprocess.run(
                [
                    "/usr/sbin/ip6tables",
                    "-A",
                    "INPUT",
                    "-s",
                    network,
                    "-j",
                    "ACCEPT",
                    "-m",
                    "comment",
                    "--comment",
                    "geoip-firewall-private",
                ],
                check=True,
                capture_output=True,
            )

        logger.info(f"사설 IP 대역 허용 완료: IPv4 {len(CONFIG['PRIVATE_NETWORKS_V4'])}개, IPv6 {len(CONFIG['PRIVATE_NETWORKS_V6'])}개")
    except subprocess.CalledProcessError as e:
        logger.error(f"사설 IP 규칙 추가 실패: {e}")
        return False

    global ALL_COUNTRIES
    blocked_countries = [c for c in ALL_COUNTRIES if c not in allowed_countries]

    for country in allowed_countries:
        try:
            ipv4_exists = subprocess.run(
                ["/usr/sbin/ipset", "list", f"country-{country}", "-name"],
                capture_output=True,
            ).returncode == 0

            if ipv4_exists:
                subprocess.run(
                    [
                        "/usr/sbin/iptables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}",
                        "src",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "NEW",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall-log",
                        "-j",
                        "LOG",
                        "--log-prefix",
                        f"GEOIP-ACCEPT-{country}: ",
                        "--log-level",
                        "6",
                    ],
                    check=True,
                    capture_output=True,
                )

                subprocess.run(
                    [
                        "/usr/sbin/iptables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}",
                        "src",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall",
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Check if IPv6 ipset exists
            ipv6_exists = subprocess.run(
                ["/usr/sbin/ipset", "list", f"country-{country}-v6", "-name"],
                capture_output=True,
            ).returncode == 0

            if ipv6_exists:
                subprocess.run(
                    [
                        "/usr/sbin/ip6tables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}-v6",
                        "src",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "NEW",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall-log",
                        "-j",
                        "LOG",
                        "--log-prefix",
                        f"GEOIP-ACCEPT-{country}: ",
                        "--log-level",
                        "6",
                    ],
                    check=True,
                    capture_output=True,
                )

                subprocess.run(
                    [
                        "/usr/sbin/ip6tables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}-v6",
                        "src",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall",
                        "-j",
                        "ACCEPT",
                    ],
                    check=True,
                    capture_output=True,
                )

            logger.info(f"허용 규칙 추가: {country} (IPv4 + IPv6)")
        except subprocess.CalledProcessError as e:
            logger.error(f"iptables 규칙 추가 실패 ({country}): {e}")
            return False

    logger.info(f"차단 규칙 추가 중: {len(blocked_countries)}개 국가")
    for country in blocked_countries:
        try:
            ipv4_exists = subprocess.run(
                ["/usr/sbin/ipset", "list", f"country-{country}", "-name"],
                capture_output=True,
            ).returncode == 0

            if ipv4_exists:
                subprocess.run(
                    [
                        "/usr/sbin/iptables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}",
                        "src",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "NEW",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall-log",
                        "-j",
                        "LOG",
                        "--log-prefix",
                        f"GEOIP-DROP-{country}: ",
                        "--log-level",
                        "6",
                    ],
                    check=True,
                    capture_output=True,
                )

                subprocess.run(
                    [
                        "/usr/sbin/iptables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}",
                        "src",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall-drop",
                        "-j",
                        "DROP",
                    ],
                    check=True,
                    capture_output=True,
                )

            # Check if IPv6 ipset exists
            ipv6_exists = subprocess.run(
                ["/usr/sbin/ipset", "list", f"country-{country}-v6", "-name"],
                capture_output=True,
            ).returncode == 0

            if ipv6_exists:
                subprocess.run(
                    [
                        "/usr/sbin/ip6tables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}-v6",
                        "src",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "NEW",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall-log",
                        "-j",
                        "LOG",
                        "--log-prefix",
                        f"GEOIP-DROP-{country}: ",
                        "--log-level",
                        "6",
                    ],
                    check=True,
                    capture_output=True,
                )

                subprocess.run(
                    [
                        "/usr/sbin/ip6tables",
                        "-A",
                        "INPUT",
                        "-m",
                        "set",
                        "--match-set",
                        f"country-{country}-v6",
                        "src",
                        "-m",
                        "comment",
                        "--comment",
                        "geoip-firewall-drop",
                        "-j",
                        "DROP",
                    ],
                    check=True,
                    capture_output=True,
                )

        except subprocess.CalledProcessError as e:
            logger.error(f"차단 규칙 추가 실패 ({country}): {e}")
            return False

    logger.info(f"차단 규칙 추가 완료: {len(blocked_countries)}개 국가")

    try:
        subprocess.run(
            [
                "/usr/sbin/iptables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-log",
                "-j",
                "LOG",
                "--log-prefix",
                "GEOIP-DROP-UNKNOWN: ",
                "--log-level",
                "6",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "/usr/sbin/iptables",
                "-A",
                "INPUT",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-drop",
                "-j",
                "DROP",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "/usr/sbin/ip6tables",
                "-A",
                "INPUT",
                "-m",
                "conntrack",
                "--ctstate",
                "NEW",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-log",
                "-j",
                "LOG",
                "--log-prefix",
                "GEOIP-DROP-UNKNOWN: ",
                "--log-level",
                "6",
            ],
            check=True,
            capture_output=True,
        )

        subprocess.run(
            [
                "/usr/sbin/ip6tables",
                "-A",
                "INPUT",
                "-m",
                "comment",
                "--comment",
                "geoip-firewall-drop",
                "-j",
                "DROP",
            ],
            check=True,
            capture_output=True,
        )

        logger.info("DROP 규칙 추가 완료: 허용 국가 외 모든 연결 차단")
    except subprocess.CalledProcessError as e:
        logger.error(f"DROP 규칙 추가 실패: {e}")
        return False

    logger.info(f"iptables 규칙 설정 완료: {len(allowed_countries)}개 국가 허용, 나머지 차단")
    return True


def smart_update() -> bool:
    logger.info("=" * 70)
    logger.info("Linux GeoIP Firewall Update (Native ipset)")
    logger.info("=" * 70)

    url = get_current_month_url()
    logger.info(f"URL: {url}")

    mmdb_exists = Path(CONFIG["MMDB_FILE"]).exists()

    try:
        result = subprocess.run(
            ["/usr/sbin/ipset", "list", "-n"],
            capture_output=True,
            text=True,
        )
        ipset_count = len([s for s in result.stdout.split("\n") if s.startswith("country-")])
    except Exception:
        ipset_count = 0

    if ipset_count == 0:
        logger.info("ipset 없음 감지")

        if mmdb_exists:
            logger.info("재부팅 감지 - 기존 MMDB로 방화벽 즉시 복원")
            logger.info(f"기존 파일 사용: {CONFIG['MMDB_FILE']}")
            # 재부팅 시에도 해시 파일 갱신 (다음 업데이트 체크를 위해)
            if not Path(CONFIG["HASH_FILE"]).exists():
                check_file_hash_changed(CONFIG["MMDB_FILE"])
        else:
            logger.info("첫 설치 - MMDB 파일 다운로드 필요")
            Path(CONFIG["LAST_CHECK_FILE"]).unlink(missing_ok=True)
            Path(CONFIG["HASH_FILE"]).unlink(missing_ok=True)

            logger.info("파일 다운로드 중...")
            if not download_dbip_database(url):
                logger.error("다운로드 실패")
                return False
    elif mmdb_exists:
        if not check_remote_file_changed(url):
            logger.info("업데이트 불필요")
            return True

        logger.info("원격 파일 변경 감지 - 다운로드 중...")
        if not download_dbip_database(url):
            logger.error("다운로드 실패")
            return False

        logger.info("해시 비교...")
        if not check_file_hash_changed(CONFIG["MMDB_FILE"]):
            logger.info("동일 파일 - 업데이트 건너뜀")
            return True
    else:
        logger.warning("비정상 상태 감지: ipset은 있지만 MMDB 파일 없음")
        logger.info("MMDB 재다운로드 시도...")
        if not download_dbip_database(url):
            logger.error("다운로드 실패")
            return False

    logger.info("MMDB 파싱...")
    country_ip_ranges = parse_mmdb_to_country_ipranges()
    if not country_ip_ranges:
        logger.error("파싱 실패")
        return False

    logger.info("기존 규칙 정리...")
    cleanup_existing_ipsets()

    logger.info("Native ipset 적용...")
    if not apply_native_ipset(country_ip_ranges):
        logger.error("ipset 적용 실패")
        return False

    logger.info("iptables 규칙 설정...")
    if not setup_firewall_rules(CONFIG["ALLOWED_COUNTRIES"]):
        logger.error("iptables 규칙 설정 실패")
        return False

    logger.info("=" * 70)
    logger.info("업데이트 완료!")
    logger.info(f"허용된 국가: {', '.join(CONFIG['ALLOWED_COUNTRIES'])}")
    logger.info("=" * 70)
    return True


def main() -> None:
    try:
        success = smart_update()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.info("중단됨")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"오류: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
