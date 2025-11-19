#!/bin/bash
# GeoIP Firewall installation script for RHEL/Rocky Linux/AlmaLinux

set -e
set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "이 스크립트는 root 권한이 필요합니다."
        log_info "다시 실행: sudo bash install.sh"
        exit 1
    fi
}

check_rhel_system() {
    if [ ! -f /etc/redhat-release ]; then
        log_error "이 스크립트는 RHEL 계열 시스템에서만 작동합니다."
        log_error "현재 시스템이 RHEL/Rocky/CentOS/AlmaLinux인지 확인하세요."
        exit 1
    fi

    log_info "시스템 확인: $(cat /etc/redhat-release)"
}

check_ipset_installed() {
    if ! command -v ipset &> /dev/null; then
        log_error "ipset이 설치되지 않았습니다."
        log_info "설치 중: dnf install ipset"
        dnf install -y ipset
    else
        log_info "ipset 확인: $(ipset --version | head -n 1)"
    fi
}

cleanup_firewall() {
    log_info "이전 설치 완전 제거 중..."

    log_info "방화벽 정책을 ACCEPT로 변경 중..."
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    ip6tables -P INPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true

    log_info "모든 iptables 규칙 삭제 중..."
    iptables -F INPUT 2>/dev/null || true
    iptables -F FORWARD 2>/dev/null || true
    iptables -F OUTPUT 2>/dev/null || true
    ip6tables -F INPUT 2>/dev/null || true
    ip6tables -F FORWARD 2>/dev/null || true
    ip6tables -F OUTPUT 2>/dev/null || true

    log_info "실행 중인 geoip 프로세스 종료 중..."
    pkill -9 -f geoip-update 2>/dev/null || true
    pkill -9 -f "python.*geoip" 2>/dev/null || true

    log_info "systemd 서비스 중지 및 비활성화 중..."
    systemctl stop geoip-firewall.service 2>/dev/null || true
    systemctl stop geoip-firewall-update.service 2>/dev/null || true
    systemctl stop geoip-firewall-update.timer 2>/dev/null || true
    systemctl disable geoip-firewall.service 2>/dev/null || true
    systemctl disable geoip-firewall-update.service 2>/dev/null || true
    systemctl disable geoip-firewall-update.timer 2>/dev/null || true

    log_info "systemd 서비스 파일 삭제 중..."
    rm -f /etc/systemd/system/geoip-firewall.service
    rm -f /etc/systemd/system/geoip-firewall-update.service
    rm -f /etc/systemd/system/geoip-firewall-update.timer
    systemctl daemon-reload 2>/dev/null || true

    log_info "모든 ipset 삭제 중..."
    ipset list -n 2>/dev/null | grep "^country-" | while read set; do
        ipset destroy "$set" 2>/dev/null || true
    done

    log_info "설치 디렉토리 삭제 중..."
    rm -rf /usr/local/geoip-firewall

    log_info "로그 파일 삭제 중..."
    rm -rf /var/log/iptables
    rm -f /var/log/geoip-firewall-update.log

    log_info "로그 설정 파일 삭제 중..."
    rm -f /etc/rsyslog.d/10-geoip-firewall.conf
    rm -f /etc/logrotate.d/geoip-firewall
    systemctl restart rsyslog 2>/dev/null || true

    log_info "이전 설치 완전 제거 완료"
}

install_dependencies() {
    log_info "필수 패키지 설치 중..."

    dnf install -y curl wget ca-certificates ipset iptables

    log_info "패키지 설치 완료"
}

install_uv() {
    log_info "uv 패키지 관리자 설치 중..."

    if command -v uv &> /dev/null; then
        log_info "uv가 이미 설치되어 있습니다: $(uv --version)"
        return
    fi

    curl -LsSf https://astral.sh/uv/install.sh | sh

    export PATH="$HOME/.cargo/bin:$PATH"

    if command -v uv &> /dev/null; then
        log_info "uv 설치 완료: $(uv --version)"
    else
        log_error "uv 설치 실패"
        exit 1
    fi
}

install_project_files() {
    log_info "프로젝트 파일 설치 중..."

    INSTALL_DIR="/usr/local/geoip-firewall"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ ! -f "$SCRIPT_DIR/pyproject.toml" ] || [ ! -d "$SCRIPT_DIR/src" ]; then
        log_error "필수 파일이 없습니다. 스크립트를 프로젝트 디렉토리에서 실행하세요."
        exit 1
    fi

    log_info "설치 경로: $INSTALL_DIR"

    mkdir -p "$INSTALL_DIR"
    cp -r "$SCRIPT_DIR/src" "$SCRIPT_DIR/pyproject.toml" "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"

    log_info "파일 복사 완료"
}

setup_python_environment() {
    log_info "Python 가상환경 설정 중..."

    cd "$INSTALL_DIR"

    uv sync --python 3.13

    log_info "Python 환경 설정 완료"
}

install_systemd_service() {
    log_info "Systemd 서비스 설치 중..."

    cat > /etc/systemd/system/geoip-firewall.service << 'EOF'
[Unit]
Description=Linux GeoIP Firewall (Boot-time Rule Restoration)
After=network-online.target
Wants=network-online.target
Before=sshd.service

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=/usr/local/geoip-firewall
RemainAfterExit=yes

ExecStart=/root/.cargo/bin/uv run geoip-update

StandardOutput=journal
StandardError=journal
SyslogIdentifier=geoip-firewall-boot

PrivateTmp=true
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=true

TimeoutSec=600

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/geoip-firewall-update.service << 'EOF'
[Unit]
Description=Linux GeoIP Firewall Update Service (Native ipset)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
Group=root
WorkingDirectory=/usr/local/geoip-firewall

ExecStart=/root/.cargo/bin/uv run geoip-update

StandardOutput=journal
StandardError=journal
SyslogIdentifier=geoip-firewall-update

PrivateTmp=true
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=true

TimeoutSec=600

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/geoip-firewall-update.timer << 'EOF'
[Unit]
Description=Linux GeoIP Firewall Monthly Update Timer
Requires=geoip-firewall-update.service

[Timer]
OnCalendar=*-*-15 03:00:00
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable geoip-firewall.service
    systemctl enable geoip-firewall-update.timer
    systemctl start geoip-firewall-update.timer

    log_info "Systemd 서비스 설치 완료"
    log_info "  - geoip-firewall.service: 부팅 시 자동 실행 (재부팅 후 룰 복원)"
    log_info "  - geoip-firewall-update.timer: 매월 15일 자동 업데이트"
}

setup_logging() {
    log_info "로깅 설정 중..."

    mkdir -p /var/log/iptables
    cp "$SCRIPT_DIR/config/rsyslog-geoip.conf" /etc/rsyslog.d/10-geoip-firewall.conf
    cp "$SCRIPT_DIR/config/logrotate-geoip" /etc/logrotate.d/geoip-firewall
    systemctl restart rsyslog

    log_info "로깅 설정 완료: /var/log/iptables/{access.log,drop.log}"
}

cleanup_on_failure() {
    log_warn "실패 감지 - 자동 정리 시작..."

    pkill -9 -f geoip-update 2>/dev/null || true
    pkill -9 -f "python.*geoip" 2>/dev/null || true

    rm -f "$INSTALL_DIR/last-check.txt" 2>/dev/null || true
    rm -f "$INSTALL_DIR/dbip-version.hash" 2>/dev/null || true
    rm -f "$INSTALL_DIR/dbip-country-lite.mmdb" 2>/dev/null || true

    iptables -L INPUT -n --line-numbers | grep geoip-firewall | awk '{print $1}' | tac | while read line; do
        iptables -D INPUT "$line" 2>/dev/null || true
    done
    ip6tables -L INPUT -n --line-numbers | grep geoip-firewall | awk '{print $1}' | tac | while read line; do
        ip6tables -D INPUT "$line" 2>/dev/null || true
    done

    ipset list -n 2>/dev/null | grep "^country-" | while read set; do
        ipset destroy "$set" 2>/dev/null || true
    done

    log_info "정리 완료 - 모든 프로세스, 캐시, ipset, iptables 규칙 삭제됨"
}

run_initial_update() {
    log_info "초기 GeoIP 데이터베이스 업데이트 실행 중..."
    log_warn "이 작업은 5-10분 정도 소요될 수 있습니다..."

    cd "$INSTALL_DIR"

    if uv run geoip-update; then
        log_info "✅ 초기 업데이트 성공!"
    else
        log_error "초기 업데이트 실패"
        cleanup_on_failure
        log_error "다시 시도하려면: cd /root/proxmox-geoip-firewall && ./install.sh"
        exit 1
    fi
}

print_success_message() {
    echo
    echo "======================================================================"
    log_info "✅ Linux GeoIP Firewall 설치 완료!"
    echo "======================================================================"
    echo
    echo "📋 설치 정보:"
    echo "   - 설치 경로: /usr/local/geoip-firewall"
    echo "   - 업데이트 로그: /var/log/geoip-firewall-update.log"
    echo "   - ACCEPT 로그: /var/log/iptables/access.log"
    echo "   - DROP 로그: /var/log/iptables/drop.log"
    echo "   - 방화벽 방식: Native ipset + iptables"
    echo
    echo "🔄 재부팅 자동 복원:"
    echo "   ✅ geoip-firewall.service 활성화됨"
    echo "   - 재부팅 시 자동으로 방화벽 룰 복원"
    echo "   - 상태 확인: systemctl status geoip-firewall.service"
    echo "   - 부팅 로그: journalctl -u geoip-firewall -b"
    echo
    echo "🔄 자동 업데이트:"
    echo "   - 매월 15일 오전 3시 자동 실행"
    echo "   - 상태 확인: systemctl status geoip-firewall-update.timer"
    echo
    echo "🔥 허용된 국가 설정:"
    echo "   - 기본값: KR (한국)"
    echo "   - 변경: /usr/local/geoip-firewall/src/proxmox_geoip_firewall/main.py"
    echo "   - CONFIG['ALLOWED_COUNTRIES'] = ['KR', 'US', 'JP'] 형식"
    echo
    echo "📊 ipset 확인:"
    echo "   - ipset list | grep country"
    echo "   - ipset list country-KR | head -20"
    echo
    echo "🛡️ iptables 규칙 확인:"
    echo "   - iptables -L INPUT -n --line-numbers | grep geoip"
    echo
    echo "📝 유용한 명령어:"
    echo "   - 수동 업데이트: systemctl start geoip-firewall-update.service"
    echo "   - 로그 확인: journalctl -u geoip-firewall-update -f"
    echo "   - Timer 상태: systemctl list-timers geoip-firewall-update.timer"
    echo "   - 서비스 비활성화: systemctl disable geoip-firewall.service"
    echo "   - 재부팅 테스트: reboot (재부팅 후 iptables 룰 자동 복원됨)"
    echo
    echo "======================================================================"
}

main() {
    echo "======================================================================"
    echo "  Linux GeoIP Firewall 자동 설치 스크립트 (RHEL/Rocky Linux)"
    echo "  Native ipset + iptables + Python 3.13 + uv"
    echo "======================================================================"
    echo

    check_root
    check_rhel_system
    check_ipset_installed
    cleanup_firewall
    install_dependencies
    install_uv
    install_project_files
    setup_python_environment
    install_systemd_service
    setup_logging
    run_initial_update
    print_success_message
}

main "$@"
