# Linux GeoIP Firewall

DB-IP 무료 데이터베이스를 이용한 국가별 IP 차단 시스템입니다.
Debian/RHEL 계열에서 native ipset과 iptables를 사용하여 251개 국가의 IP를 관리할 수 있습니다.

**지원 운영체제:**
- Debian 12+ / Ubuntu 22.04+ / Proxmox VE 9+
- RHEL 9+ / Rocky Linux 9+ / AlmaLinux 9+

## 주요 기능

- 251개 국가 IP 범위 자동 관리
- 매월 자동 업데이트 (DB-IP 기준)
- Python 3.13 + uv 사용
- 변경사항 있을 때만 업데이트 (해시 비교)
- 국가별 접속/차단 로그 자동 기록
- IPv4/IPv6 약 123만개 IP 범위를 ipset restore로 빠르게 처리
- DROP 규칙을 먼저 제거하여 SSH 끊김 방지
- 로그 로테이션 (7일 보관)

## 요구사항

### Debian/Ubuntu/Proxmox
- apt 패키지 관리자

### RHEL/Rocky/AlmaLinux
- dnf 패키지 관리자

### 공통
- 인터넷 연결 (DB-IP 다운로드)
- root 권한
- ipset, iptables, rsyslog는 자동 설치됨

## 설치

### 1. 파일 배포

서버로 파일을 복사합니다:

```bash
rsync -av ./proxmox-geoip-firewall/ \
  root@your-server:/root/geoip-firewall/ \
  --exclude='.venv' --exclude='__pycache__' --delete
```

### 2. 설치 스크립트 실행

**Debian/Ubuntu/Proxmox:**
```bash
ssh root@your-server
cd /root/geoip-firewall
chmod +x install_debian.sh
./install_debian.sh
```

**RHEL/Rocky/AlmaLinux:**
```bash
ssh root@your-server
cd /root/geoip-firewall
chmod +x install_rhel.sh
./install_rhel.sh
```

설치 완료 후 자동으로 첫 업데이트가 실행됩니다 (1-2분 소요).

## 작동 방식

```
DB-IP MMDB
    ↓
maxminddb 파싱
    ↓
ipset 생성 (country-KR, country-US, ...)
    ↓
iptables 규칙 설정
    ↓
rsyslog → /var/log/iptables/{access.log, drop.log}
    ↓
logrotate (매일 00:00, 7일 보관)
```

### 설치 후 디렉토리 구조

```
/usr/local/geoip-firewall/          # 메인 설치 디렉토리
├── dbip-country-lite.mmdb          # DB-IP 데이터베이스
├── .venv/                          # Python 가상환경
├── last-check.txt                  # 마지막 체크 시간
└── dbip-version.hash               # 데이터베이스 해시

/var/log/iptables/                  # 로그
├── access.log                      # 허용된 연결
├── drop.log                        # 차단된 연결
└── *.log.*.gz                      # 로테이트된 로그

/etc/rsyslog.d/10-geoip-firewall.conf
/etc/logrotate.d/geoip-firewall
/etc/systemd/system/geoip-firewall-update.*
```

## 방화벽 규칙

### 기본 설정 (한국만 허용)

설치 시 자동으로 다음 규칙이 적용됩니다:

```bash
# Localhost 트래픽 허용
iptables -I INPUT 1 -i lo -j ACCEPT

# 한국 IP 허용 (로깅 + ACCEPT)
iptables -I INPUT 1 -m set --match-set country-KR src -m conntrack --ctstate NEW -j LOG --log-prefix "GEOIP-ACCEPT-KR: "
iptables -I INPUT 2 -m set --match-set country-KR src -j ACCEPT

# 기타 국가 차단 (로깅 + DROP)
iptables -A INPUT -m set --match-set country-US src -m conntrack --ctstate NEW -j LOG --log-prefix "GEOIP-DROP-US: "
iptables -A INPUT -m set --match-set country-US src -j DROP
# ... (250개 국가 동일)

# 매칭 안된 모든 연결 차단
iptables -A INPUT -m conntrack --ctstate NEW -j LOG --log-prefix "GEOIP-DROP-UNKNOWN: "
iptables -A INPUT -j DROP
```

### 허용 국가 변경

`/usr/local/geoip-firewall/src/proxmox_geoip_firewall/main.py` 파일을 수정:

```python
# 허용할 국가 설정
allowed_countries = ["KR", "US", "JP"]  # 한국, 미국, 일본
```

변경 후 업데이트:

```bash
cd /usr/local/geoip-firewall
rm -rf .venv
uv sync
uv run geoip-update
```

## 로그 확인

### 실시간 모니터링

```bash
# 허용된 연결
tail -f /var/log/iptables/access.log

# 차단된 연결
tail -f /var/log/iptables/drop.log

# 전체
tail -f /var/log/iptables/*.log
```

### 로그 예시

**access.log** (NEW 연결만 기록):
```
2025-11-06T09:24:57+09:00 server kernel: GEOIP-ACCEPT-KR: IN=eth0 SRC=1.2.3.4 DST=10.0.0.1 PROTO=TCP SPT=50986 DPT=22 SYN
```

**drop.log** (차단된 시도):
```
2025-11-06T09:24:50+09:00 server kernel: GEOIP-DROP-US: IN=eth0 SRC=5.6.7.8 DST=10.0.0.1 PROTO=TCP SPT=51076 DPT=443 SYN
2025-11-06T09:23:26+09:00 server kernel: GEOIP-DROP-NL: IN=eth0 SRC=9.10.11.12 DST=10.0.0.1 PROTO=TCP SPT=50375 DPT=80 SYN
```

### 통계

```bash
# 국가별 차단 횟수
grep "GEOIP-DROP" /var/log/iptables/drop.log | awk '{print $6}' | sort | uniq -c | sort -nr

# 출력 예시:
# 1348 GEOIP-DROP-SG:
#  379 GEOIP-DROP-CN:
#  340 GEOIP-DROP-DE:
```

## 자동 업데이트

### 일정

- 매월 15일 오전 3시 자동 업데이트
- DB-IP는 매월 1일 업데이트되므로 충분한 여유

### 관리

```bash
# Timer 상태
systemctl status geoip-firewall-update.timer

# 다음 실행 시간
systemctl list-timers geoip-firewall-update.timer

# 수동 실행
systemctl start geoip-firewall-update.service

# 로그 확인
journalctl -u geoip-firewall-update.service -f
```

## 개발

### 코드 수정 후 배포

```bash
# 코드 수정
vim src/proxmox_geoip_firewall/main.py

# 서버로 배포
rsync -av ./ root@your-server:/root/geoip-firewall/ \
  --exclude='.venv' --exclude='__pycache__' --delete

# 서버에서 적용
ssh root@your-server
cd /usr/local/geoip-firewall
rm -rf .venv
uv sync
uv run geoip-update
```

### 재설치

```bash
# Debian/Ubuntu/Proxmox
cd /root/geoip-firewall
./install_debian.sh

# RHEL/Rocky/AlmaLinux
cd /root/geoip-firewall
./install_rhel.sh
```

### 전체 정리

```bash
# 프로세스 종료
pkill -9 -f geoip-update

# DROP 규칙 먼저 제거 (SSH 유지)
iptables -L INPUT -n --line-numbers | grep 'geoip-firewall-drop' | \
  awk '{print $1}' | tac | while read line; do iptables -D INPUT $line; done

ip6tables -L INPUT -n --line-numbers | grep 'geoip-firewall-drop' | \
  awk '{print $1}' | tac | while read line; do ip6tables -D INPUT $line; done

# 나머지 규칙 제거
iptables -L INPUT -n --line-numbers | grep 'geoip-firewall' | \
  awk '{print $1}' | tac | while read line; do iptables -D INPUT $line; done

ip6tables -L INPUT -n --line-numbers | grep 'geoip-firewall' | \
  awk '{print $1}' | tac | while read line; do ip6tables -D INPUT $line; done

# ipset 제거
ipset list -n | grep '^country-' | while read set; do ipset destroy $set; done

# 캐시 제거
cd /usr/local/geoip-firewall
rm -f last-check.txt dbip-version.hash dbip-country-lite.mmdb*
rm -rf .venv
```

## 프로젝트 구조

```
proxmox-geoip-firewall/
├── src/
│   └── proxmox_geoip_firewall/
│       ├── __init__.py
│       └── main.py              # 메인 스크립트
├── config/
│   ├── rsyslog-geoip.conf       # rsyslog 설정
│   └── logrotate-geoip          # logrotate 설정
├── pyproject.toml
├── install_debian.sh
├── install_rhel.sh
└── README.md
```

## 기술 상세

### ipset 최적화

- `ipset restore` 사용으로 bulk operation 처리 (개별 add 대비 280,000배 빠름)
- 동적 maxelem (각 국가 IP 수 * 1.1)
- IPv4/IPv6 분리 (`hash:net`, `hash:net family inet6`)

### 로깅 최적화

- `conntrack NEW`로 새 연결만 로깅
- SSH 세션 데이터 교환은 로깅 안함 → 로그 크기 90% 감소
- 국가별 프리픽스로 구분 (`GEOIP-ACCEPT-KR:`, `GEOIP-DROP-US:`)
- rsyslog로 access.log, drop.log 분리

### 안전성

- DROP 규칙을 먼저 제거하여 SSH 끊김 방지
- localhost 트래픽 최우선 허용 (`-i lo -j ACCEPT`)
- 재부팅 시 기존 MMDB로 즉시 복원 (네트워크 대기 없음)
- 실패 시 캐시 및 규칙 자동 제거

## 지원 국가 코드 (예시)

| 코드 | 국가 | IPv4 범위 | IPv6 범위 |
|------|------|-----------|-----------|
| KR | 대한민국 | 3,451개 | 1,432개 |
| US | 미국 | 172,366개 | 109,432개 |
| JP | 일본 | 21,614개 | 4,787개 |
| CN | 중국 | 8,132개 | 6,098개 |
| DE | 독일 | 28,745개 | 98,301개 |

총 251개 국가 지원

## 성능

테스트 환경: Proxmox VE 9.0, Python 3.13, uv

- 파싱: 약 5초 (123만개 IP 범위)
- ipset 생성: 약 40-60초 (251개 국가)
- iptables 규칙: 약 5초 (500+ 규칙)
- 전체: 약 1-2분
- 메모리: ~200MB
- 디스크: ~50MB

## 문제 해결

### 업데이트 안됨

```bash
# 수동 실행
systemctl start geoip-firewall-update.service

# 로그 확인
journalctl -u geoip-firewall-update.service -n 100
```

### ipset 없음

```bash
# 확인
ipset list -n | grep country-

# 재생성
cd /usr/local/geoip-firewall
uv run geoip-update
```

### 로그 안쌓임

```bash
# rsyslog 재시작
systemctl restart rsyslog

# 규칙 확인
iptables -L INPUT -n -v | grep geoip
```

### SSH 끊김

```bash
# 다른 터미널에서 DROP 규칙 제거
iptables -L INPUT -n --line-numbers | grep 'geoip-firewall-drop' | \
  awk '{print $1}' | tac | while read line; do iptables -D INPUT $line; done
```

## 보안 권장사항

1. SSH 포트 변경 (기본 22 대신 다른 포트)
2. SSH 키 인증 사용 (패스워드 인증 비활성화)
3. fail2ban 설치
4. 정기적인 로그 모니터링

## 라이선스

MIT License

이 프로젝트는 [DB-IP Lite](https://db-ip.com/db/lite.php) 데이터베이스를 사용합니다 (CC BY 4.0).

---

만든 사람: jeosong
최종 업데이트: 2025-11-19
Python 3.13+, Debian 12+/Ubuntu 22.04+/Proxmox VE 9+/RHEL 9+/Rocky 9+/AlmaLinux 9+
