#!/usr/bin/env bash
# Enhanced security process monitor - Looks for security risks in running processes
# Added detailed security scanning on April 28, 2025
# Improved risk scoring and added exceptions for known legitimate processes

# Set thresholds - include lower thresholds to catch more processes
CPU_T=3.0  # Lowered from 5.0 to catch more processes
MEM_T=3.0  # Lowered from 5.0 to catch more processes

# ANSI color codes for highlighting risks
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Known legitimate processes that may trigger false positives
# Use simpler array approach for compatibility with older bash versions
KNOWN_LEGITIMATE="launchd automountd autofsd endpointsecurit WindowServer mdworker_shared syslogd"

print_header() {
  echo -e "${YELLOW}===== SECURITY PROCESS SCANNER - $(date) =====${NC}"
  echo -e "Looking for potentially suspicious processes on system..."
  echo ""
  printf "%-5s %-8s %5s %5s %-15s %-8s %-9s %-8s %-15s %-20s %s\n" \
    "PID" "USER" "%CPU" "%MEM" "COMMAND" "RISK" "SIGNATURE" "AGE" "NETWORK" "SECURITY FLAGS" "PARENT"
  printf "%-5s %-8s %5s %5s %-15s %-8s %-9s %-8s %-15s %-20s %s\n" \
    "----" "--------" "----" "----" "---------------" "--------" "---------" "--------" "---------------" "--------------------" "------"
}

# Print a risk assessment for the given process
scan_process() {
  local pid=$1
  local user=$2
  local cpu=$3 
  local mem=$4
  local command=$5
  local path=$6
  local ppid=$7
  
  # Initialize risk score
  risk_score=0
  security_flags=""
  
  # Get command name (executable name)
  comm=$(echo "$command" | awk '{print $1}' | awk -F/ '{print $NF}')
  
  # Reduce risk score for known legitimate processes
  if [[ " $KNOWN_LEGITIMATE " =~ " $comm " && "$user" == "root" ]]; then
    risk_adjustment=-25
  else
    risk_adjustment=0
  fi
  
  # Check code signature with more details
  if [[ -f "$path" ]]; then
    sig_status=$(codesign -v "$path" 2>&1)
    if [[ $? -eq 0 ]]; then
      sig_check="VALID"
      sig_details=$(codesign -dv --verbose=2 "$path" 2>&1)
      
      # Check if Apple signed
      if echo "$sig_details" | grep -q "Apple"; then
        sig_source="Apple"
        risk_adjustment=$((risk_adjustment - 10))  # Lower risk for Apple-signed apps
      else
        sig_source=$(codesign -dv --verbose=1 "$path" 2>&1 | grep "Authority" | head -1 | sed 's/.*=[[:space:]]*//')
        sig_source="${sig_source:0:8}"
      fi
      
      # Check if notarized (more secure)
      if echo "$sig_details" | grep -q "notarized"; then
        sig_check="NOTARIZED"
        risk_adjustment=$((risk_adjustment - 5))  # Lower risk for notarized apps
      fi
    else
      sig_check="INVALID"
      sig_source="-"
      risk_score=$((risk_score + 30))
      security_flags+="UNSIGNED,"
    fi
  else
    sig_check="UNKNOWN"
    sig_source="-"
    risk_score=$((risk_score + 15))
    security_flags+="NO_FILE,"
  fi
  
  # Make signature display
  signature="${sig_check}:${sig_source}"
  
  # Check file age if file exists
  if [[ -f "$path" ]]; then
    file_age_days=$(( ( $(date +%s) - $(stat -f %m "$path") ) / 86400 ))
    if [[ $file_age_days -lt 1 ]]; then
      age="TODAY!"
      risk_score=$((risk_score + 20))
      security_flags+="NEW_EXEC,"
    elif [[ $file_age_days -lt 7 ]]; then
      age="${file_age_days}d"
      risk_score=$((risk_score + 10))
    else
      age="${file_age_days}d"
    fi
    
    # Check suspicious permissions
    perms=$(stat -f %Lp "$path")
    if [[ $perms -ge 4000 ]]; then
      risk_score=$((risk_score + 25))
      security_flags+="SETUID,"
    elif [[ $(($perms & 2)) -ne 0 ]]; then
      # Don't flag world-writable for VS Code extensions paths
      if [[ "$path" =~ /Library/Application\ Support/Code/User/globalStorage || "$path" =~ /.vscode/ ]]; then
        # Common for VS Code extensions to have world-writable files
        security_flags+="EXT_W,"  # Mark as extension writable instead
      else
        risk_score=$((risk_score + 15))
        security_flags+="WORLD_W,"
      fi
    fi
  else
    age="?"
  fi
  
  # Check path location
  if [[ "$path" =~ ^/(usr|System|Library|Applications)/ ]]; then
    badpath="no"
  # Don't flag VS Code paths as unusual
  elif [[ "$path" =~ /Library/Application\ Support/Code/ ]]; then
    badpath="no"
    security_flags+="VS_CODE,"
  else
    badpath="yes"
    risk_score=$((risk_score + 20))
    security_flags+="ODD_PATH,"
  fi
  
  # Check for root/admin processes that are user apps
  if [[ "$user" == "root" && ! "$path" =~ ^/(usr/|/System/) ]]; then
    risk_score=$((risk_score + 25))
    security_flags+="ROOT!,"
  fi
  
  # Check for network activity - both listening ports and outbound connections
  network_info=""
  
  # Listening ports - higher risk
  listen_ports=$(lsof -Pan -p "$pid" -iTCP -sTCP:LISTEN -n 2>/dev/null | awk 'NR>1 { print $9 }' | tr '\n' ' ')
  if [[ -n "$listen_ports" ]]; then
    network_info+="LISTEN:${listen_ports}"
    risk_score=$((risk_score + 15))
    security_flags+="LISTENING,"
  fi
  
  # Foreign connections
  foreign_conn=$(lsof -Pan -p "$pid" -i -n 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
  if [[ "$foreign_conn" -gt 0 ]]; then
    [[ -n "$network_info" ]] && network_info+=","
    network_info+="CONN:${foreign_conn}"
    risk_score=$((risk_score + 10))
    security_flags+="NET_CONN,"
  fi
  
  [[ -z "$network_info" ]] && network_info="-"
  network_info="${network_info:0:14}"
  
  # Check loaded dynamic libraries for suspicious ones
  suspicious_dylibs=$(otool -L "$path" 2>/dev/null | grep -v "/System\|/usr/lib\|@rpath" | wc -l | tr -d ' ')
  if [[ "$suspicious_dylibs" -gt 0 ]]; then
    # Check if this is a VS Code/development related process
    if [[ "$path" =~ /node_modules/ || "$path" =~ /Library/Application\ Support/Code/ ]]; then
      security_flags+="DEV_LIB,"  # Mark as development libraries instead
    else
      risk_score=$((risk_score + 15))
      security_flags+="ODD_DYLIB,"
    fi
  fi
  
  # Add arguments checking for suspicious patterns
  args=$(ps -p "$pid" -o args | tail -1)
  if echo "$args" | grep -qi "proxy\|pac\|socks\|http://\|https://\|ssh\|port=\|keylog"; then
    risk_score=$((risk_score + 15))
    security_flags+="SUSP_ARGS,"
  fi
  
  # Build parent chain with process names for better context
  chain="$pid(${comm:0:5})"
  cur=$ppid
  while [[ $cur -gt 1 ]]; do
    parent_name=$(ps -p "$cur" -o comm= | tr -d ' ' | awk -F/ '{print $NF}')
    parent_name="${parent_name:0:5}"
    chain="${cur}(${parent_name})->${chain}"
    cur=$(ps -p "$cur" -o ppid= | tr -d ' ')
  done
  
  # Special case for VS Code processes - lower their risk
  if [[ "$chain" =~ "Elect" && ( "$comm" == "node" || "$comm" == "npm" ) ]]; then
    # VS Code extensions/processes
    risk_adjustment=$((risk_adjustment - 15))
  fi
  
  # Apply risk adjustment but don't go below 0
  risk_score=$((risk_score + risk_adjustment))
  [[ $risk_score -lt 0 ]] && risk_score=0
  
  # Trim security flags
  security_flags=${security_flags%,}
  [[ -z "$security_flags" ]] && security_flags="-"
  security_flags="${security_flags:0:19}"
  
  # Calculate final risk level
  if [[ $risk_score -ge 50 ]]; then
    risk_color="${RED}"
    risk_level="HIGH"
  elif [[ $risk_score -ge 25 ]]; then
    risk_color="${YELLOW}"
    risk_level="MEDIUM"
  else
    risk_color="${GREEN}" 
    risk_level="LOW"
  fi
  
  # Print detailed process information with color-coded risk
  printf "%-5s %-8s %5s %5s %-15.15s ${risk_color}%-8s${NC} %-9.9s %-8s %-15.15s %-20.20s %s\n" \
    "$pid" "$user" "$cpu" "$mem" "${comm:0:15}" "$risk_level" \
    "$signature" "$age" "$network_info" "$security_flags" "$chain"
}

# Main execution
print_header

# Use macOS compatible ps command syntax and scan each process
ps aux | tail -n +2 | while read user pid cpu mem vsz rss tty stat start time command; do
    over_cpu=$(awk "BEGIN { print ($cpu > $CPU_T) }")
    over_mem=$(awk "BEGIN { print ($mem > $MEM_T) }")
    
    # Skip processes below resource thresholds unless they have other risk factors
    if [[ $over_cpu -eq 0 && $over_mem -eq 0 ]]; then
        # Check for high risk even with low CPU/MEM
        path=$(echo "$command" | awk '{print $1}')
        
        # Skip common low-risk processes quickly
        [[ "$path" =~ ^/(usr/|/System/) && "$user" != "root" ]] && continue
        
        # Do extra checks on non-system paths
        if [[ ! "$path" =~ ^/(usr|System|Library|Applications)/ ]]; then
            # Continue scan for this process
            :
        else 
            # Skip this process - low CPU/MEM and in system path
            continue
        fi
    fi
    
    # Get full path of the process (first part of command)
    path=$(echo "$command" | awk '{print $1}')
    
    # Fall back to command if full path can't be determined
    [[ ! -f "$path" ]] && path=$(which $(echo "$command" | awk '{print $1}' | awk -F/ '{print $NF}') 2>/dev/null || echo "$command" | awk '{print $1}')
    
    # Get parent pid
    ppid=$(ps -o ppid= -p "$pid" | tr -d ' ')
    
    # Scan this process for security issues
    scan_process "$pid" "$user" "$cpu" "$mem" "$command" "$path" "$ppid"
done

echo ""
echo -e "${YELLOW}=== Security Notes ===${NC}"
echo "- HIGH risk processes warrant immediate investigation"
echo "- NEW_EXEC: Executables created today are suspicious"
echo "- ODD_PATH: Applications running from non-standard locations"
echo "- UNSIGNED: Code not signed by verified developer"
echo "- SETUID: Process has elevated permissions"
echo "- ROOT!: Application running as root from non-system location"
echo "- VS_CODE: Visual Studio Code related process (expected)"
echo "- EXT_W: World-writable file in extension directory (expected)"
echo "- DEV_LIB: Development libraries (expected in dev environment)"