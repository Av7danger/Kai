#!/bin/bash
"""
🐉 BATCH BUG BOUNTY HUNTER
⚡ Continuous automated hunting across multiple targets
💰 Optimized for 24/7 profit generation

Usage: ./batch_hunt.sh targets.txt [options]
"""

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE="$HOME/bb_pro_workspace"
LOG_FILE="$WORKSPACE/logs/batch_hunt_$(date +%Y%m%d_%H%M%S).log"
RESULTS_DIR="$WORKSPACE/batch_results"
MAX_CONCURRENT=3
DELAY_BETWEEN_TARGETS=300  # 5 minutes
DAILY_TARGET_LIMIT=50

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}" | tee -a "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}" | tee -a "$LOG_FILE"
}

# Banner
print_banner() {
    echo -e "${PURPLE}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     🐉 BATCH BUG BOUNTY HUNTER - 24/7 PROFIT MACHINE            ║
    ║        Automated continuous hunting across multiple targets       ║
    ║         💰 Designed for maximum earnings with minimal effort     ║
    ╚═══════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()
    
    if [ ! -f "$SCRIPT_DIR/kali_bb_pro.py" ]; then
        missing_deps+=("kali_bb_pro.py")
    fi
    
    for cmd in python3 jq; do
        if ! command -v $cmd &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing_deps[*]}"
        exit 1
    fi
}

# Setup workspace
setup_workspace() {
    mkdir -p "$RESULTS_DIR"
    mkdir -p "$WORKSPACE/logs"
    mkdir -p "$WORKSPACE/campaigns"
    mkdir -p "$WORKSPACE/reports"
    
    # Create session info
    cat > "$RESULTS_DIR/session_info.json" << EOF
{
    "session_id": "$(date +%s)",
    "start_time": "$(date -Iseconds)",
    "targets_file": "$1",
    "max_concurrent": $MAX_CONCURRENT,
    "delay_between_targets": $DELAY_BETWEEN_TARGETS,
    "daily_target_limit": $DAILY_TARGET_LIMIT,
    "total_targets": 0,
    "completed_targets": 0,
    "total_findings": 0,
    "estimated_earnings": 0.0,
    "actual_earnings": 0.0
}
EOF
}

# Process single target
hunt_target() {
    local target="$1"
    local target_id="$2"
    
    log "Starting hunt for target: $target (ID: $target_id)"
    
    local target_dir="$RESULTS_DIR/target_${target_id}_$(echo $target | tr '.' '_')"
    mkdir -p "$target_dir"
    
    # Record start time
    local start_time=$(date +%s)
    
    # Run the hunting tool
    cd "$SCRIPT_DIR"
    local hunt_result="$target_dir/hunt_result.json"
    
    if timeout 3600 python3 kali_bb_pro.py quick-hunt "$target" > "$target_dir/hunt_output.txt" 2>&1; then
        log "Hunt completed successfully for $target"
        
        # Extract results (simplified - you may need to parse actual output)
        local findings=$(grep -c "FINDING" "$target_dir/hunt_output.txt" 2>/dev/null || echo "0")
        local estimated_value=$(grep "Estimated Earnings" "$target_dir/hunt_output.txt" | grep -oE '\$[0-9,]+\.[0-9]{2}' | sed 's/\$//;s/,//' || echo "0.0")
        
        # Create result summary
        cat > "$hunt_result" << EOF
{
    "target": "$target",
    "target_id": $target_id,
    "start_time": $start_time,
    "end_time": $(date +%s),
    "duration": $(($(date +%s) - start_time)),
    "status": "success",
    "findings_count": $findings,
    "estimated_value": $estimated_value,
    "output_file": "$target_dir/hunt_output.txt"
}
EOF
        
        info "Target $target: $findings findings, \$$estimated_value estimated value"
        return 0
    else
        error "Hunt failed for $target"
        
        cat > "$hunt_result" << EOF
{
    "target": "$target",
    "target_id": $target_id,
    "start_time": $start_time,
    "end_time": $(date +%s),
    "duration": $(($(date +%s) - start_time)),
    "status": "failed",
    "findings_count": 0,
    "estimated_value": 0.0,
    "error": "Hunt execution failed"
}
EOF
        return 1
    fi
}

# Generate daily report
generate_daily_report() {
    local report_file="$WORKSPACE/reports/daily_report_$(date +%Y%m%d).md"
    
    log "Generating daily report: $report_file"
    
    # Aggregate results
    local total_targets=0
    local successful_hunts=0
    local total_findings=0
    local total_estimated=0.0
    
    for result_file in "$RESULTS_DIR"/target_*/hunt_result.json; do
        if [ -f "$result_file" ]; then
            total_targets=$((total_targets + 1))
            
            local status=$(jq -r '.status' "$result_file" 2>/dev/null || echo "unknown")
            if [ "$status" = "success" ]; then
                successful_hunts=$((successful_hunts + 1))
                local findings=$(jq -r '.findings_count' "$result_file" 2>/dev/null || echo "0")
                local estimated=$(jq -r '.estimated_value' "$result_file" 2>/dev/null || echo "0.0")
                
                total_findings=$((total_findings + findings))
                total_estimated=$(echo "$total_estimated + $estimated" | bc -l 2>/dev/null || echo "$total_estimated")
            fi
        fi
    done
    
    # Create report
    cat > "$report_file" << EOF
# 🎯 Daily Bug Bounty Report - $(date +%Y-%m-%d)

## 📊 Summary Statistics
- **Total Targets Processed**: $total_targets
- **Successful Hunts**: $successful_hunts ($((successful_hunts * 100 / (total_targets > 0 ? total_targets : 1)))%)
- **Total Findings**: $total_findings
- **Estimated Earnings**: \$$total_estimated
- **Average per Target**: \$$(echo "scale=2; $total_estimated / ($total_targets > 0 ? $total_targets : 1)" | bc -l)

## 🔍 Top Findings
EOF
    
    # Add top findings
    local finding_count=0
    for result_file in "$RESULTS_DIR"/target_*/hunt_result.json; do
        if [ -f "$result_file" ] && [ $finding_count -lt 10 ]; then
            local target=$(jq -r '.target' "$result_file" 2>/dev/null)
            local findings=$(jq -r '.findings_count' "$result_file" 2>/dev/null)
            local estimated=$(jq -r '.estimated_value' "$result_file" 2>/dev/null)
            
            if [ "$findings" -gt 0 ]; then
                echo "- **$target**: $findings findings, \$$estimated estimated" >> "$report_file"
                finding_count=$((finding_count + 1))
            fi
        fi
    done
    
    # Add performance metrics
    cat >> "$report_file" << EOF

## ⚡ Performance Metrics
- **Hunt Success Rate**: $((successful_hunts * 100 / (total_targets > 0 ? total_targets : 1)))%
- **Average Findings per Successful Hunt**: $(echo "scale=1; $total_findings / ($successful_hunts > 0 ? $successful_hunts : 1)" | bc -l)
- **ROI Estimate**: $(echo "scale=0; $total_estimated * 0.8" | bc -l)% (assuming 80% payout rate)

## 📈 Recommendations
- Focus on targets with > 5 findings
- Prioritize high-value estimates (> \$1000)
- Review failed hunts for optimization opportunities

---
*Generated by Batch Bug Bounty Hunter*
EOF
    
    log "Daily report generated: $report_file"
}

# Monitor system resources
monitor_resources() {
    while true; do
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')
        local mem_usage=$(free | grep Mem | awk '{printf("%.1f", $3/$2 * 100.0)}')
        local disk_usage=$(df -h / | awk 'NR==2{print $5}' | sed 's/%//')
        
        # Log resource usage
        echo "$(date -Iseconds),CPU:${cpu_usage}%,Memory:${mem_usage}%,Disk:${disk_usage}%" >> "$WORKSPACE/logs/resource_monitor.csv"
        
        # Alert if resources are high
        if (( $(echo "$cpu_usage > 90" | bc -l) )) || (( $(echo "$mem_usage > 90" | bc -l) )); then
            warning "High resource usage detected - CPU: ${cpu_usage}%, Memory: ${mem_usage}%"
        fi
        
        sleep 60
    done
}

# Signal handler for graceful shutdown
cleanup() {
    log "Received shutdown signal, cleaning up..."
    
    # Kill any running hunts
    pkill -f "kali_bb_pro.py" || true
    
    # Generate final report
    generate_daily_report
    
    # Update session info
    if [ -f "$RESULTS_DIR/session_info.json" ]; then
        local completed=$(ls "$RESULTS_DIR"/target_*/hunt_result.json 2>/dev/null | wc -l)
        jq --arg end_time "$(date -Iseconds)" --arg completed "$completed" \
           '.end_time = $end_time | .completed_targets = ($completed | tonumber)' \
           "$RESULTS_DIR/session_info.json" > "$RESULTS_DIR/session_info.json.tmp" && \
           mv "$RESULTS_DIR/session_info.json.tmp" "$RESULTS_DIR/session_info.json"
    fi
    
    log "Cleanup completed"
    exit 0
}

# Main batch hunting function
run_batch_hunt() {
    local targets_file="$1"
    
    if [ ! -f "$targets_file" ]; then
        error "Targets file not found: $targets_file"
        exit 1
    fi
    
    # Count total targets
    local total_targets=$(wc -l < "$targets_file")
    log "Starting batch hunt with $total_targets targets"
    
    # Update session info
    jq --arg total "$total_targets" '.total_targets = ($total | tonumber)' \
       "$RESULTS_DIR/session_info.json" > "$RESULTS_DIR/session_info.json.tmp" && \
       mv "$RESULTS_DIR/session_info.json.tmp" "$RESULTS_DIR/session_info.json"
    
    # Start resource monitoring in background
    monitor_resources &
    local monitor_pid=$!
    
    # Setup signal handlers
    trap cleanup SIGINT SIGTERM
    
    # Process targets
    local target_id=1
    local hunts_today=0
    local concurrent_jobs=0
    
    while IFS= read -r target && [ $hunts_today -lt $DAILY_TARGET_LIMIT ]; do
        # Skip empty lines and comments
        [[ -z "$target" || "$target" =~ ^[[:space:]]*# ]] && continue
        
        # Wait for available slot
        while [ $concurrent_jobs -ge $MAX_CONCURRENT ]; do
            sleep 10
            concurrent_jobs=$(jobs -r | wc -l)
        done
        
        # Start hunt in background
        log "Starting concurrent hunt for $target"
        (hunt_target "$target" "$target_id") &
        
        concurrent_jobs=$((concurrent_jobs + 1))
        target_id=$((target_id + 1))
        hunts_today=$((hunts_today + 1))
        
        # Delay between targets
        if [ $hunts_today -lt $DAILY_TARGET_LIMIT ]; then
            info "Waiting $DELAY_BETWEEN_TARGETS seconds before next target..."
            sleep $DELAY_BETWEEN_TARGETS
        fi
        
        # Update progress
        local progress=$((hunts_today * 100 / DAILY_TARGET_LIMIT))
        log "Progress: $hunts_today/$DAILY_TARGET_LIMIT targets ($progress%)"
        
    done < "$targets_file"
    
    # Wait for all background jobs to complete
    log "Waiting for all hunts to complete..."
    wait
    
    # Stop resource monitoring
    kill $monitor_pid 2>/dev/null || true
    
    # Generate final report
    generate_daily_report
    
    log "Batch hunt completed successfully!"
}

# Usage function
show_usage() {
    cat << EOF
Usage: $0 <targets_file> [options]

Options:
    -c, --concurrent NUM     Maximum concurrent hunts (default: $MAX_CONCURRENT)
    -d, --delay SECONDS      Delay between targets (default: $DELAY_BETWEEN_TARGETS)
    -l, --limit NUM          Daily target limit (default: $DAILY_TARGET_LIMIT)
    -h, --help              Show this help message

Examples:
    $0 targets.txt
    $0 targets.txt --concurrent 5 --delay 600
    $0 high_value_targets.txt --limit 20

Target file format:
    target1.com
    target2.com
    # This is a comment
    target3.com
EOF
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--concurrent)
                MAX_CONCURRENT="$2"
                shift 2
                ;;
            -d|--delay)
                DELAY_BETWEEN_TARGETS="$2"
                shift 2
                ;;
            -l|--limit)
                DAILY_TARGET_LIMIT="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
            *)
                TARGETS_FILE="$1"
                shift
                ;;
        esac
    done
}

# Main execution
main() {
    print_banner
    
    # Parse arguments
    parse_arguments "$@"
    
    if [ -z "$TARGETS_FILE" ]; then
        error "No targets file specified"
        show_usage
        exit 1
    fi
    
    # Validate inputs
    if ! [[ "$MAX_CONCURRENT" =~ ^[0-9]+$ ]] || [ "$MAX_CONCURRENT" -lt 1 ] || [ "$MAX_CONCURRENT" -gt 10 ]; then
        error "Invalid concurrent value. Must be 1-10"
        exit 1
    fi
    
    if ! [[ "$DELAY_BETWEEN_TARGETS" =~ ^[0-9]+$ ]] || [ "$DELAY_BETWEEN_TARGETS" -lt 60 ]; then
        error "Invalid delay value. Must be >= 60 seconds"
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Setup workspace
    setup_workspace "$TARGETS_FILE"
    
    log "Configuration:"
    log "  Targets file: $TARGETS_FILE"
    log "  Max concurrent: $MAX_CONCURRENT"
    log "  Delay between targets: $DELAY_BETWEEN_TARGETS seconds"
    log "  Daily limit: $DAILY_TARGET_LIMIT targets"
    log "  Results directory: $RESULTS_DIR"
    
    # Start batch hunting
    run_batch_hunt "$TARGETS_FILE"
}

# Execute main function
main "$@"
