#!/usr/bin/env bash
set -uo pipefail
cli=${cli:-}

SCRIPT_DIR=$(dirname "$(realpath "$0")")

assert_violation(){
  local nth=$1; shift
  local cmd="$*"
  log=$(mktemp)
  bash -c "$cmd" > "$log" 2>&1
  status=$?
  output=$(cat "$log")
  if [[ $status -eq 1 && "$output" == *"=== Violations detected ==="* ]]; then
    return 0
  else
    echo "Detection FAIL (iteration $nth)" >&2
    echo "Cmd : $cmd" >&2
    echo "Exit: $status" >&2
    echo "Out : $output" >&2
    return 1
  fi
}

assert_no_violation(){
  local nth=$1; shift
  local cmd="$*"
  log=$(mktemp)
  bash -c "$cmd" > "$log" 2>&1
  status=$?
  output=$(cat "$log")
  if [[ $status -eq 0 && "$output" != *"=== Violations detected ==="* ]]; then
    return 0
  else
    echo "Filtering FAIL (iteration $nth)" >&2
    echo "Cmd : $cmd" >&2
    echo "Exit: $status" >&2
    echo "Out : $output" >&2
    return 1
  fi
}

cmd1="rvzr $cli fuzz -s $SCRIPT_DIR/../base.json --save-violations f -I $SCRIPT_DIR/x86_tests/configs -t $SCRIPT_DIR/x86_tests/asm/spectre_ret.asm -c $SCRIPT_DIR/x86_tests/configs/ct-seq.yaml -i 20"
#cmd2="rvzr $cli fuzz -s $SCRIPT_DIR/../base.json --save-violations f -I $SCRIPT_DIR/x86_tests/configs -t $SCRIPT_DIR/x86_tests/asm/spectre_v1.asm -c $SCRIPT_DIR/x86_tests/configs/ct-cond.yaml -i 20"

cnt1=0; cnt2=0

for i in {1..50}; do
  assert_violation "$i" "$cmd1" && ((cnt1++))
done

#for i in {1..50}; do
#  assert_no_violation "$i" "$cmd2" && ((cnt2++))
#done

echo "Ran 50 times each:"
echo "  ct-seq (should detect):  $cnt1  OK"
#echo "  ct-cond (should filter): $cnt2  OK"