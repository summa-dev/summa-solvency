#!/bin/bash
set -e

runner="i-0e04845bff4576909"

while true; do
  runner_status=$(aws ec2 describe-instances --instance-ids $runner --query "Reservations[*].Instances[*].State.[Name]" --output text)
  if [ $runner_status = "stopped" ]; then
    aws ec2 start-instances --instance-ids $runner
    break
  elif [ $runner_status = "running" ]; then
    break
  else
    sleep 5
  fi
done

exit 0
