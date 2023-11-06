#!/bin/bash

for N_ASSETS in {1..5}; do
    for LEVELS in {17..21}; do
        echo "${N_ASSETS} asset, 2^${LEVELS} bench start"
        N_ASSETS=$N_ASSETS LEVELS=$LEVELS cargo bench > ${N_ASSETS}_2_${LEVELS}_bench_result.log
        echo "${N_ASSETS} asset, 2^${LEVELS} bench complete"
    done
done
