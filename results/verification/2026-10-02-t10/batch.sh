#!/bin/bash
# The T10 evidence runs (release build of the final client sources, dev Mac, loopback).
# Run from the repository root; tools/clients/t10_run.sh is the driver.
export REFCLIENT_ARGS="--reorder-capacity 8388608"
R=results/verification/2026-10-02-t10
tools/clients/t10_run.sh $R/01302019        data/itch/01302019.NASDAQ_ITCH50.gz 20261002 2%   5% 1000000 43000 --outage-every 50000000 --outage-len 50000
tools/clients/t10_run.sh $R/01302019-nosnap data/itch/01302019.NASDAQ_ITCH50.gz 20261003 0.1% 1% 1000000 43100
tools/clients/t10_run.sh $R/S120925         data/itch/S120925-v50.txt.gz        20261004 3%   4% 1000000 43200 --outage-every 100000000 --outage-len 50000
tools/clients/t10_run.sh $R/S120925-500k    data/itch/S120925-v50.txt.gz        20261005 3%   4% 500000  43300 --outage-every 100000000 --outage-len 50000
