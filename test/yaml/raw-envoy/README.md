# Envoy TLS proxy perf test

This directory contains a setup for testing host to host proxy performance with envoy

## Test conditions

We test TLS 1.3 with AES256-GCM-SHA384 and AES128-GCM-SHA256

## Running the tests

First you should `./envoy_test.sh certs` to create the required TLS certificates

Then you can use `./envoy_test.sh sync` to rsync the configuration to vq1 & vq2

This does not copy docker-compose.yml by default
