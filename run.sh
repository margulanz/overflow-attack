#!/bin/bash

set -e  # stop on error

echo "Starting Ryu controller..."
sudo docker compose up --build -d ryu

echo "Waiting for controller to be ready..."
sleep 5

echo "Running Mininet topology..."
cd mininet
sudo python3 topology.py
