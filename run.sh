#!/bin/bash

pushd onearm_lb/skeleton

echo "about to clean"
make clean
make -j 30

pushd build
#sudo -E ./basicfwd -l 0,2,4,6,8,10,12,14,16,18,20,22,24 -n 18
sudo -E ./basicfwd -l 0 -n 2
