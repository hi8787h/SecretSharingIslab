#!/bin/bash
for i in {1..100};
do
    echo "$i th share construction"
    python main.py
    sleep 5
done