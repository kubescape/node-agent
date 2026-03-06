#!/bin/bash
curl -s https://api.github.com/repos/k8sstormcenter/storage/tags | jq -r '.[0].name'
