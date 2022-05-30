#!/bin/bash

CONSUMER="submission"
SUBJECT="self"

TOKEN=$(curl http://localhost:8080/token/${CONSUMER}/${SUBJECT})

curl -v -H "Authorization: Bearer ${TOKEN}" http://localhost:8080/submission/status