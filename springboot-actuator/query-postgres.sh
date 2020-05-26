#!/bin/bash
set -v

'''
"connectionTestQuery": "SELECT 1",
"driverClassName": "org.postgresql.Driver",
"jdbcUrl": "jdbc:postgresql://127.0.0.1:5432/qcm",
'''

curl -k -i -H "Accept: application/json" -H "Content-Type: application/json" -H "Host: 1.2.3.4" -X GET http://127.0.0.1:5432
