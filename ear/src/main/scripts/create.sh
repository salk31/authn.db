#!/bin/sh

props=./glassfish.props
if [ ! -f $props ]; then
    echo There is no $props file
    exit 1
fi

. $props

for key in authn_dbProperties driver port; do
    eval val='$'$key
    if [ -z "$val" ]; then
        echo $key must be set in $props file
        exit 1
    fi
done

asadmin="$glassfish/bin/asadmin --port $port"

$asadmin create-jdbc-connection-pool \
   --datasourceclassname ${driver} --restype javax.sql.DataSource \
   --failconnection=true --steadypoolsize 2 --maxpoolsize 8 --ping \
   --property ${authn_dbProperties} \
   authn_db
$asadmin create-jdbc-resource --connectionpoolid icatuser jdbc/authn_db
