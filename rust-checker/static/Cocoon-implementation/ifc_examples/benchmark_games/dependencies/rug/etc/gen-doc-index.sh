#!/bin/bash

set -e

cd public
cp dev/*/index.html index.html

function filter {
    awk "$1" < index.html > index.html.tmp
    mv index.html.tmp index.html
}

filter '{
    if ($0 ~ /button>$/) {
        printf "%s", $0
        getline
    }
    print
}'
filter '{
    gsub(/'\''\.\.\//, "'\''dev/")
    gsub(/"\.\.\//, "\"dev/")
    print
}'
filter '{
    gsub(/<\/nav>/, "\013")
    sub(/<div class="block[^\013]*\013/, "\013")
    sub(/<nav class="sub[^\013]*\013/, "")
    gsub(/\013/, "</nav>")

    sub(/dev\/[^\/]*\/index.html/, "index.html")

    gsub(/<\/h1>/, "\013")
    sub(/<h1 class="fqn[^\013]*\013/, "")
    gsub(/\013/, "</h1>")

    gsub(/<\/script>/, "\013")
    sub(/<script src="[^"]*main\.js[^\013]*\013/, "")
    gsub(/\013/, "</script>")

    print
}'
filter '{
    if ($0 ~ /<\/h1>/) {
        h = $0
        sub(/<\/h1>.*/, "</h1>", h)
        print h
        sub(/.*<\/h1>/, "")
        while ($0 !~ /<\/section>/) { getline }
        while (getline line<"../etc/index-contents.html") { print line }
        gsub(/<\/section>/, "\013")
        sub(/^[^\013]*/, "</div>")
        gsub(/\013/, "</section>")
    }
    print
}'
