#!/bin/sh

echo "Pulling $1:$CI_COMMIT_REF_NAME..."
docker pull "$1:$CI_COMMIT_REF_NAME" > /dev/null

if test $? -ne 0
then
    echo "Pulling $1:latest..."
    docker pull "$1:latest" > /dev/null
    
    if test $? -ne 0
    then
        echo "No cached images present, will build everything from scratch..."
    fi
fi

docker build --cache-from "$1:$CI_COMMIT_REF_NAME" --cache-from "$1:latest" -t "$1:$CI_COMMIT_SHA" -t "$1:$CI_COMMIT_REF_NAME" $2

echo "Pushing as $1:$CI_COMMIT_SHA"
docker push "$1:$CI_COMMIT_SHA" > /dev/null

echo "Pushing as $1:$CI_COMMIT_REF_NAME"
docker push "$1:$CI_COMMIT_REF_NAME" > /dev/null

if test "$CI_COMMIT_REF_NAME" = 'master'
then
    echo "Pushing as $1:latest"
    docker tag "$1:$CI_COMMIT_SHA" "$1:latest"
    docker push "$1:latest" > /dev/null
fi

